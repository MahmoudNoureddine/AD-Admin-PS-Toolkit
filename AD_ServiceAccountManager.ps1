#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Service Account Manager - Audit, create, and manage AD service accounts.

.DESCRIPTION
    Comprehensive service account lifecycle management:
      - Discover and audit all service accounts
      - Create new service accounts with best-practice settings
      - Review accounts running Windows services
      - Check password age and rotation compliance
      - Identify over-privileged service accounts
      - Generate service account compliance report

.PARAMETER OutputPath    Directory for reports. Defaults to Desktop.

.EXAMPLE
    .\18_AD_ServiceAccountManager.ps1

.NOTES
    Prerequisites : ActiveDirectory module; Domain Admin rights recommended.
    Author        : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param([string]$OutputPath = "$env:USERPROFILE\Desktop")

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "AD_ServiceAccounts_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$M, [string]$L = "INFO")
    $e = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$L] $M"
    Add-Content $logFile $e -ErrorAction SilentlyContinue
    Write-Host "  $e" -ForegroundColor $(switch($L){"ERROR"{"Red"}"WARN"{"Yellow"}"OK"{"Green"}default{"Gray"}})
}

function Write-Section { param([string]$T)
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $T" -ForegroundColor Yellow
    Write-Host "$("=" * 60)" -ForegroundColor Cyan
}

# ─── Discover Service Accounts ────────────────────────────────────────────────
function Get-ServiceAccountAudit {
    Write-Section "SERVICE ACCOUNT DISCOVERY & AUDIT"
    try {
        # Find by naming convention
        $svcAccounts = Get-ADUser -Filter {
            SamAccountName -like "svc-*" -or
            SamAccountName -like "svc_*" -or
            SamAccountName -like "sa-*"  -or
            SamAccountName -like "svc.*"
        } -Properties PasswordNeverExpires, PasswordLastSet, LastLogonDate,
            Description, MemberOf, Enabled, PasswordExpired, PasswordNotRequired,
            WhenCreated | Sort-Object SamAccountName

        Write-Host "`n  Found $($svcAccounts.Count) service account(s):" -ForegroundColor Cyan
        Write-Host ("  {0,-28} {1,-8} {2,-12} {3,-12} {4,-6} {5}" -f "Account","Enabled","PwdLastSet","LastLogon","Groups","Issues") -ForegroundColor White
        Write-Host ("  {0,-28} {1,-8} {2,-12} {3,-12} {4,-6} {5}" -f "-------","-------","----------","----------","------","------")

        $alerts = [System.Collections.Generic.List[string]]::new()
        $report = [System.Collections.Generic.List[object]]::new()

        foreach ($s in $svcAccounts) {
            $pwdAge  = if ($s.PasswordLastSet) { [math]::Round(((Get-Date) - $s.PasswordLastSet).TotalDays) } else { 9999 }
            $ll      = if ($s.LastLogonDate)   { $s.LastLogonDate.ToString("yyyy-MM-dd") }           else { "Never" }
            $pwdDate = if ($s.PasswordLastSet) { $s.PasswordLastSet.ToString("yyyy-MM-dd") }          else { "Never" }
            $issues  = @()

            if ($s.PasswordNeverExpires)  { $issues += "PwdNeverExpires" }
            if ($s.PasswordNotRequired)   { $issues += "PwdNotRequired" }
            if ($pwdAge -gt 365)          { $issues += "PwdAge:${pwdAge}d" }
            if (-not $s.Enabled)          { $issues += "Disabled" }
            if ($s.MemberOf.Count -gt 10) { $issues += "HighPriv($($s.MemberOf.Count)groups)" }

            $issueStr = if ($issues) { $issues -join "," } else { "OK" }
            $color    = if ($issues) { "Yellow" } else { "White" }

            Write-Host ("  {0,-28} {1,-8} {2,-12} {3,-12} {4,-6} {5}" -f `
                $s.SamAccountName, $s.Enabled, $pwdDate, $ll, $s.MemberOf.Count, $issueStr) -ForegroundColor $color

            foreach ($i in $issues) { $alerts.Add("$($s.SamAccountName): $i") }

            $report.Add([PSCustomObject]@{
                SamAccountName      = $s.SamAccountName
                Enabled             = $s.Enabled
                PasswordLastSet     = $pwdDate
                PasswordAge_Days    = $pwdAge
                PasswordNeverExpires = $s.PasswordNeverExpires
                LastLogon           = $ll
                GroupCount          = $s.MemberOf.Count
                Description         = $s.Description
                WhenCreated         = $s.WhenCreated
                Issues              = $issueStr
            })
        }

        $csv = Join-Path $OutputPath "ServiceAccounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $report | Export-Csv $csv -NoTypeInformation
        Write-Host "`n  Exported to: $csv" -ForegroundColor Gray

        if ($alerts.Count -gt 0) {
            Write-Host "`n  Issues found ($($alerts.Count)):" -ForegroundColor Red
            $alerts | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
            Write-Log "$($alerts.Count) service account issues found"
        } else {
            Write-Host "`n  [OK] No issues found with service accounts." -ForegroundColor Green
        }
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# ─── Create Service Account ───────────────────────────────────────────────────
function New-ServiceAccount {
    Write-Section "CREATE SERVICE ACCOUNT"
    Write-Host "  Best practices applied automatically:" -ForegroundColor Gray
    Write-Host "    - Password never expires (service accounts)" -ForegroundColor Gray
    Write-Host "    - User cannot change password" -ForegroundColor Gray
    Write-Host "    - svc- naming prefix enforced" -ForegroundColor Gray
    Write-Host ""

    $name    = Read-Host "  Account name (without prefix, e.g. 'sql-backup')"
    $desc    = Read-Host "  Description / purpose"
    $ou      = Read-Host "  Target OU DN (leave blank for default)"
    $groups  = (Read-Host "  Groups to add (comma-separated, optional)") -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    $sam     = "svc-$name"
    $domain  = (Get-ADDomain).DNSRoot
    $upn     = "$sam@$domain"
    $domainDN = (Get-ADDomain).DistinguishedName
    $targetOU = if ($ou) { $ou } else { "OU=Service Accounts,OU=Company,$domainDN" }

    # Verify OU, fallback to Users
    try { Get-ADOrganizationalUnit -Identity $targetOU -ErrorAction Stop | Out-Null }
    catch { $targetOU = "CN=Users,$domainDN" }

    # Generate strong password
    $pwd = (-join ((65..90)+(97..122)+(48..57)+(33,35,36,37,38,42,64) | Get-Random -Count 24 | ForEach-Object { [char]$_ }))

    Write-Host "`n  Account to create: $sam" -ForegroundColor Cyan
    Write-Host "  OU             : $targetOU"
    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -ne 'Y') { return }

    try {
        New-ADUser -Name $sam -SamAccountName $sam -UserPrincipalName $upn `
            -Description $desc -Path $targetOU `
            -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) `
            -PasswordNeverExpires $true -CannotChangePassword $true `
            -Enabled $true -ErrorAction Stop

        foreach ($g in $groups) {
            try { Add-ADGroupMember -Identity $g -Members $sam -ErrorAction Stop; Write-Log "Added $sam to group: $g" "OK" }
            catch { Write-Log "Could not add to group '$g': $($_.Exception.Message)" "WARN" }
        }

        Write-Log "Service account created: $sam" "OK"
        Write-Host "`n  [OK] Service account '$sam' created." -ForegroundColor Green
        Write-Host "  Password: $pwd" -ForegroundColor Yellow
        Write-Host "  *** Store this password securely in your password vault ***" -ForegroundColor Yellow
    } catch {
        Write-Log "Failed to create service account '$sam': $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Services Using Domain Accounts ──────────────────────────────────────────
function Get-ServicesUsingDomainAccounts {
    Write-Section "WINDOWS SERVICES RUNNING AS DOMAIN ACCOUNTS"
    $target = Read-Host "  Computer name (leave blank for local machine)"
    if (-not $target) { $target = $env:COMPUTERNAME }

    try {
        $services = Get-CimInstance -ComputerName $target -ClassName Win32_Service -ErrorAction Stop |
            Where-Object { $_.StartName -and $_.StartName -notlike "LocalSystem" -and
                           $_.StartName -notlike "NT AUTHORITY*" -and
                           $_.StartName -notlike "NT SERVICE*" } |
            Sort-Object StartName

        Write-Host "`n  Services on '$target' using domain accounts ($($services.Count)):" -ForegroundColor Cyan
        Write-Host ("  {0,-35} {1,-20} {2,-10} {3}" -f "Service","Account","Status","Start Mode")
        Write-Host ("  {0,-35} {1,-20} {2,-10} {3}" -f "-------","-------","------","----------")
        foreach ($s in $services) {
            $color = if ($s.State -eq "Running") { "White" } else { "Yellow" }
            Write-Host ("  {0,-35} {1,-20} {2,-10} {3}" -f `
                ($s.DisplayName.Substring(0,[math]::Min(34,$s.DisplayName.Length))), `
                $s.StartName, $s.State, $s.StartMode) -ForegroundColor $color
        }

        $csv = Join-Path $OutputPath "ServicesWithDomainAccounts_$(Get-Date -Format 'yyyyMMdd').csv"
        $services | Select-Object DisplayName, Name, StartName, State, StartMode |
            Export-Csv $csv -NoTypeInformation
        Write-Host "`n  Exported to: $csv" -ForegroundColor Gray
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# ─── Reset Service Account Password ──────────────────────────────────────────
function Reset-ServiceAccountPassword {
    Write-Section "RESET SERVICE ACCOUNT PASSWORD"
    $sam = Read-Host "  Service account SAMAccountName"
    try {
        $user = Get-ADUser -Identity $sam -ErrorAction Stop
        Write-Host "  Account: $($user.Name)" -ForegroundColor Cyan
        $confirm = Read-Host "  Generate and set new random password? (Y/N)"
        if ($confirm -ne 'Y') { return }

        $newPwd = (-join ((65..90)+(97..122)+(48..57)+(33,35,36,37) | Get-Random -Count 24 | ForEach-Object { [char]$_ }))
        Set-ADAccountPassword -Identity $sam -NewPassword (ConvertTo-SecureString $newPwd -AsPlainText -Force) -Reset -ErrorAction Stop
        Write-Log "Password reset for service account: $sam" "OK"
        Write-Host "`n  [OK] Password reset successfully." -ForegroundColor Green
        Write-Host "  New Password: $newPwd" -ForegroundColor Yellow
        Write-Host "  *** Update all services/tasks using this account immediately ***" -ForegroundColor Yellow
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   SERVICE ACCOUNT MANAGER" -ForegroundColor Yellow
    Write-Host "   Domain: $((Get-ADDomain).DNSRoot)"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  [1] Audit all service accounts`n  [2] Create new service account`n  [3] Services running as domain accounts`n  [4] Reset service account password`n  [Q] Quit`n"
}

Write-Log "Service Account Manager started"
do {
    Show-Menu; $c = Read-Host "Select"
    switch ($c.ToUpper()) {
        '1' { Get-ServiceAccountAudit;              Read-Host "`nPress Enter" }
        '2' { New-ServiceAccount;                   Read-Host "`nPress Enter" }
        '3' { Get-ServicesUsingDomainAccounts;      Read-Host "`nPress Enter" }
        '4' { Reset-ServiceAccountPassword;         Read-Host "`nPress Enter" }
        'Q' { break }
        default { Start-Sleep 1 }
    }
} while ($c.ToUpper() -ne 'Q')
