#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD User Reports - Generates detailed user and account reports.

.DESCRIPTION
    Comprehensive reporting tool covering:
      - Inactive users (no logon in X days)
      - Disabled accounts
      - Recently created accounts
      - Users by department/OU
      - Accounts expiring soon
      - Full user detail report
      - Stale computer accounts

.PARAMETER OutputPath
    Directory for report files. Defaults to Desktop.

.PARAMETER InactiveDays
    Days of inactivity threshold. Default: 90.

.EXAMPLE
    .\07_AD_UserReports.ps1
    .\07_AD_UserReports.ps1 -InactiveDays 60 -OutputPath "C:\Reports"

.NOTES
    Prerequisites : ActiveDirectory module; read access to AD.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath  = "$env:USERPROFILE\Desktop",
    [int]$InactiveDays   = 90
)

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

function Write-Section {
    param([string]$Title)
    Write-Host "`n$("=" * 55)" -ForegroundColor Cyan
    Write-Host "  $Title"      -ForegroundColor Yellow
    Write-Host "$("=" * 55)"   -ForegroundColor Cyan
}

function Export-Report {
    param($Data, [string]$Name)
    $path = Join-Path $OutputPath "${Name}_$timestamp.csv"
    $Data | Export-Csv -Path $path -NoTypeInformation
    Write-Host "  Saved: $path" -ForegroundColor Gray
    return $path
}

# ─── 1. Inactive Users ─────────────────────────────────────────────────────────
function Get-InactiveUsers {
    Write-Section "INACTIVE USERS (No logon in $InactiveDays days)"
    try {
        $cutoff  = (Get-Date).AddDays(-$InactiveDays)
        $inactive = Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $cutoff } `
            -Properties LastLogonDate, Department, Title, Manager, PasswordLastSet |
            Where-Object { $_.LastLogonDate } | Sort-Object LastLogonDate

        Write-Host "`n  Found $($inactive.Count) inactive user(s):" -ForegroundColor $(if($inactive.Count -gt 0){"Yellow"}else{"Green"})
        Write-Host ("  {0,-25} {1,-20} {2,-15} {3}" -f "Username", "Last Logon", "Department", "Name")
        Write-Host ("  {0,-25} {1,-20} {2,-15} {3}" -f "--------", "----------", "----------", "----")

        foreach ($u in $inactive | Select-Object -First 30) {
            Write-Host ("  {0,-25} {1,-20} {2,-15} {3}" -f `
                $u.SamAccountName, $u.LastLogonDate.ToString("yyyy-MM-dd"), $u.Department, $u.Name) -ForegroundColor Yellow
        }
        if ($inactive.Count -gt 30) { Write-Host "  ... and $($inactive.Count - 30) more. See CSV." -ForegroundColor Gray }

        $report = $inactive | Select-Object Name, SamAccountName, LastLogonDate, Department, Title, PasswordLastSet, DistinguishedName
        Export-Report -Data $report -Name "InactiveUsers"
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── 2. Disabled Accounts ─────────────────────────────────────────────────────
function Get-DisabledAccounts {
    Write-Section "DISABLED ACCOUNTS"
    try {
        $disabled = Get-ADUser -Filter { Enabled -eq $false } `
            -Properties LastLogonDate, Department, Description, WhenChanged | Sort-Object Name

        Write-Host "`n  Found $($disabled.Count) disabled account(s)." -ForegroundColor Cyan
        Write-Host ("  {0,-25} {1,-20} {2,-30} {3}" -f "Username", "Last Logon", "Description", "Name")
        foreach ($u in $disabled | Select-Object -First 20) {
            $ll = if ($u.LastLogonDate) { $u.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
            Write-Host ("  {0,-25} {1,-20} {2,-30} {3}" -f $u.SamAccountName, $ll, ($u.Description -replace ".{30}$","..."), $u.Name) -ForegroundColor DarkGray
        }

        Export-Report -Data ($disabled | Select-Object Name, SamAccountName, LastLogonDate, Department, Description, WhenChanged) -Name "DisabledAccounts"
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── 3. Recently Created Accounts ─────────────────────────────────────────────
function Get-RecentAccounts {
    Write-Section "RECENTLY CREATED ACCOUNTS (Last 30 days)"
    try {
        $cutoff = (Get-Date).AddDays(-30)
        $recent = Get-ADUser -Filter { WhenCreated -gt $cutoff } `
            -Properties WhenCreated, Department, Title, EmailAddress | Sort-Object WhenCreated -Descending

        Write-Host "`n  Found $($recent.Count) recently created account(s):" -ForegroundColor Cyan
        Write-Host ("  {0,-25} {1,-12} {2,-20} {3}" -f "Username", "Created", "Department", "Name")
        foreach ($u in $recent) {
            Write-Host ("  {0,-25} {1,-12} {2,-20} {3}" -f `
                $u.SamAccountName, $u.WhenCreated.ToString("yyyy-MM-dd"), $u.Department, $u.Name) -ForegroundColor Green
        }

        Export-Report -Data ($recent | Select-Object Name, SamAccountName, WhenCreated, Department, Title, EmailAddress) -Name "RecentAccounts"
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── 4. Users by Department ───────────────────────────────────────────────────
function Get-UsersByDepartment {
    Write-Section "USERS BY DEPARTMENT"
    try {
        $users = Get-ADUser -Filter { Enabled -eq $true } -Properties Department | Sort-Object Department, Name
        $grouped = $users | Group-Object Department | Sort-Object Count -Descending

        Write-Host "`n  User count by department:" -ForegroundColor Cyan
        Write-Host ("  {0,-30} {1}" -f "Department", "Users")
        Write-Host ("  {0,-30} {1}" -f "----------", "-----")
        foreach ($g in $grouped) {
            $dept = if ($g.Name) { $g.Name } else { "(No Department)" }
            Write-Host ("  {0,-30} {1}" -f $dept, $g.Count)
        }
        Write-Host "`n  Total active users: $($users.Count)"

        Export-Report -Data ($users | Select-Object Name, SamAccountName, Department, Title) -Name "UsersByDepartment"
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── 5. Expiring Accounts ─────────────────────────────────────────────────────
function Get-ExpiringAccounts {
    Write-Section "ACCOUNTS EXPIRING SOON (Next 30 days)"
    try {
        $soon    = (Get-Date).AddDays(30)
        $expiring = Search-ADAccount -AccountExpiring -TimeSpan (New-TimeSpan -Days 30) -UsersOnly |
                    Get-ADUser -Properties AccountExpirationDate, Department, EmailAddress |
                    Sort-Object AccountExpirationDate

        if ($expiring) {
            Write-Host "`n  $($expiring.Count) account(s) expiring in the next 30 days:" -ForegroundColor Yellow
            foreach ($u in $expiring) {
                $exp = $u.AccountExpirationDate.ToString("yyyy-MM-dd")
                $days = [math]::Round(($u.AccountExpirationDate - (Get-Date)).TotalDays)
                $color = if ($days -le 7) { "Red" } else { "Yellow" }
                Write-Host "  $($u.SamAccountName) - Expires: $exp ($days days)  Dept: $($u.Department)" -ForegroundColor $color
            }
            Export-Report -Data ($expiring | Select-Object Name, SamAccountName, AccountExpirationDate, Department) -Name "ExpiringAccounts"
        } else {
            Write-Host "`n  [OK] No accounts expiring in the next 30 days." -ForegroundColor Green
        }
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── 6. Full User Detail Report ───────────────────────────────────────────────
function Get-FullUserReport {
    Write-Section "FULL USER DETAIL REPORT"
    Write-Host "  Collecting all user data - this may take a moment..." -ForegroundColor Gray
    try {
        $users = Get-ADUser -Filter * -Properties `
            Department, Title, EmailAddress, Manager, LastLogonDate, `
            PasswordLastSet, PasswordNeverExpires, PasswordExpired, `
            AccountExpirationDate, Enabled, LockedOut, WhenCreated, `
            DistinguishedName, MemberOf |
            Sort-Object Enabled, Name

        $report = $users | ForEach-Object {
            $mgr = if ($_.Manager) { (Get-ADUser -Identity $_.Manager -ErrorAction SilentlyContinue).Name } else { "" }
            [PSCustomObject]@{
                Name                = $_.Name
                SamAccountName      = $_.SamAccountName
                UPN                 = $_.UserPrincipalName
                Email               = $_.EmailAddress
                Department          = $_.Department
                Title               = $_.Title
                Manager             = $mgr
                Enabled             = $_.Enabled
                LockedOut           = $_.LockedOut
                PasswordExpired     = $_.PasswordExpired
                PasswordNeverExpires = $_.PasswordNeverExpires
                PasswordLastSet     = $_.PasswordLastSet
                LastLogonDate       = $_.LastLogonDate
                AccountExpires      = $_.AccountExpirationDate
                WhenCreated         = $_.WhenCreated
                GroupCount          = $_.MemberOf.Count
                OU                  = ($_.DistinguishedName -replace "^CN=[^,]+,", "")
            }
        }

        $path = Export-Report -Data $report -Name "FullUserReport"
        Write-Host "  Total users exported: $($report.Count)" -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── 7. Stale Computer Accounts ───────────────────────────────────────────────
function Get-StaleComputers {
    Write-Section "STALE COMPUTER ACCOUNTS (No logon in $InactiveDays days)"
    try {
        $cutoff  = (Get-Date).AddDays(-$InactiveDays)
        $stale   = Get-ADComputer -Filter { Enabled -eq $true -and LastLogonDate -lt $cutoff } `
            -Properties LastLogonDate, OperatingSystem, Description | Sort-Object LastLogonDate

        Write-Host "`n  Found $($stale.Count) stale computer account(s):" -ForegroundColor $(if($stale.Count -gt 0){"Yellow"}else{"Green"})
        foreach ($c in $stale | Select-Object -First 25) {
            $ll = if ($c.LastLogonDate) { $c.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
            Write-Host ("  {0,-25} {1,-12} {2}" -f $c.Name, $ll, $c.OperatingSystem) -ForegroundColor Yellow
        }

        Export-Report -Data ($stale | Select-Object Name, LastLogonDate, OperatingSystem, Description, DistinguishedName) -Name "StaleComputers"
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   AD USER REPORTS"                                             -ForegroundColor Yellow
    Write-Host "   Domain: $((Get-ADDomain).DNSRoot)  | Reports saved to: $OutputPath"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Inactive users (>$InactiveDays days)"   -ForegroundColor White
    Write-Host "  [2] Disabled accounts"                       -ForegroundColor White
    Write-Host "  [3] Recently created accounts"               -ForegroundColor White
    Write-Host "  [4] Users by department"                     -ForegroundColor White
    Write-Host "  [5] Accounts expiring soon"                  -ForegroundColor White
    Write-Host "  [6] Full user detail report (all users)"     -ForegroundColor White
    Write-Host "  [7] Stale computer accounts"                 -ForegroundColor White
    Write-Host "  [A] Run ALL reports"                         -ForegroundColor Yellow
    Write-Host "  [Q] Quit"                                    -ForegroundColor Gray
    Write-Host ""
}

try {
    do {
        Show-Menu
        $choice = Read-Host "Select option"
        switch ($choice.ToUpper()) {
            '1' { Get-InactiveUsers;     Read-Host "`nPress Enter" }
            '2' { Get-DisabledAccounts;  Read-Host "`nPress Enter" }
            '3' { Get-RecentAccounts;    Read-Host "`nPress Enter" }
            '4' { Get-UsersByDepartment; Read-Host "`nPress Enter" }
            '5' { Get-ExpiringAccounts;  Read-Host "`nPress Enter" }
            '6' { Get-FullUserReport;    Read-Host "`nPress Enter" }
            '7' { Get-StaleComputers;    Read-Host "`nPress Enter" }
            'A' {
                Get-InactiveUsers; Get-DisabledAccounts; Get-RecentAccounts
                Get-UsersByDepartment; Get-ExpiringAccounts; Get-FullUserReport; Get-StaleComputers
                Read-Host "`nAll reports complete. Press Enter"
            }
            'Q' { break }
            default { Write-Host "  Invalid." -ForegroundColor Yellow; Start-Sleep 1 }
        }
    } while ($choice.ToUpper() -ne 'Q')
} catch {
    Write-Host "`n[FATAL] $($_.Exception.Message)" -ForegroundColor Red; exit 1
}
