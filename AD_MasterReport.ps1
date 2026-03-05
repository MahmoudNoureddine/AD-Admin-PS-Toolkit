#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD Master Report - One-click comprehensive Active Directory status report.

.DESCRIPTION
    Generates a complete, executive-ready AD environment report covering:
      - Domain & forest overview
      - User statistics and health
      - Computer inventory summary
      - Group summary
      - Security audit highlights
      - Password policy
      - Replication health
      - Domain Controller status
      - FSMO roles
      - Recent changes
    Saves as a timestamped .txt report and optionally zips for sharing.

.PARAMETER OutputPath    Directory to save the report. Defaults to Desktop.
.PARAMETER Zip           Compress the report to a .zip file after generation.

.EXAMPLE
    .\20_AD_MasterReport.ps1
    .\20_AD_MasterReport.ps1 -OutputPath "C:\Reports" -Zip

.NOTES
    Prerequisites : ActiveDirectory module; read access to AD.
    Author        : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    [switch]$Zip
)

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "AD_MasterReport_$((Get-ADDomain).Name)_$timestamp.txt"
$lines      = [System.Collections.Generic.List[string]]::new()
$alerts     = [System.Collections.Generic.List[string]]::new()

function Add-Line  { param([string]$T = ""); $lines.Add($T); Write-Host $T }
function Add-Title { param([string]$T)
    $bar = "=" * 65
    $lines.Add("`n$bar"); $lines.Add("  $T"); $lines.Add($bar)
    Write-Host "`n$bar" -ForegroundColor Cyan
    Write-Host "  $T"   -ForegroundColor Yellow
    Write-Host "$bar"   -ForegroundColor Cyan
}
function Add-Sub  { param([string]$T); $lines.Add("`n  ── $T"); Write-Host "`n  ── $T" -ForegroundColor White }
function Add-OK   { param([string]$T); $lines.Add("  [OK]   $T"); Write-Host "  [OK]   $T" -ForegroundColor Green }
function Add-Warn { param([string]$T); $lines.Add("  [WARN] $T"); Write-Host "  [WARN] $T" -ForegroundColor Yellow; $alerts.Add("WARN: $T") }
function Add-Fail { param([string]$T); $lines.Add("  [FAIL] $T"); Write-Host "  [FAIL] $T" -ForegroundColor Red;    $alerts.Add("FAIL: $T") }

function Show-Progress { param([string]$Status, [int]$Pct)
    Write-Progress -Activity "Generating AD Master Report" -Status $Status -PercentComplete $Pct
}

# ─── Header ───────────────────────────────────────────────────────────────────
$lines.Add("=" * 65)
$lines.Add("  ACTIVE DIRECTORY MASTER REPORT")
$lines.Add("  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$lines.Add("  Operator  : $env:USERNAME on $env:COMPUTERNAME")
$lines.Add("=" * 65)
Write-Host "`nGenerating AD Master Report..." -ForegroundColor Green

# ─── 1. Domain & Forest Overview ──────────────────────────────────────────────
Show-Progress "Domain Overview" 5
Add-Title "1. DOMAIN & FOREST OVERVIEW"
try {
    $domain = Get-ADDomain
    $forest = Get-ADForest
    Add-Line "  Domain Name            : $($domain.DNSRoot)"
    Add-Line "  Domain DN              : $($domain.DistinguishedName)"
    Add-Line "  Domain Functional Level: $($domain.DomainMode)"
    Add-Line "  Forest Name            : $($forest.Name)"
    Add-Line "  Forest Functional Level: $($forest.ForestMode)"
    Add-Line "  Child Domains          : $($domain.ChildDomains.Count)"
    Add-Line "  Sites                  : $($forest.Sites.Count)"
    Add-Line "  Global Catalogs        : $($forest.GlobalCatalogs.Count)"

    if ("$($domain.DomainMode)" -notmatch "2016|2019|2022") { Add-Warn "Domain functional level below Windows Server 2016" }
} catch { Add-Fail "Could not retrieve domain info: $($_.Exception.Message)" }

# ─── 2. FSMO Roles ────────────────────────────────────────────────────────────
Show-Progress "FSMO Roles" 12
Add-Title "2. FSMO ROLE HOLDERS"
try {
    $domain = Get-ADDomain; $forest = Get-ADForest
    Add-Line "  PDC Emulator         : $($domain.PDCEmulator)"
    Add-Line "  RID Master           : $($domain.RIDMaster)"
    Add-Line "  Infrastructure Master: $($domain.InfrastructureMaster)"
    Add-Line "  Schema Master        : $($forest.SchemaMaster)"
    Add-Line "  Domain Naming Master : $($forest.DomainNamingMaster)"
    Add-OK "FSMO roles retrieved successfully"
} catch { Add-Fail "FSMO roles unavailable: $($_.Exception.Message)" }

# ─── 3. Domain Controllers ────────────────────────────────────────────────────
Show-Progress "Domain Controllers" 20
Add-Title "3. DOMAIN CONTROLLERS"
try {
    $dcs = Get-ADDomainController -Filter * | Sort-Object Name
    Add-Line "  Total DCs: $($dcs.Count)`n"
    Add-Line ("  {0,-25} {1,-8} {2,-20} {3,-15} {4}" -f "Name","Enabled","OS","Site","RODC")
    Add-Line ("  {0,-25} {1,-8} {2,-20} {3,-15} {4}" -f "----","-------","--","----","----")
    foreach ($dc in $dcs) {
        Add-Line ("  {0,-25} {1,-8} {2,-20} {3,-15} {4}" -f $dc.Name, $dc.Enabled, $dc.OperatingSystem, $dc.Site, $dc.IsReadOnly)
        $ping = Test-Connection -ComputerName $dc.HostName -Count 1 -ErrorAction SilentlyContinue
        if ($ping) { Add-OK "$($dc.Name): Reachable" }
        else        { Add-Fail "$($dc.Name): NOT REACHABLE" }
    }
} catch { Add-Fail "Could not enumerate DCs: $($_.Exception.Message)" }

# ─── 4. Replication Health ────────────────────────────────────────────────────
Show-Progress "Replication" 30
Add-Title "4. REPLICATION HEALTH"
try {
    $replStatus = Get-ADReplicationPartnerMetadata -Target * -Scope Domain -ErrorAction Stop
    $failures   = $replStatus | Where-Object { $_.LastReplicationResult -ne 0 }
    $oldest     = ($replStatus | Sort-Object LastReplicationSuccess | Select-Object -First 1).LastReplicationSuccess
    $oldestMins = if ($oldest) { [math]::Round(((Get-Date) - $oldest).TotalMinutes) } else { 9999 }

    Add-Line "  Total partnerships    : $($replStatus.Count)"
    Add-Line "  Failures              : $($failures.Count)"
    Add-Line "  Oldest successful sync: $($oldest?.ToString('yyyy-MM-dd HH:mm')) ($oldestMins min ago)"

    if ($failures.Count -eq 0) { Add-OK "All replication partnerships healthy" }
    else {
        foreach ($f in $failures) { Add-Fail "Replication error: $($f.Server) | Code: $($f.LastReplicationResult)" }
    }
    if ($oldestMins -gt 360) { Add-Warn "Replication stale - oldest sync is $oldestMins minutes ago" }
} catch { Add-Warn "Replication check failed: $($_.Exception.Message)" }

# ─── 5. User Statistics ───────────────────────────────────────────────────────
Show-Progress "User Statistics" 42
Add-Title "5. USER STATISTICS"
try {
    $allUsers     = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordExpired, LockedOut, PasswordNeverExpires, Department
    $enabled      = @($allUsers | Where-Object { $_.Enabled })
    $disabled     = @($allUsers | Where-Object { -not $_.Enabled })
    $locked       = @($allUsers | Where-Object { $_.LockedOut })
    $pwdExpired   = @($allUsers | Where-Object { $_.PasswordExpired })
    $neverExpires = @($allUsers | Where-Object { $_.PasswordNeverExpires -and $_.Enabled })
    $inactive90   = @($allUsers | Where-Object { $_.Enabled -and $_.LastLogonDate -and ((Get-Date) - $_.LastLogonDate).Days -gt 90 })
    $neverLogged  = @($allUsers | Where-Object { $_.Enabled -and -not $_.LastLogonDate })

    Add-Sub "Account Counts"
    Add-Line "  Total Accounts        : $($allUsers.Count)"
    Add-Line "  Enabled               : $($enabled.Count)"
    Add-Line "  Disabled              : $($disabled.Count)"

    Add-Sub "Security Flags"
    Add-Line "  Locked Out            : $($locked.Count)"       ; if ($locked.Count -gt 0) { Add-Warn "$($locked.Count) account(s) currently locked out" }
    Add-Line "  Password Expired      : $($pwdExpired.Count)"   ; if ($pwdExpired.Count -gt 5) { Add-Warn "$($pwdExpired.Count) passwords expired" }
    Add-Line "  Password Never Expires: $($neverExpires.Count)" ; if ($neverExpires.Count -gt 5) { Add-Warn "$($neverExpires.Count) enabled accounts with Password Never Expires" }

    Add-Sub "Activity"
    Add-Line "  Inactive >90 days     : $($inactive90.Count)"  ; if ($inactive90.Count -gt 10) { Add-Warn "$($inactive90.Count) accounts inactive for 90+ days" }
    Add-Line "  Never Logged On       : $($neverLogged.Count)" ; if ($neverLogged.Count -gt 5) { Add-Warn "$($neverLogged.Count) enabled accounts have never logged on" }

    Add-Sub "By Department (Top 10)"
    $allUsers | Where-Object { $_.Enabled } | Group-Object Department | Sort-Object Count -Descending |
        Select-Object -First 10 | ForEach-Object {
            Add-Line ("  {0,-30} {1}" -f $(if($_.Name){"$($_.Name)"}else{"(No Department)"}), $_.Count)
        }
} catch { Add-Fail "User statistics failed: $($_.Exception.Message)" }

# ─── 6. Computer Statistics ───────────────────────────────────────────────────
Show-Progress "Computer Statistics" 54
Add-Title "6. COMPUTER STATISTICS"
try {
    $computers  = Get-ADComputer -Filter * -Properties Enabled, OperatingSystem, LastLogonDate
    $enabled    = @($computers | Where-Object { $_.Enabled })
    $stale90    = @($computers | Where-Object { $_.Enabled -and $_.LastLogonDate -and ((Get-Date) - $_.LastLogonDate).Days -gt 90 })

    Add-Line "  Total Computer Accounts: $($computers.Count)"
    Add-Line "  Enabled                : $($enabled.Count)"
    Add-Line "  Stale (>90 days)       : $($stale90.Count)"

    if ($stale90.Count -gt 10) { Add-Warn "$($stale90.Count) computer accounts inactive 90+ days" }

    Add-Sub "By Operating System"
    $computers | Where-Object { $_.Enabled } | Group-Object OperatingSystem | Sort-Object Count -Descending | ForEach-Object {
        Add-Line ("  {0,-45} {1}" -f $(if($_.Name){"$($_.Name)"}else{"Unknown"}), $_.Count)
    }
} catch { Add-Fail "Computer statistics failed: $($_.Exception.Message)" }

# ─── 7. Group Statistics ──────────────────────────────────────────────────────
Show-Progress "Group Statistics" 64
Add-Title "7. GROUP STATISTICS"
try {
    $groups  = Get-ADGroup -Filter * -Properties Members, GroupScope, GroupCategory
    $empty   = @($groups | Where-Object { $_.Members.Count -eq 0 })
    $security = @($groups | Where-Object { $_.GroupCategory -eq "Security" })
    $dist     = @($groups | Where-Object { $_.GroupCategory -eq "Distribution" })

    Add-Line "  Total Groups     : $($groups.Count)"
    Add-Line "  Security Groups  : $($security.Count)"
    Add-Line "  Distribution     : $($dist.Count)"
    Add-Line "  Empty Groups     : $($empty.Count)" ; if ($empty.Count -gt 20) { Add-Warn "$($empty.Count) empty groups found" }

    Add-Sub "By Scope"
    $groups | Group-Object GroupScope | Sort-Object Count -Descending | ForEach-Object {
        Add-Line "  $($_.Name): $($_.Count)"
    }
} catch { Add-Fail "Group statistics failed: $($_.Exception.Message)" }

# ─── 8. Password Policy ───────────────────────────────────────────────────────
Show-Progress "Password Policy" 74
Add-Title "8. PASSWORD POLICY"
try {
    $p = Get-ADDefaultDomainPasswordPolicy
    Add-Line "  Min Length          : $($p.MinPasswordLength)"
    Add-Line "  Max Age             : $($p.MaxPasswordAge)"
    Add-Line "  Complexity          : $($p.ComplexityEnabled)"
    Add-Line "  History Count       : $($p.PasswordHistoryCount)"
    Add-Line "  Lockout Threshold   : $($p.LockoutThreshold)"
    Add-Line "  Lockout Duration    : $($p.LockoutDuration)"
    Add-Line "  Lockout Window      : $($p.LockoutObservationWindow)"

    if ($p.MinPasswordLength -lt 12) { Add-Warn "Min password length $($p.MinPasswordLength) is below recommended 12" }
    if (-not $p.ComplexityEnabled)    { Add-Fail "Password complexity is DISABLED" }
    if ($p.LockoutThreshold -eq 0)    { Add-Warn "Account lockout threshold is not configured" }
    if ($p.PasswordHistoryCount -lt 10) { Add-Warn "Password history below recommended 10" }
} catch { Add-Fail "Password policy unavailable: $($_.Exception.Message)" }

# ─── 9. Privileged Groups ─────────────────────────────────────────────────────
Show-Progress "Privileged Groups" 83
Add-Title "9. PRIVILEGED GROUP SUMMARY"
try {
    $privGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators")
    foreach ($g in $privGroups) {
        try {
            $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop
            Add-Line "  $g : $($members.Count) member(s)"
            if ($g -eq "Domain Admins" -and $members.Count -gt 5) { Add-Warn "Domain Admins has $($members.Count) members - review for least privilege" }
            if ($g -eq "Schema Admins" -and $members.Count -gt 0) { Add-Warn "Schema Admins is not empty ($($members.Count) members)" }
        } catch { Add-Line "  $g : could not enumerate" }
    }
} catch { Add-Fail "Privileged group check failed: $($_.Exception.Message)" }

# ─── 10. Recent Activity ──────────────────────────────────────────────────────
Show-Progress "Recent Activity" 92
Add-Title "10. RECENT ACTIVITY (Last 7 Days)"
try {
    $cutoff  = (Get-Date).AddDays(-7)
    $newUsers = Get-ADUser -Filter { WhenCreated -gt $cutoff } -Properties WhenCreated | Sort-Object WhenCreated -Descending
    $newComps = Get-ADComputer -Filter { WhenCreated -gt $cutoff } -Properties WhenCreated | Sort-Object WhenCreated -Descending

    Add-Line "  New users created    : $($newUsers.Count)"
    $newUsers | Select-Object -First 5 | ForEach-Object { Add-Line "    + $($_.Name) ($($_.WhenCreated.ToString('yyyy-MM-dd')))" }

    Add-Line "  New computers joined : $($newComps.Count)"
    $newComps | Select-Object -First 5 | ForEach-Object { Add-Line "    + $($_.Name) ($($_.WhenCreated.ToString('yyyy-MM-dd')))" }
} catch { Add-Fail "Recent activity check failed: $($_.Exception.Message)" }

# ─── 11. Executive Summary ────────────────────────────────────────────────────
Show-Progress "Summary" 98
Add-Title "11. EXECUTIVE SUMMARY"
Add-Line ""
$fails = @($alerts | Where-Object { $_ -like "FAIL:*" })
$warns = @($alerts | Where-Object { $_ -like "WARN:*" })

if ($fails.Count -eq 0 -and $warns.Count -eq 0) {
    Add-OK "All checks passed. AD environment appears healthy."
} else {
    Add-Line "  Total Issues: $($alerts.Count)  ($($fails.Count) failures, $($warns.Count) warnings)"
    Add-Line ""
    if ($fails.Count -gt 0) {
        Add-Line "  FAILURES (action required):"
        $fails | ForEach-Object { Add-Line "    - $_" }
    }
    if ($warns.Count -gt 0) {
        Add-Line ""
        Add-Line "  WARNINGS (review recommended):"
        $warns | ForEach-Object { Add-Line "    - $_" }
    }
}

Add-Line ""
Add-Line "  Report generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-Line "  Domain          : $((Get-ADDomain).DNSRoot)"
Add-Line "  Generated by    : $env:USERNAME on $env:COMPUTERNAME"

Write-Progress -Activity "Generating AD Master Report" -Completed

# ─── Save Report ──────────────────────────────────────────────────────────────
$lines | Out-File -FilePath $reportFile -Encoding UTF8

if ($Zip) {
    $zipFile = $reportFile -replace "\.txt$", ".zip"
    Compress-Archive -Path $reportFile -DestinationPath $zipFile -Force
    Remove-Item $reportFile -Force
    Write-Host "`n[OK] Report compressed: $zipFile" -ForegroundColor Green
} else {
    Write-Host "`n[OK] Report saved: $reportFile" -ForegroundColor Green
}

Write-Host "`n  Summary: $($fails.Count) failure(s), $($warns.Count) warning(s)" -ForegroundColor $(if($fails.Count){"Red"}elseif($warns.Count){"Yellow"}else{"Green"})
