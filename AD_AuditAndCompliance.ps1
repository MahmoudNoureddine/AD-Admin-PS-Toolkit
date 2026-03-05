#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD Audit & Compliance - Security and compliance auditing for Active Directory.

.DESCRIPTION
    Generates comprehensive security audit reports:
      - Privileged group membership audit
      - Admin accounts with no recent logon
      - Service accounts audit
      - Guest account status
      - Accounts never logged on
      - Password policy compliance
      - Admin SmartCard requirements

.PARAMETER OutputPath
    Directory for audit reports. Defaults to Desktop.

.EXAMPLE
    .\11_AD_AuditAndCompliance.ps1
    .\11_AD_AuditAndCompliance.ps1 -OutputPath "C:\AuditReports"

.NOTES
    Prerequisites : ActiveDirectory module; read access to AD.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "AD_AuditReport_$timestamp.txt"
$lines      = [System.Collections.Generic.List[string]]::new()
$alerts     = [System.Collections.Generic.List[string]]::new()

function Write-Section { param([string]$T)
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $T" -ForegroundColor Yellow
    Write-Host "$("=" * 60)" -ForegroundColor Cyan
}
function Add-Line  { param([string]$T = ""); $lines.Add($T); Write-Host $T }
function Add-Alert { param([string]$T)
    $alerts.Add($T)
    Write-Host "  *** ALERT: $T ***" -ForegroundColor Red
    $lines.Add("  *** ALERT: $T ***")
}

# 1. Privileged Groups
Write-Section "PRIVILEGED GROUP MEMBERSHIP"
Add-Line "`n[High-Privilege Group Audit]"
$privGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Group Policy Creator Owners","Account Operators","Server Operators")
foreach ($group in $privGroups) {
    try {
        $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop | Sort-Object Name
        Add-Line "`n  $group ($($members.Count) members):"
        foreach ($m in $members) {
            $user = if ($m.objectClass -eq "user") {
                Get-ADUser -Identity $m.SamAccountName -Properties Enabled, LastLogonDate -ErrorAction SilentlyContinue
            } else { $null }
            $enabled   = if ($user) { $user.Enabled } else { "N/A" }
            $lastLogon = if ($user -and $user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
            Add-Line "    - $($m.Name) [$($m.objectClass)]  Enabled: $enabled  LastLogon: $lastLogon"
            if ($user -and -not $user.Enabled) { Add-Alert "Disabled account in privileged group: $($m.Name) ($group)" }
            if ($user -and $user.LastLogonDate -and ((Get-Date) - $user.LastLogonDate).Days -gt 90) {
                Add-Alert "Privileged account not used in 90+ days: $($m.Name) ($group)"
            }
        }
    } catch { Add-Line "  $group : Could not enumerate ($($_.Exception.Message))" }
}

# 2. Service Accounts
Write-Section "SERVICE ACCOUNTS AUDIT"
Add-Line "`n[Service Accounts]"
try {
    $svcAccounts = Get-ADUser -Filter {
        SamAccountName -like "svc-*" -or SamAccountName -like "sa-*" -or SamAccountName -like "svc_*"
    } -Properties PasswordNeverExpires, LastLogonDate, Enabled, MemberOf | Sort-Object SamAccountName

    Add-Line "  Found $($svcAccounts.Count) service account(s):"
    Add-Line ("  {0,-25} {1,-8} {2,-15} {3,-12} {4}" -f "Account","Enabled","LastLogon","PwdExpires","Groups")
    foreach ($s in $svcAccounts) {
        $ll  = if ($s.LastLogonDate) { $s.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
        $exp = -not $s.PasswordNeverExpires
        Add-Line ("  {0,-25} {1,-8} {2,-15} {3,-12} {4}" -f $s.SamAccountName, $s.Enabled, $ll, $exp, $s.MemberOf.Count)
        if ($s.PasswordNeverExpires) { Add-Alert "Service account Password Never Expires: $($s.SamAccountName)" }
    }
} catch { Add-Line "  [ERROR] $($_.Exception.Message)" }

# 3. Guest Account
Write-Section "GUEST & BUILT-IN ACCOUNT STATUS"
Add-Line ""
try {
    $guest = Get-ADUser -Filter "SamAccountName -eq 'Guest'" -Properties Enabled, LastLogonDate -ErrorAction Stop
    Add-Line "  Guest Account : Enabled=$($guest.Enabled)  LastLogon=$($guest.LastLogonDate)"
    if ($guest.Enabled) { Add-Alert "Guest account is ENABLED" }
} catch { Add-Line "  Guest account not found." }
try {
    $krb    = Get-ADUser -Filter "SamAccountName -eq 'krbtgt'" -Properties PasswordLastSet, Enabled
    $kAge   = if ($krb.PasswordLastSet) { [math]::Round(((Get-Date) - $krb.PasswordLastSet).TotalDays) } else { 9999 }
    Add-Line "  KRBTGT Account: Enabled=$($krb.Enabled)  PwdLastSet=$($krb.PasswordLastSet?.ToString('yyyy-MM-dd'))  Age: $kAge days"
    if ($kAge -gt 180) { Add-Alert "KRBTGT password not changed in $kAge days (recommend <180)" }
} catch {}

# 4. Never Logged On
Write-Section "ACCOUNTS NEVER LOGGED ON"
Add-Line ""
try {
    $never = Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate, WhenCreated |
             Where-Object { -not $_.LastLogonDate } | Sort-Object WhenCreated
    Add-Line "  $($never.Count) account(s) have never logged on:"
    foreach ($u in $never) {
        $age   = [math]::Round(((Get-Date) - $u.WhenCreated).TotalDays)
        $color = if ($age -gt 30) { "Yellow" } else { "White" }
        Write-Host ("  {0,-25} Created: {1}  ({2} days ago)" -f $u.SamAccountName, $u.WhenCreated.ToString("yyyy-MM-dd"), $age) -ForegroundColor $color
        $lines.Add(("  {0,-25} Created: {1}  ({2} days ago)" -f $u.SamAccountName, $u.WhenCreated.ToString("yyyy-MM-dd"), $age))
        if ($age -gt 30) { Add-Alert "Account created 30+ days ago, never used: $($u.SamAccountName)" }
    }
} catch { Add-Line "  [ERROR] $($_.Exception.Message)" }

# 5. Password Policy
Write-Section "PASSWORD POLICY"
Add-Line ""
try {
    $p = Get-ADDefaultDomainPasswordPolicy
    Add-Line "  Min Length        : $($p.MinPasswordLength)"
    Add-Line "  Max Age           : $($p.MaxPasswordAge)"
    Add-Line "  Complexity        : $($p.ComplexityEnabled)"
    Add-Line "  History Count     : $($p.PasswordHistoryCount)"
    Add-Line "  Lockout Threshold : $($p.LockoutThreshold)"
    Add-Line "  Lockout Duration  : $($p.LockoutDuration)"
    if ($p.MinPasswordLength -lt 12) { Add-Alert "Min password length is $($p.MinPasswordLength) - recommend 12+" }
    if (-not $p.ComplexityEnabled)    { Add-Alert "Password complexity is DISABLED" }
    if ($p.LockoutThreshold -eq 0)    { Add-Alert "Account lockout threshold is NOT set" }
} catch { Add-Line "  [ERROR] $($_.Exception.Message)" }

# 6. Admin SmartCard Check
Write-Section "DOMAIN ADMINS - SMARTCARD REQUIREMENT"
Add-Line ""
try {
    $admins = Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction Stop |
              Where-Object { $_.objectClass -eq "user" } |
              ForEach-Object { Get-ADUser -Identity $_.SamAccountName -Properties SmartcardLogonRequired, Enabled }
    foreach ($a in $admins) {
        $color = if ($a.SmartcardLogonRequired) { "Green" } else { "Yellow" }
        Write-Host ("  {0,-25} SmartCard: {1}" -f $a.SamAccountName, $a.SmartcardLogonRequired) -ForegroundColor $color
        $lines.Add(("  {0,-25} SmartCard: {1}" -f $a.SamAccountName, $a.SmartcardLogonRequired))
        if (-not $a.SmartcardLogonRequired) { Add-Alert "Domain Admin without SmartCard requirement: $($a.SamAccountName)" }
    }
} catch { Add-Line "  [ERROR] $($_.Exception.Message)" }

# Summary
Write-Section "AUDIT SUMMARY"
Add-Line ""
if ($alerts.Count -eq 0) {
    Write-Host "  [PASS] No critical issues detected." -ForegroundColor Green
    Add-Line "  Status: PASS"
} else {
    Write-Host "  [REVIEW] $($alerts.Count) issue(s) found:" -ForegroundColor Red
    Add-Line "  Status: $($alerts.Count) issue(s) require attention"
    foreach ($a in $alerts) { Add-Line "    - $a"; Write-Host "    - $a" -ForegroundColor Yellow }
}

$lines | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "`n[OK] Report saved: $reportFile" -ForegroundColor Green
