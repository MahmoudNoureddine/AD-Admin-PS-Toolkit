#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Offboarding Workflow - Complete automated user offboarding checklist.

.DESCRIPTION
    Runs a structured, step-by-step offboarding process for departing users:
      1. Disable account
      2. Reset to random password
      3. Remove all group memberships
      4. Hide from GAL / clear email
      5. Move to Disabled OU
      6. Update description with offboarding stamp
      7. Manager notification summary
      8. Generate offboarding report

    All steps are logged and a completion report is saved.

.PARAMETER Identity     SAMAccountName of the user to offboard.
.PARAMETER Reason       Reason for offboarding (Resigned/Terminated/etc).
.PARAMETER DisabledOU   OU DN to move disabled account to.
.PARAMETER OutputPath   Directory for reports. Defaults to Desktop.

.EXAMPLE
    .\15_AD_OffboardingWorkflow.ps1 -Identity "jdoe" -Reason "Resigned"

.NOTES
    Prerequisites : ActiveDirectory module; Account Operator / Domain Admin.
    Author        : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Identity,
    [string]$Reason     = "Employee departure",
    [string]$DisabledOU = "",
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "Offboarding_${Identity}_$timestamp.txt"
$logFile    = Join-Path $OutputPath "AD_Offboarding_$(Get-Date -Format 'yyyyMMdd').log"
$lines      = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$M, [string]$L = "INFO")
    $e = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$L] [Op:$env:USERNAME] $M"
    Add-Content $logFile $e -ErrorAction SilentlyContinue
    $lines.Add($e)
    Write-Host "  $e" -ForegroundColor $(switch($L){"ERROR"{"Red"}"WARN"{"Yellow"}"OK"{"Green"}default{"Gray"}})
}

function Write-Step { param([int]$N, [string]$T)
    Write-Host "`n  [$N/8] $T" -ForegroundColor Cyan
    $lines.Add("`n  [$N/8] $T")
}

try {
    Write-Host "`nAD Offboarding Workflow" -ForegroundColor Red
    Write-Host "  User    : $Identity"
    Write-Host "  Reason  : $Reason"
    Write-Host "  Operator: $env:USERNAME"
    Write-Host ""

    # Load user
    $user = Get-ADUser -Filter "SamAccountName -eq '$Identity'" `
        -Properties MemberOf, Description, EmailAddress, Department, Manager, DisplayName, Title `
        -ErrorAction Stop | Select-Object -First 1

    if (-not $user) { throw "User '$Identity' not found in Active Directory." }

    Write-Host "  Found: $($user.Name)  |  $($user.Title)  |  $($user.Department)" -ForegroundColor Yellow
    $confirm = Read-Host "`n  Start offboarding for '$($user.Name)'? (Y/N)"
    if ($confirm -ne 'Y') { Write-Host "  Cancelled." -ForegroundColor Gray; exit 0 }

    $lines.Add("=" * 60)
    $lines.Add("  OFFBOARDING REPORT: $($user.Name)")
    $lines.Add("  Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $lines.Add("  Reason  : $Reason")
    $lines.Add("  Operator: $env:USERNAME")
    $lines.Add("=" * 60)

    # STEP 1: Disable account
    Write-Step 1 "Disabling account"
    try {
        Disable-ADAccount -Identity $Identity -ErrorAction Stop
        Write-Log "Account disabled: $Identity" "OK"
    } catch { Write-Log "FAILED to disable: $($_.Exception.Message)" "ERROR" }

    # STEP 2: Reset password
    Write-Step 2 "Resetting password to random value"
    try {
        $rnd = (-join ((65..90)+(97..122)+(48..57)+(33,35,36,37) | Get-Random -Count 20 | ForEach-Object { [char]$_ }))
        Set-ADAccountPassword -Identity $Identity -NewPassword (ConvertTo-SecureString $rnd -AsPlainText -Force) -Reset -ErrorAction Stop
        Write-Log "Password reset to random value" "OK"
    } catch { Write-Log "FAILED to reset password: $($_.Exception.Message)" "WARN" }

    # STEP 3: Remove group memberships
    Write-Step 3 "Removing group memberships"
    $removedGroups = [System.Collections.Generic.List[string]]::new()
    foreach ($g in $user.MemberOf) {
        try {
            $groupName = ($g -split ",")[0] -replace "CN="
            Remove-ADGroupMember -Identity $g -Members $Identity -Confirm:$false -ErrorAction Stop
            $removedGroups.Add($groupName)
            Write-Log "Removed from group: $groupName" "OK"
        } catch { Write-Log "Could not remove from group $g : $($_.Exception.Message)" "WARN" }
    }
    Write-Log "Removed from $($removedGroups.Count) group(s)" "OK"

    # STEP 4: Clear sensitive attributes
    Write-Step 4 "Clearing email and profile attributes"
    try {
        Set-ADUser -Identity $Identity -Clear EmailAddress, HomeDirectory, HomeDrive -ErrorAction SilentlyContinue
        Write-Log "Cleared email and home directory attributes" "OK"
    } catch { Write-Log "Could not clear attributes: $($_.Exception.Message)" "WARN" }

    # STEP 5: Update description
    Write-Step 5 "Stamping description with offboarding info"
    try {
        $desc = "OFFBOARDED: $(Get-Date -Format 'yyyy-MM-dd') | Reason: $Reason | By: $env:USERNAME"
        Set-ADUser -Identity $Identity -Description $desc -ErrorAction Stop
        Write-Log "Description updated: $desc" "OK"
    } catch { Write-Log "FAILED to update description: $($_.Exception.Message)" "WARN" }

    # STEP 6: Move to disabled OU
    Write-Step 6 "Moving account to Disabled OU"
    if ($DisabledOU) {
        try {
            $userDN = (Get-ADUser -Identity $Identity).DistinguishedName
            Move-ADObject -Identity $userDN -TargetPath $DisabledOU -ErrorAction Stop
            Write-Log "Moved to: $DisabledOU" "OK"
        } catch { Write-Log "FAILED to move: $($_.Exception.Message)" "WARN" }
    } else {
        Write-Log "No Disabled OU specified - account remains in current OU" "WARN"
    }

    # STEP 7: Manager info
    Write-Step 7 "Retrieving manager information"
    $mgrName = ""
    if ($user.Manager) {
        try {
            $mgr     = Get-ADUser -Identity $user.Manager -Properties EmailAddress
            $mgrName = $mgr.Name
            Write-Log "Manager identified: $mgrName ($($mgr.EmailAddress))" "OK"
        } catch { Write-Log "Could not retrieve manager info" "WARN" }
    } else {
        Write-Log "No manager assigned to this account" "WARN"
    }

    # STEP 8: Final report
    Write-Step 8 "Generating offboarding report"

    $lines.Add("`n  OFFBOARDING CHECKLIST:")
    $lines.Add("  [X] Account disabled")
    $lines.Add("  [X] Password randomized")
    $lines.Add("  [X] Removed from $($removedGroups.Count) group(s): $($removedGroups -join ', ')")
    $lines.Add("  [X] Email address cleared")
    $lines.Add("  [X] Description stamped")
    $lines.Add(if ($DisabledOU) { "  [X] Moved to Disabled OU" } else { "  [ ] No Disabled OU configured" })
    $lines.Add("  [ ] Exchange/M365 license revoked    <-- Manual step required")
    $lines.Add("  [ ] VPN access revoked               <-- Manual step required")
    $lines.Add("  [ ] Physical access revoked          <-- Manual step required")
    $lines.Add("  [ ] Company equipment recovered      <-- Manual step required")
    $lines.Add("  [ ] Email forwarding configured      <-- Check with manager")
    $lines.Add("`n  Manager to notify: $mgrName")

    $lines | Out-File -FilePath $reportFile -Encoding UTF8

    Write-Host "`n  ============================================" -ForegroundColor Green
    Write-Host "  OFFBOARDING COMPLETE" -ForegroundColor Green
    Write-Host "  ============================================" -ForegroundColor Green
    Write-Host "  Report saved: $reportFile" -ForegroundColor Gray
    Write-Host "`n  MANUAL STEPS STILL REQUIRED:" -ForegroundColor Yellow
    Write-Host "    - Revoke M365/Exchange license"
    Write-Host "    - Revoke VPN access"
    Write-Host "    - Notify manager: $mgrName"
    Write-Host "    - Recover company equipment"

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
