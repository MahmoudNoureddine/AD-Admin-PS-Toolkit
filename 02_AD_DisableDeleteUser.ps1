#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Disables or deletes an Active Directory user account safely.

.DESCRIPTION
    Offboarding tool that can:
      - Disable an account and move it to a Disabled Users OU
      - Remove all group memberships before disabling
      - Optionally delete the account after a retention period
      - Add a description noting when and why it was disabled
      - Log all actions for auditing

.PARAMETER Identity
    SAMAccountName, UPN, or Display Name of the user.

.PARAMETER Action
    "Disable" or "Delete". Default is Disable.

.PARAMETER Reason
    Reason for the action (e.g. "Resigned", "Terminated", "Leave of Absence").

.PARAMETER RemoveGroups
    If specified, removes all group memberships before disabling.

.PARAMETER DisabledOU
    OU to move disabled accounts to.

.PARAMETER OutputPath
    Directory for logs. Defaults to Desktop.

.EXAMPLE
    .\02_AD_DisableDeleteUser.ps1 -Identity "jdoe" -Action Disable -Reason "Resigned"
    .\02_AD_DisableDeleteUser.ps1 -Identity "jdoe" -Action Delete

.NOTES
    Prerequisites : ActiveDirectory module, Domain Admin or Account Operator rights.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Identity,
    [ValidateSet("Disable","Delete")][string]$Action = "Disable",
    [string]$Reason      = "Account disabled by IT Administration",
    [switch]$RemoveGroups,
    [string]$DisabledOU  = "",   # e.g. "OU=Disabled,OU=Users,DC=domain,DC=com"
    [string]$OutputPath  = "$env:USERPROFILE\Desktop"
)

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "AD_DisableDelete_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] [Operator:$env:USERNAME] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } "OK" { "Green" } default { "Gray" } }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nAD User Disable/Delete Tool" -ForegroundColor Green

    # Find the user
    $user = Get-ADUser -Filter "SamAccountName -eq '$Identity' -or UserPrincipalName -eq '$Identity' -or DisplayName -eq '$Identity'" `
                -Properties MemberOf, Description, EmailAddress, Department -ErrorAction Stop |
                Select-Object -First 1

    if (-not $user) { throw "User '$Identity' not found in Active Directory." }

    Write-Host "`n  Found user:" -ForegroundColor Cyan
    Write-Host "    Name       : $($user.Name)"
    Write-Host "    SAM        : $($user.SamAccountName)"
    Write-Host "    UPN        : $($user.UserPrincipalName)"
    Write-Host "    Department : $($user.Department)"
    Write-Host "    Enabled    : $($user.Enabled)"
    Write-Host "    Action     : $Action"
    Write-Host ""

    # Confirmation
    $confirm = Read-Host "  Confirm $Action for '$($user.Name)'? (Y/N)"
    if ($confirm -ne 'Y') { Write-Host "  Cancelled." -ForegroundColor Yellow; exit 0 }

    Write-Log "$Action initiated for: $($user.SamAccountName) ($($user.Name)) - Reason: $Reason"

    if ($Action -eq "Disable") {

        # 1. Disable the account
        Disable-ADAccount -Identity $user.SamAccountName -ErrorAction Stop
        Write-Log "Account disabled: $($user.SamAccountName)" "OK"

        # 2. Remove all group memberships (except Domain Users)
        if ($RemoveGroups) {
            $groups = $user.MemberOf
            foreach ($group in $groups) {
                try {
                    Remove-ADGroupMember -Identity $group -Members $user.SamAccountName -Confirm:$false -ErrorAction Stop
                    Write-Log "Removed from group: $group" "OK"
                } catch {
                    Write-Log "Could not remove from group $group : $($_.Exception.Message)" "WARN"
                }
            }
        }

        # 3. Update description with disable date and reason
        $newDesc = "DISABLED: $(Get-Date -Format 'yyyy-MM-dd') | Reason: $Reason | By: $env:USERNAME"
        Set-ADUser -Identity $user.SamAccountName -Description $newDesc -ErrorAction SilentlyContinue
        Write-Log "Description updated: $newDesc"

        # 4. Reset password to random (prevent unauthorized use)
        $rndPwd = [System.Web.Security.Membership]::GeneratePassword(20, 5)
        try {
            $rndPwd = (-join ((65..90)+(97..122)+(48..57)+(33,35,36,37,38,42,64) | Get-Random -Count 20 | ForEach-Object { [char]$_ }))
            Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword (ConvertTo-SecureString $rndPwd -AsPlainText -Force) -Reset -ErrorAction SilentlyContinue
            Write-Log "Password reset to random value" "OK"
        } catch {
            Write-Log "Could not reset password: $($_.Exception.Message)" "WARN"
        }

        # 5. Move to disabled OU
        if ($DisabledOU) {
            try {
                Get-ADOrganizationalUnit -Identity $DisabledOU -ErrorAction Stop | Out-Null
                Move-ADObject -Identity $user.DistinguishedName -TargetPath $DisabledOU -ErrorAction Stop
                Write-Log "Moved to Disabled OU: $DisabledOU" "OK"
            } catch {
                Write-Log "Could not move to Disabled OU: $($_.Exception.Message)" "WARN"
            }
        }

        Write-Host "`n  [OK] Account '$($user.SamAccountName)' has been disabled." -ForegroundColor Green
        Write-Host "  Checklist reminder:" -ForegroundColor Yellow
        Write-Host "    - Revoke Microsoft 365 / Exchange access"
        Write-Host "    - Revoke VPN access"
        Write-Host "    - Recover company equipment"
        Write-Host "    - Forward email if required"

    } elseif ($Action -eq "Delete") {

        # Extra confirmation for deletion
        Write-Host "`n  WARNING: This will PERMANENTLY delete the account." -ForegroundColor Red
        $confirm2 = Read-Host "  Type the username '$($user.SamAccountName)' to confirm deletion"
        if ($confirm2 -ne $user.SamAccountName) {
            Write-Host "  Confirmation failed. Aborting." -ForegroundColor Yellow
            Write-Log "Delete aborted - confirmation mismatch" "WARN"
            exit 0
        }

        Remove-ADUser -Identity $user.SamAccountName -Confirm:$false -ErrorAction Stop
        Write-Log "Account DELETED: $($user.SamAccountName) ($($user.Name))" "OK"
        Write-Host "`n  [OK] Account '$($user.SamAccountName)' has been permanently deleted." -ForegroundColor Green
    }

} catch {
    Write-Log "FAILED: $($_.Exception.Message)" "ERROR"
    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
