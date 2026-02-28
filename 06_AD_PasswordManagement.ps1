#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD Password Management - Reset passwords, unlock accounts, enforce policies.

.DESCRIPTION
    Comprehensive password and account management tool:
      - Reset user password (with temp password generation)
      - Unlock locked-out accounts
      - Force password change at next logon
      - Find accounts with passwords never expiring
      - Find accounts with expired passwords
      - Bulk unlock all locked accounts
      - Check password policy settings

.PARAMETER OutputPath
    Directory for logs. Defaults to Desktop.

.EXAMPLE
    .\06_AD_PasswordManagement.ps1

.NOTES
    Prerequisites : ActiveDirectory module; rights to reset passwords.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "AD_Password_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] [Op:$env:USERNAME] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR"{"Red"} "WARN"{"Yellow"} "OK"{"Green"} default{"Gray"} }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── Generate Temp Password ───────────────────────────────────────────────────
function New-TempPassword {
    $chars = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%"
    $pwd   = "Aa1!" + (-join (1..8 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] }))
    return $pwd
}

# ─── Reset Password ───────────────────────────────────────────────────────────
function Reset-UserPassword {
    Write-Host "`n--- RESET USER PASSWORD ---" -ForegroundColor Yellow
    $sam = Read-Host "  SAMAccountName"
    try {
        $user = Get-ADUser -Identity $sam -Properties LockedOut, PasswordExpired, PasswordLastSet -ErrorAction Stop
        Write-Host "  User: $($user.Name)  Locked: $($user.LockedOut)  PwdExpired: $($user.PasswordExpired)" -ForegroundColor Cyan

        $useTemp = Read-Host "  Generate temp password? (Y) or enter custom? (N)"
        if ($useTemp -eq 'Y') {
            $newPwd = New-TempPassword
            Write-Host "  Generated password: $newPwd" -ForegroundColor Yellow
        } else {
            $secure = Read-Host "  Enter new password" -AsSecureString
            $newPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
        }

        $mustChange = (Read-Host "  Must change at next logon? (Y/N) [Y]") -ne 'N'

        Set-ADAccountPassword -Identity $sam -NewPassword (ConvertTo-SecureString $newPwd -AsPlainText -Force) -Reset -ErrorAction Stop
        if ($mustChange) { Set-ADUser -Identity $sam -ChangePasswordAtLogon $true }

        # Unlock if locked
        if ($user.LockedOut) {
            Unlock-ADAccount -Identity $sam -ErrorAction SilentlyContinue
            Write-Log "Account also unlocked: $sam" "OK"
        }

        Write-Log "Password reset for: $sam (MustChange: $mustChange)" "OK"
        Write-Host "`n  [OK] Password reset successfully." -ForegroundColor Green
        if ($useTemp -eq 'Y') {
            Write-Host "  Temp Password: $newPwd" -ForegroundColor Yellow
            Write-Host "  *** Provide this to the user via a secure channel ***" -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Password reset FAILED for '$sam': $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Unlock Account ───────────────────────────────────────────────────────────
function Invoke-UnlockAccount {
    Write-Host "`n--- UNLOCK ACCOUNT ---" -ForegroundColor Yellow
    $sam = Read-Host "  SAMAccountName (or 'ALL' to unlock all locked accounts)"

    if ($sam.ToUpper() -eq 'ALL') {
        $locked = Search-ADAccount -LockedOut -UsersOnly -ErrorAction Stop
        if (-not $locked) { Write-Host "  No locked accounts found." -ForegroundColor Green; return }

        Write-Host "  Found $($locked.Count) locked account(s):" -ForegroundColor Cyan
        $locked | ForEach-Object { Write-Host "    - $($_.SamAccountName) ($($_.Name))" }

        $confirm = Read-Host "`n  Unlock ALL $($locked.Count) accounts? (Y/N)"
        if ($confirm -ne 'Y') { return }

        $ok = 0
        foreach ($acct in $locked) {
            try {
                Unlock-ADAccount -Identity $acct.SamAccountName -ErrorAction Stop
                Write-Log "Unlocked: $($acct.SamAccountName)" "OK"
                $ok++
            } catch {
                Write-Log "Could not unlock $($acct.SamAccountName): $($_.Exception.Message)" "WARN"
            }
        }
        Write-Host "  [OK] $ok account(s) unlocked." -ForegroundColor Green
    } else {
        try {
            $user = Get-ADUser -Identity $sam -Properties LockedOut -ErrorAction Stop
            if (-not $user.LockedOut) {
                Write-Host "  Account '$sam' is not locked." -ForegroundColor Yellow
                return
            }
            Unlock-ADAccount -Identity $sam -ErrorAction Stop
            Write-Log "Unlocked: $sam" "OK"
            Write-Host "  [OK] Account '$sam' unlocked." -ForegroundColor Green
        } catch {
            Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ─── Find Password Policy Issues ──────────────────────────────────────────────
function Find-PasswordIssues {
    Write-Host "`n--- PASSWORD AUDIT ---" -ForegroundColor Yellow
    Write-Host "  Scanning for password policy issues..." -ForegroundColor Gray

    try {
        $allUsers = Get-ADUser -Filter { Enabled -eq $true } `
            -Properties PasswordNeverExpires, PasswordExpired, PasswordLastSet, LockedOut, `
                        LastLogonDate, PasswordNotRequired -ErrorAction Stop

        $neverExpires   = $allUsers | Where-Object { $_.PasswordNeverExpires }
        $expired        = $allUsers | Where-Object { $_.PasswordExpired }
        $locked         = $allUsers | Where-Object { $_.LockedOut }
        $notRequired    = $allUsers | Where-Object { $_.PasswordNotRequired }
        $oldPwd         = $allUsers | Where-Object { $_.PasswordLastSet -and $_.PasswordLastSet -lt (Get-Date).AddDays(-90) }

        Write-Host "`n  PASSWORD AUDIT RESULTS:" -ForegroundColor Cyan
        Write-Host "  Password Never Expires : $($neverExpires.Count)" -ForegroundColor $(if($neverExpires.Count -gt 0){"Yellow"}else{"White"})
        Write-Host "  Passwords Expired      : $($expired.Count)"      -ForegroundColor $(if($expired.Count -gt 0){"Red"}else{"White"})
        Write-Host "  Locked Accounts        : $($locked.Count)"       -ForegroundColor $(if($locked.Count -gt 0){"Red"}else{"White"})
        Write-Host "  Password Not Required  : $($notRequired.Count)"  -ForegroundColor $(if($notRequired.Count -gt 0){"Red"}else{"White"})
        Write-Host "  Password >90 Days Old  : $($oldPwd.Count)"       -ForegroundColor $(if($oldPwd.Count -gt 0){"Yellow"}else{"White"})

        # Export report
        $csv = Join-Path $OutputPath "PasswordAudit_$(Get-Date -Format 'yyyyMMdd').csv"
        $allUsers | Select-Object Name, SamAccountName, PasswordNeverExpires, PasswordExpired,
            PasswordLastSet, LockedOut, PasswordNotRequired, LastLogonDate |
            Export-Csv -Path $csv -NoTypeInformation
        Write-Host "`n  Full audit exported to: $csv" -ForegroundColor Gray
        Write-Log "Password audit completed. Exported to: $csv"

        # Show never-expire list
        if ($neverExpires.Count -gt 0) {
            Write-Host "`n  Accounts with Password Never Expires:" -ForegroundColor Yellow
            $neverExpires | Sort-Object Name | ForEach-Object {
                Write-Host "    $($_.SamAccountName) - $($_.Name)"
            }
        }
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── View Password Policy ─────────────────────────────────────────────────────
function Show-PasswordPolicy {
    Write-Host "`n--- DOMAIN PASSWORD POLICY ---" -ForegroundColor Yellow
    try {
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        Write-Host ""
        Write-Host ("  {0,-35} {1}" -f "Setting", "Value") -ForegroundColor Cyan
        Write-Host ("  {0,-35} {1}" -f "-------", "-----") -ForegroundColor Cyan
        Write-Host ("  {0,-35} {1}" -f "Min Password Length",    $policy.MinPasswordLength)
        Write-Host ("  {0,-35} {1}" -f "Max Password Age",       $policy.MaxPasswordAge)
        Write-Host ("  {0,-35} {1}" -f "Min Password Age",       $policy.MinPasswordAge)
        Write-Host ("  {0,-35} {1}" -f "Password History",       $policy.PasswordHistoryCount)
        Write-Host ("  {0,-35} {1}" -f "Complexity Required",    $policy.ComplexityEnabled)
        Write-Host ("  {0,-35} {1}" -f "Reversible Encryption",  $policy.ReversibleEncryptionEnabled)
        Write-Host ("  {0,-35} {1}" -f "Lockout Threshold",      $policy.LockoutThreshold)
        Write-Host ("  {0,-35} {1}" -f "Lockout Duration",       $policy.LockoutDuration)
        Write-Host ("  {0,-35} {1}" -f "Lockout Observation",    $policy.LockoutObservationWindow)

        # Fine-grained password policies
        $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
        if ($fgpp) {
            Write-Host "`n  Fine-Grained Password Policies: $($fgpp.Count)" -ForegroundColor Cyan
            $fgpp | ForEach-Object { Write-Host "    - $($_.Name)  Priority: $($_.Precedence)  MinLen: $($_.MinPasswordLength)" }
        }
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Force Password Change ────────────────────────────────────────────────────
function Set-ForcePasswordChange {
    Write-Host "`n--- FORCE PASSWORD CHANGE AT NEXT LOGON ---" -ForegroundColor Yellow
    $sam = Read-Host "  SAMAccountName (or 'bulk' to select multiple)"
    try {
        Set-ADUser -Identity $sam -ChangePasswordAtLogon $true -ErrorAction Stop
        Write-Log "Force password change set for: $sam" "OK"
        Write-Host "  [OK] '$sam' must change password at next logon." -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   AD PASSWORD MANAGEMENT"                                      -ForegroundColor Yellow
    Write-Host "   Domain: $((Get-ADDomain).DNSRoot)"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Reset user password"               -ForegroundColor White
    Write-Host "  [2] Unlock account(s)"                 -ForegroundColor White
    Write-Host "  [3] Force password change at logon"    -ForegroundColor White
    Write-Host "  [4] Password audit report"             -ForegroundColor White
    Write-Host "  [5] View domain password policy"       -ForegroundColor White
    Write-Host "  [Q] Quit"                              -ForegroundColor Gray
    Write-Host ""
}

Write-Log "AD Password Management started"
try {
    do {
        Show-Menu
        $choice = Read-Host "Select option"
        switch ($choice.ToUpper()) {
            '1' { Reset-UserPassword;       Read-Host "`nPress Enter" }
            '2' { Invoke-UnlockAccount;     Read-Host "`nPress Enter" }
            '3' { Set-ForcePasswordChange;  Read-Host "`nPress Enter" }
            '4' { Find-PasswordIssues;      Read-Host "`nPress Enter" }
            '5' { Show-PasswordPolicy;      Read-Host "`nPress Enter" }
            'Q' { break }
            default { Write-Host "  Invalid." -ForegroundColor Yellow; Start-Sleep 1 }
        }
    } while ($choice.ToUpper() -ne 'Q')
} catch {
    Write-Host "`n[FATAL] $($_.Exception.Message)" -ForegroundColor Red; exit 1
}
