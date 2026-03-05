#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Account Expiry Manager - Manage and report on AD account expiration dates.

.DESCRIPTION
    Full account expiry lifecycle management:
      - View accounts expiring within a configurable window
      - Set or extend expiration dates on accounts
      - Remove expiration dates
      - Bulk expiry updates from CSV
      - Send expiry reminder report

.PARAMETER OutputPath    Directory for reports. Defaults to Desktop.
.PARAMETER DaysAhead     Lookahead window for expiring accounts. Default: 30.

.EXAMPLE
    .\13_AD_AccountExpiry.ps1
    .\13_AD_AccountExpiry.ps1 -DaysAhead 60

.NOTES
    Prerequisites : ActiveDirectory module; Account Operator rights.
    Author        : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    [int]$DaysAhead     = 30
)

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "AD_Expiry_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$M, [string]$L = "INFO")
    $e = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$L] $M"
    Add-Content $logFile $e -ErrorAction SilentlyContinue
    Write-Host "  $e" -ForegroundColor $(switch($L){"ERROR"{"Red"}"WARN"{"Yellow"}"OK"{"Green"}default{"Gray"}})
}

function Show-ExpiringAccounts {
    Write-Host "`n--- ACCOUNTS EXPIRING IN NEXT $DaysAhead DAYS ---" -ForegroundColor Yellow
    try {
        $expiring = Search-ADAccount -AccountExpiring -TimeSpan (New-TimeSpan -Days $DaysAhead) -UsersOnly |
                    Get-ADUser -Properties AccountExpirationDate, Department, EmailAddress, Title |
                    Sort-Object AccountExpirationDate

        if (-not $expiring) { Write-Host "  [OK] No accounts expiring in the next $DaysAhead days." -ForegroundColor Green; return }

        Write-Host "`n  $(@($expiring).Count) account(s) expiring:" -ForegroundColor Yellow
        Write-Host ("  {0,-25} {1,-12} {2,-6} {3,-20} {4}" -f "SAM","Expires","Days","Department","Name")
        Write-Host ("  {0,-25} {1,-12} {2,-6} {3,-20} {4}" -f "---","-------","----","----------","----")
        foreach ($u in $expiring) {
            $days  = [math]::Round(($u.AccountExpirationDate - (Get-Date)).TotalDays)
            $color = if ($days -le 7) { "Red" } elseif ($days -le 14) { "Yellow" } else { "White" }
            Write-Host ("  {0,-25} {1,-12} {2,-6} {3,-20} {4}" -f `
                $u.SamAccountName, $u.AccountExpirationDate.ToString("yyyy-MM-dd"), $days, $u.Department, $u.Name) -ForegroundColor $color
        }

        $csv = Join-Path $OutputPath "ExpiringAccounts_$(Get-Date -Format 'yyyyMMdd').csv"
        $expiring | Select-Object Name, SamAccountName, AccountExpirationDate, Department, EmailAddress |
            Export-Csv $csv -NoTypeInformation
        Write-Host "`n  Exported to: $csv" -ForegroundColor Gray
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

function Set-AccountExpiry {
    Write-Host "`n--- SET ACCOUNT EXPIRY DATE ---" -ForegroundColor Yellow
    $sam  = Read-Host "  SAMAccountName"
    $date = Read-Host "  Expiry date (yyyy-MM-dd) or 'never' to remove expiry"
    try {
        $user = Get-ADUser -Identity $sam -Properties AccountExpirationDate -ErrorAction Stop
        Write-Host "  Current expiry: $($user.AccountExpirationDate)" -ForegroundColor Cyan

        if ($date.ToLower() -eq 'never') {
            Clear-ADAccountExpiration -Identity $sam -ErrorAction Stop
            Write-Log "Removed expiry for: $sam" "OK"
            Write-Host "  [OK] Expiry removed. Account will not expire." -ForegroundColor Green
        } else {
            $expDate = [datetime]::ParseExact($date,"yyyy-MM-dd",$null)
            Set-ADAccountExpiration -Identity $sam -DateTime $expDate -ErrorAction Stop
            Write-Log "Set expiry for $sam to: $date" "OK"
            Write-Host "  [OK] Expiry set to: $date" -ForegroundColor Green
        }
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

function Extend-AccountExpiry {
    Write-Host "`n--- EXTEND ACCOUNT EXPIRY ---" -ForegroundColor Yellow
    $sam  = Read-Host "  SAMAccountName"
    $days = Read-Host "  Extend by how many days?"
    try {
        $user = Get-ADUser -Identity $sam -Properties AccountExpirationDate -ErrorAction Stop
        $base = if ($user.AccountExpirationDate -and $user.AccountExpirationDate -gt (Get-Date)) {
            $user.AccountExpirationDate
        } else { Get-Date }
        $newDate = $base.AddDays([int]$days)
        Set-ADAccountExpiration -Identity $sam -DateTime $newDate -ErrorAction Stop
        Write-Log "Extended expiry for $sam to: $($newDate.ToString('yyyy-MM-dd'))" "OK"
        Write-Host "  [OK] Expiry extended to: $($newDate.ToString('yyyy-MM-dd'))" -ForegroundColor Green
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

function Invoke-BulkExpiry {
    Write-Host "`n--- BULK SET EXPIRY FROM CSV ---" -ForegroundColor Yellow
    Write-Host "  Expected CSV columns: SamAccountName, ExpiryDate (yyyy-MM-dd or 'never')"
    $csv = Read-Host "  CSV file path"
    if (-not (Test-Path $csv)) { Write-Host "  File not found." -ForegroundColor Red; return }
    $rows = Import-Csv $csv
    $ok = 0; $fail = 0
    foreach ($row in $rows) {
        try {
            if ($row.ExpiryDate.ToLower() -eq 'never') {
                Clear-ADAccountExpiration -Identity $row.SamAccountName -ErrorAction Stop
            } else {
                $d = [datetime]::ParseExact($row.ExpiryDate,"yyyy-MM-dd",$null)
                Set-ADAccountExpiration -Identity $row.SamAccountName -DateTime $d -ErrorAction Stop
            }
            Write-Log "Bulk expiry set: $($row.SamAccountName) -> $($row.ExpiryDate)" "OK"
            $ok++
        } catch { Write-Log "Failed: $($row.SamAccountName) - $($_.Exception.Message)" "WARN"; $fail++ }
    }
    Write-Host "  Done: $ok updated, $fail failed." -ForegroundColor $(if($fail){"Yellow"}else{"Green"})
}

function Show-AllExpiries {
    Write-Host "`n--- ALL ACCOUNTS WITH EXPIRY DATES ---" -ForegroundColor Yellow
    try {
        $users = Get-ADUser -Filter { AccountExpirationDate -like "*" } `
            -Properties AccountExpirationDate, Department, Enabled | Sort-Object AccountExpirationDate
        Write-Host "`n  $($users.Count) account(s) have expiry dates set:" -ForegroundColor Cyan
        foreach ($u in $users) {
            $isPast  = $u.AccountExpirationDate -lt (Get-Date)
            $color   = if ($isPast) { "Red" } elseif (($u.AccountExpirationDate - (Get-Date)).TotalDays -le 30) { "Yellow" } else { "White" }
            $status  = if ($isPast) { "[EXPIRED]" } else { "" }
            Write-Host ("  {0,-25} {1,-12} {2,-12} {3} {4}" -f `
                $u.SamAccountName, $u.AccountExpirationDate.ToString("yyyy-MM-dd"), $u.Department, $u.Enabled, $status) -ForegroundColor $color
        }
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   ACCOUNT EXPIRY MANAGER" -ForegroundColor Yellow
    Write-Host "   Domain: $((Get-ADDomain).DNSRoot)"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  [1] View accounts expiring in next $DaysAhead days`n  [2] Set account expiry date`n  [3] Extend account expiry`n  [4] Bulk expiry from CSV`n  [5] View all accounts with expiry dates`n  [Q] Quit`n"
}

do {
    Show-Menu; $c = Read-Host "Select"
    switch ($c.ToUpper()) {
        '1' { Show-ExpiringAccounts;  Read-Host "`nPress Enter" }
        '2' { Set-AccountExpiry;      Read-Host "`nPress Enter" }
        '3' { Extend-AccountExpiry;   Read-Host "`nPress Enter" }
        '4' { Invoke-BulkExpiry;      Read-Host "`nPress Enter" }
        '5' { Show-AllExpiries;       Read-Host "`nPress Enter" }
        'Q' { break }
        default { Start-Sleep 1 }
    }
} while ($c.ToUpper() -ne 'Q')
