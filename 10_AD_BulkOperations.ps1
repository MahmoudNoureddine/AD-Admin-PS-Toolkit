#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD Bulk Operations - Mass update, export, and manage AD objects via CSV.

.DESCRIPTION
    Perform bulk operations across multiple AD users or computers:
      - Bulk update user attributes (department, title, manager, etc.)
      - Bulk enable or disable accounts
      - Bulk add users to groups from CSV
      - Bulk move users to different OUs
      - Export users to CSV for editing and re-import
      - Bulk set password expiry options

.PARAMETER OutputPath
    Directory for output files and logs. Defaults to Desktop.

.EXAMPLE
    .\10_AD_BulkOperations.ps1

.NOTES
    Prerequisites : ActiveDirectory module, appropriate AD rights.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "AD_BulkOps_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] [Op:$env:USERNAME] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR"{"Red"} "WARN"{"Yellow"} "OK"{"Green"} default{"Gray"} }
    Write-Host "  $entry" -ForegroundColor $color
}

function Invoke-BulkAction {
    param([string]$CsvPath, [scriptblock]$Action, [string]$Label)
    if (-not (Test-Path $CsvPath)) { Write-Host "  CSV not found: $CsvPath" -ForegroundColor Red; return }
    $rows = Import-Csv $CsvPath
    $ok = 0; $fail = 0
    Write-Host "  Processing $($rows.Count) record(s)..." -ForegroundColor Gray
    foreach ($row in $rows) {
        try { & $Action $row; $ok++ }
        catch { Write-Log "$Label FAILED for $($row.SamAccountName): $($_.Exception.Message)" "WARN"; $fail++ }
    }
    Write-Log "$Label complete: $ok OK, $fail failed" $(if($fail){"WARN"}else{"OK"})
    Write-Host "  Done: $ok succeeded, $fail failed." -ForegroundColor $(if($fail){"Yellow"}else{"Green"})
}

# ─── 1. Bulk Update Attributes ────────────────────────────────────────────────
function Invoke-BulkUpdateAttributes {
    Write-Host "`n--- BULK UPDATE USER ATTRIBUTES ---" -ForegroundColor Yellow
    Write-Host "  Expected CSV columns: SamAccountName, Department, Title, Office, Phone, Manager"
    $csv = Read-Host "  CSV file path"
    $preview = Read-Host "  Preview only? (Y/N)"

    if (-not (Test-Path $csv)) { Write-Host "  File not found." -ForegroundColor Red; return }

    $rows = Import-Csv $csv
    $ok = 0; $fail = 0

    foreach ($row in $rows) {
        $sam = $row.SamAccountName.Trim()
        Write-Host "  Processing: $sam" -ForegroundColor Gray

        try {
            $user = Get-ADUser -Identity $sam -ErrorAction Stop

            $params = @{ Identity = $sam }
            if ($row.Department) { $params["Department"] = $row.Department }
            if ($row.Title)      { $params["Title"]      = $row.Title }
            if ($row.Office)     { $params["Office"]     = $row.Office }
            if ($row.Phone)      { $params["OfficePhone"] = $row.Phone }

            if ($row.Manager) {
                $mgr = Get-ADUser -Filter "SamAccountName -eq '$($row.Manager)'" -ErrorAction SilentlyContinue
                if ($mgr) { $params["Manager"] = $mgr.DistinguishedName }
            }

            if ($preview -ne 'Y') {
                Set-ADUser @params -ErrorAction Stop
                Write-Log "Updated attributes for: $sam" "OK"
                $ok++
            } else {
                Write-Host "  [PREVIEW] Would update: $sam -> $($params | Out-String -Width 120)" -ForegroundColor Cyan
                $ok++
            }
        } catch {
            Write-Log "Failed to update $sam : $($_.Exception.Message)" "WARN"
            $fail++
        }
    }
    Write-Host "  Done: $ok processed, $fail failed." -ForegroundColor $(if($fail){"Yellow"}else{"Green"})
}

# ─── 2. Bulk Enable / Disable ─────────────────────────────────────────────────
function Invoke-BulkEnableDisable {
    Write-Host "`n--- BULK ENABLE / DISABLE ACCOUNTS ---" -ForegroundColor Yellow
    Write-Host "  Expected CSV column: SamAccountName"
    $action = Read-Host "  Action: [1] Enable  [2] Disable"
    $csv    = Read-Host "  CSV file path"

    if (-not (Test-Path $csv)) { Write-Host "  File not found." -ForegroundColor Red; return }

    $rows = Import-Csv $csv
    $confirm = Read-Host "  $(if($action -eq '1'){'Enable'}else{'Disable'}) $($rows.Count) accounts? (Y/N)"
    if ($confirm -ne 'Y') { return }

    $ok = 0; $fail = 0
    foreach ($row in $rows) {
        $sam = $row.SamAccountName.Trim()
        try {
            if ($action -eq '1') { Enable-ADAccount -Identity $sam -ErrorAction Stop }
            else                  { Disable-ADAccount -Identity $sam -ErrorAction Stop }
            Write-Log "$(if($action -eq '1'){'Enabled'}else{'Disabled'}): $sam" "OK"
            $ok++
        } catch {
            Write-Log "Failed for $sam : $($_.Exception.Message)" "WARN"
            $fail++
        }
    }
    Write-Host "  Done: $ok processed, $fail failed." -ForegroundColor $(if($fail){"Yellow"}else{"Green"})
}

# ─── 3. Bulk Add to Group ─────────────────────────────────────────────────────
function Invoke-BulkAddToGroup {
    Write-Host "`n--- BULK ADD USERS TO GROUP ---" -ForegroundColor Yellow
    Write-Host "  Expected CSV column: SamAccountName"
    $group = Read-Host "  Target group name"
    $csv   = Read-Host "  CSV file path"

    try { Get-ADGroup -Identity $group -ErrorAction Stop | Out-Null }
    catch { Write-Host "  Group '$group' not found." -ForegroundColor Red; return }

    Invoke-BulkAction -CsvPath $csv -Label "BulkAddToGroup($group)" -Action {
        param($row)
        Add-ADGroupMember -Identity $group -Members $row.SamAccountName.Trim() -ErrorAction Stop
        Write-Host "  [OK] Added: $($row.SamAccountName)" -ForegroundColor Green
    }
}

# ─── 4. Bulk Move Users to OU ─────────────────────────────────────────────────
function Invoke-BulkMoveOU {
    Write-Host "`n--- BULK MOVE USERS TO OU ---" -ForegroundColor Yellow
    Write-Host "  Expected CSV columns: SamAccountName, TargetOU"
    Write-Host "  (TargetOU can be per-row, or enter one OU for all)"
    $csv       = Read-Host "  CSV file path"
    $globalOU  = Read-Host "  Single target OU for all (leave blank to use per-row TargetOU)"

    if (-not (Test-Path $csv)) { Write-Host "  File not found." -ForegroundColor Red; return }

    $rows = Import-Csv $csv
    $ok = 0; $fail = 0

    foreach ($row in $rows) {
        $sam      = $row.SamAccountName.Trim()
        $targetOU = if ($globalOU) { $globalOU } else { $row.TargetOU }
        try {
            $user = Get-ADUser -Identity $sam -ErrorAction Stop
            Move-ADObject -Identity $user.DistinguishedName -TargetPath $targetOU -ErrorAction Stop
            Write-Log "Moved $sam to: $targetOU" "OK"
            Write-Host "  [OK] $sam -> $targetOU" -ForegroundColor Green
            $ok++
        } catch {
            Write-Log "Failed to move $sam : $($_.Exception.Message)" "WARN"
            Write-Host "  [FAIL] $sam : $($_.Exception.Message)" -ForegroundColor Red
            $fail++
        }
    }
    Write-Host "  Done: $ok moved, $fail failed." -ForegroundColor $(if($fail){"Yellow"}else{"Green"})
}

# ─── 5. Export Users to CSV ───────────────────────────────────────────────────
function Export-UsersToCSV {
    Write-Host "`n--- EXPORT USERS TO CSV FOR BULK EDIT ---" -ForegroundColor Yellow
    $filter = Read-Host "  Filter: [1] All enabled users  [2] By OU  [3] By Department"
    $csv    = Join-Path $OutputPath "UserExport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    try {
        $users = switch ($filter) {
            '1' { Get-ADUser -Filter { Enabled -eq $true } -Properties Department, Title, Office, OfficePhone, Manager, EmailAddress }
            '2' {
                $ou = Read-Host "  OU Distinguished Name"
                Get-ADUser -Filter * -SearchBase $ou -Properties Department, Title, Office, OfficePhone, Manager, EmailAddress
            }
            '3' {
                $dept = Read-Host "  Department name"
                Get-ADUser -Filter "Department -eq '$dept'" -Properties Department, Title, Office, OfficePhone, Manager, EmailAddress
            }
        }

        $users | ForEach-Object {
            $mgrName = if ($_.Manager) { (Get-ADUser -Identity $_.Manager -ErrorAction SilentlyContinue).SamAccountName } else { "" }
            [PSCustomObject]@{
                SamAccountName = $_.SamAccountName
                DisplayName    = $_.Name
                Department     = $_.Department
                Title          = $_.Title
                Office         = $_.Office
                Phone          = $_.OfficePhone
                Manager        = $mgrName
                Email          = $_.EmailAddress
            }
        } | Export-Csv -Path $csv -NoTypeInformation

        Write-Host "  Exported $($users.Count) user(s) to: $csv" -ForegroundColor Green
        Write-Host "  Edit the CSV and use other bulk options to re-import changes." -ForegroundColor Gray
        Write-Log "Exported $($users.Count) users to: $csv"
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── 6. Bulk Set Password Never Expires ───────────────────────────────────────
function Set-BulkPasswordExpiry {
    Write-Host "`n--- BULK SET PASSWORD EXPIRY ---" -ForegroundColor Yellow
    Write-Host "  Expected CSV column: SamAccountName"
    $action = Read-Host "  [1] Set Password Never Expires = TRUE  [2] Set = FALSE (passwords will expire)"
    $csv    = Read-Host "  CSV file path"
    $never  = $action -eq '1'

    Invoke-BulkAction -CsvPath $csv -Label "BulkPasswordExpiry" -Action {
        param($row)
        Set-ADUser -Identity $row.SamAccountName.Trim() -PasswordNeverExpires $never -ErrorAction Stop
        Write-Host "  [OK] $($row.SamAccountName) PasswordNeverExpires=$never" -ForegroundColor $(if($never){"Yellow"}else{"Green"})
    }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   AD BULK OPERATIONS"                                          -ForegroundColor Yellow
    Write-Host "   Domain: $((Get-ADDomain).DNSRoot)"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Bulk update user attributes (CSV)"   -ForegroundColor White
    Write-Host "  [2] Bulk enable / disable accounts"      -ForegroundColor White
    Write-Host "  [3] Bulk add users to a group"           -ForegroundColor White
    Write-Host "  [4] Bulk move users to an OU"            -ForegroundColor White
    Write-Host "  [5] Export users to CSV for editing"     -ForegroundColor White
    Write-Host "  [6] Bulk set password expiry policy"     -ForegroundColor White
    Write-Host "  [Q] Quit"                                -ForegroundColor Gray
    Write-Host ""
}

Write-Log "AD Bulk Operations started"
try {
    do {
        Show-Menu
        $choice = Read-Host "Select option"
        switch ($choice.ToUpper()) {
            '1' { Invoke-BulkUpdateAttributes; Read-Host "`nPress Enter" }
            '2' { Invoke-BulkEnableDisable;    Read-Host "`nPress Enter" }
            '3' { Invoke-BulkAddToGroup;       Read-Host "`nPress Enter" }
            '4' { Invoke-BulkMoveOU;           Read-Host "`nPress Enter" }
            '5' { Export-UsersToCSV;           Read-Host "`nPress Enter" }
            '6' { Set-BulkPasswordExpiry;      Read-Host "`nPress Enter" }
            'Q' { break }
            default { Write-Host "  Invalid." -ForegroundColor Yellow; Start-Sleep 1 }
        }
    } while ($choice.ToUpper() -ne 'Q')
} catch {
    Write-Host "`n[FATAL] $($_.Exception.Message)" -ForegroundColor Red; exit 1
}
