#Requires -Version 5.1
#Requires -Modules GroupPolicy, ActiveDirectory
<#
.SYNOPSIS
    GPO Management - Create, link, report, and manage Group Policy Objects.

.DESCRIPTION
    Manages Group Policy with the ability to:
      - List all GPOs with link status
      - Create new GPOs
      - Link/unlink GPOs to OUs
      - Enable/disable GPOs
      - Backup and restore GPOs
      - Generate GPO reports (HTML)
      - Find unlinked GPOs
      - Check GPO inheritance on OUs

.PARAMETER OutputPath
    Directory for backups and reports. Defaults to Desktop.

.EXAMPLE
    .\09_AD_GPOManagement.ps1

.NOTES
    Prerequisites : GroupPolicy and ActiveDirectory modules; GPMC installed.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "AD_GPO_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] [Op:$env:USERNAME] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR"{"Red"} "WARN"{"Yellow"} "OK"{"Green"} default{"Gray"} }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── List All GPOs ────────────────────────────────────────────────────────────
function Show-AllGPOs {
    Write-Host "`n--- ALL GROUP POLICY OBJECTS ---" -ForegroundColor Yellow
    try {
        $gpos = Get-GPO -All | Sort-Object DisplayName
        Write-Host "`n  Found $($gpos.Count) GPO(s):" -ForegroundColor Cyan
        Write-Host ("  {0,-45} {1,-12} {2,-12} {3}" -f "GPO Name", "User Ver", "Comp Ver", "Status")
        Write-Host ("  {0,-45} {1,-12} {2,-12} {3}" -f "--------", "--------", "--------", "------")

        foreach ($g in $gpos) {
            $status = if ($g.GpoStatus -eq "AllSettingsEnabled") { "Enabled" } else { $g.GpoStatus }
            $color  = if ($g.GpoStatus -eq "AllSettingsEnabled") { "White" } else { "DarkGray" }
            Write-Host ("  {0,-45} {1,-12} {2,-12} {3}" -f `
                ($g.DisplayName.Substring(0,[math]::Min(44,$g.DisplayName.Length))), `
                $g.UserVersion, $g.ComputerVersion, $status) -ForegroundColor $color
        }

        # Export
        $csv = Join-Path $OutputPath "GPO_List_$(Get-Date -Format 'yyyyMMdd').csv"
        $gpos | Select-Object DisplayName, Id, GpoStatus, UserVersion, ComputerVersion, WhenCreated, WhenChanged |
            Export-Csv -Path $csv -NoTypeInformation
        Write-Host "`n  Exported to: $csv" -ForegroundColor Gray
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Create GPO ───────────────────────────────────────────────────────────────
function New-GPOMenu {
    Write-Host "`n--- CREATE NEW GPO ---" -ForegroundColor Yellow
    $name    = Read-Host "  GPO Name"
    $comment = Read-Host "  Comment/Description (optional)"
    $linkOU  = Read-Host "  Link to OU DN immediately? (leave blank to skip)"

    try {
        $params = @{ Name = $name }
        if ($comment) { $params["Comment"] = $comment }
        $gpo = New-GPO @params -ErrorAction Stop
        Write-Log "GPO created: $name (ID: $($gpo.Id))" "OK"
        Write-Host "  [OK] GPO '$name' created. ID: $($gpo.Id)" -ForegroundColor Green

        if ($linkOU) {
            $order = Read-Host "  Link order (default 1)"
            if (-not $order) { $order = 1 }
            New-GPLink -Name $name -Target $linkOU -LinkEnabled Yes -Order $order -ErrorAction Stop
            Write-Log "GPO '$name' linked to: $linkOU" "OK"
            Write-Host "  [OK] GPO linked to: $linkOU" -ForegroundColor Green
        }
    } catch {
        Write-Log "Failed to create GPO '$name': $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Link GPO to OU ───────────────────────────────────────────────────────────
function Set-GPOLinkMenu {
    Write-Host "`n--- LINK / UNLINK GPO ---" -ForegroundColor Yellow
    $action = Read-Host "  [1] Link  [2] Unlink"
    $name   = Read-Host "  GPO Name"
    $ou     = Read-Host "  Target OU DN"

    try {
        if ($action -eq '1') {
            $enabled = Read-Host "  Enable link? (Y/N) [Y]"
            $state   = if ($enabled -eq 'N') { "No" } else { "Yes" }
            New-GPLink -Name $name -Target $ou -LinkEnabled $state -ErrorAction Stop
            Write-Log "GPO '$name' linked to: $ou (Enabled: $state)" "OK"
            Write-Host "  [OK] GPO linked." -ForegroundColor Green
        } else {
            $confirm = Read-Host "  Unlink '$name' from '$ou'? (Y/N)"
            if ($confirm -ne 'Y') { return }
            Remove-GPLink -Name $name -Target $ou -ErrorAction Stop
            Write-Log "GPO '$name' unlinked from: $ou" "OK"
            Write-Host "  [OK] GPO unlinked." -ForegroundColor Green
        }
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Enable / Disable GPO ─────────────────────────────────────────────────────
function Set-GPOStatus {
    Write-Host "`n--- ENABLE / DISABLE GPO ---" -ForegroundColor Yellow
    $name   = Read-Host "  GPO Name"
    $status = Read-Host "  Status: [1] All Enabled  [2] All Disabled  [3] User Only  [4] Computer Only"
    $statusMap = @{ '1'="AllSettingsEnabled"; '2'="AllSettingsDisabled"; '3'="UserSettingsDisabled"; '4'="ComputerSettingsDisabled" }

    if (-not $statusMap.ContainsKey($status)) { Write-Host "  Invalid." -ForegroundColor Red; return }

    try {
        $gpo = Get-GPO -Name $name -ErrorAction Stop
        $gpo.GpoStatus = $statusMap[$status]
        Write-Log "GPO '$name' status set to: $($statusMap[$status])" "OK"
        Write-Host "  [OK] GPO status updated." -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Backup GPOs ──────────────────────────────────────────────────────────────
function Backup-GPOs {
    Write-Host "`n--- BACKUP GPOs ---" -ForegroundColor Yellow
    $backupFolder = Join-Path $OutputPath "GPO_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null

    $single = Read-Host "  Backup [A]ll GPOs or [S]pecific GPO?"
    try {
        if ($single.ToUpper() -eq 'S') {
            $name = Read-Host "  GPO Name"
            $bak  = Backup-GPO -Name $name -Path $backupFolder -ErrorAction Stop
            Write-Log "GPO backed up: $name to $backupFolder" "OK"
            Write-Host "  [OK] GPO '$name' backed up. ID: $($bak.Id)" -ForegroundColor Green
        } else {
            $baks = Backup-GPO -All -Path $backupFolder -ErrorAction Stop
            Write-Log "All GPOs backed up to: $backupFolder ($($baks.Count) GPOs)" "OK"
            Write-Host "  [OK] $($baks.Count) GPO(s) backed up to: $backupFolder" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Restore GPO ─────────────────────────────────────────────────────────────
function Restore-GPOMenu {
    Write-Host "`n--- RESTORE GPO FROM BACKUP ---" -ForegroundColor Yellow
    $backupPath = Read-Host "  Backup folder path"
    $name       = Read-Host "  GPO Name to restore"

    if (-not (Test-Path $backupPath)) { Write-Host "  Backup path not found." -ForegroundColor Red; return }

    try {
        $confirm = Read-Host "  Restore '$name' from backup? This overwrites current settings. (Y/N)"
        if ($confirm -ne 'Y') { return }
        Restore-GPO -Name $name -Path $backupPath -ErrorAction Stop
        Write-Log "GPO restored: $name from $backupPath" "OK"
        Write-Host "  [OK] GPO '$name' restored." -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Generate HTML Report ─────────────────────────────────────────────────────
function Get-GPOReport {
    Write-Host "`n--- GENERATE GPO HTML REPORT ---" -ForegroundColor Yellow
    $name = Read-Host "  GPO Name (leave blank for all GPOs)"
    $reportFile = Join-Path $OutputPath "GPO_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

    try {
        if ($name) {
            Get-GPOReport -Name $name -ReportType HTML -Path $reportFile -ErrorAction Stop
        } else {
            Get-GPOReport -All -ReportType HTML -Path $reportFile -ErrorAction Stop
        }
        Write-Log "GPO report generated: $reportFile" "OK"
        Write-Host "  [OK] Report saved to: $reportFile" -ForegroundColor Green
        Start-Process $reportFile  # Open in browser
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Find Unlinked GPOs ───────────────────────────────────────────────────────
function Find-UnlinkedGPOs {
    Write-Host "`n--- UNLINKED GPOs ---" -ForegroundColor Yellow
    try {
        $allGPOs    = Get-GPO -All
        $linkedGUIDs = (Get-GPInheritance -Target (Get-ADDomain).DistinguishedName -ErrorAction SilentlyContinue).GpoLinks.GpoId
        $unlinked   = $allGPOs | Where-Object { $_.Id -notin $linkedGUIDs }

        Write-Host "`n  Found $($unlinked.Count) unlinked GPO(s):" -ForegroundColor $(if($unlinked.Count){"Yellow"}else{"Green"})
        $unlinked | ForEach-Object { Write-Host "    - $($_.DisplayName)  Status: $($_.GpoStatus)" -ForegroundColor Yellow }

        if ($unlinked.Count -gt 0) {
            Write-Host "`n  Note: Unlinked GPOs have no effect but consume storage." -ForegroundColor Gray
        }
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   GPO MANAGEMENT"                                              -ForegroundColor Yellow
    Write-Host "   Domain: $((Get-ADDomain).DNSRoot)"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] List all GPOs"              -ForegroundColor White
    Write-Host "  [2] Create new GPO"             -ForegroundColor White
    Write-Host "  [3] Link / Unlink GPO to OU"    -ForegroundColor White
    Write-Host "  [4] Enable / Disable GPO"       -ForegroundColor White
    Write-Host "  [5] Backup GPO(s)"              -ForegroundColor White
    Write-Host "  [6] Restore GPO from backup"    -ForegroundColor White
    Write-Host "  [7] Generate HTML report"       -ForegroundColor White
    Write-Host "  [8] Find unlinked GPOs"         -ForegroundColor White
    Write-Host "  [Q] Quit"                       -ForegroundColor Gray
    Write-Host ""
}

Write-Log "GPO Management started"
try {
    do {
        Show-Menu
        $choice = Read-Host "Select option"
        switch ($choice.ToUpper()) {
            '1' { Show-AllGPOs;       Read-Host "`nPress Enter" }
            '2' { New-GPOMenu;        Read-Host "`nPress Enter" }
            '3' { Set-GPOLinkMenu;    Read-Host "`nPress Enter" }
            '4' { Set-GPOStatus;      Read-Host "`nPress Enter" }
            '5' { Backup-GPOs;        Read-Host "`nPress Enter" }
            '6' { Restore-GPOMenu;    Read-Host "`nPress Enter" }
            '7' { Get-GPOReport;      Read-Host "`nPress Enter" }
            '8' { Find-UnlinkedGPOs;  Read-Host "`nPress Enter" }
            'Q' { break }
            default { Write-Host "  Invalid." -ForegroundColor Yellow; Start-Sleep 1 }
        }
    } while ($choice.ToUpper() -ne 'Q')
} catch {
    Write-Host "`n[FATAL] $($_.Exception.Message)" -ForegroundColor Red; exit 1
}
