#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD Computer Management - Manage and audit computer accounts in AD.

.DESCRIPTION
    Manage domain computer objects with the ability to:
      - Search and view computer details
      - Add new computer accounts
      - Disable or delete stale computer accounts
      - Move computers between OUs
      - Remote management (ping, RDP, remote PS)
      - Export computer inventory

.PARAMETER OutputPath
    Directory for logs/reports. Defaults to Desktop.

.EXAMPLE
    .\08_AD_ComputerManagement.ps1

.NOTES
    Prerequisites : ActiveDirectory module; Domain Admin rights for management tasks.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "AD_Computers_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR"{"Red"} "WARN"{"Yellow"} "OK"{"Green"} default{"Gray"} }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── Search Computer ──────────────────────────────────────────────────────────
function Find-Computer {
    Write-Host "`n--- FIND COMPUTER ---" -ForegroundColor Yellow
    $query = Read-Host "  Enter computer name (partial match OK, * for all)"
    try {
        $computers = Get-ADComputer -Filter "Name -like '$query'" `
            -Properties LastLogonDate, OperatingSystem, OperatingSystemVersion, `
                        IPv4Address, Description, Enabled, WhenCreated |
            Sort-Object Name

        if (-not $computers) { Write-Host "  No computers found matching '$query'." -ForegroundColor Yellow; return }

        Write-Host "`n  Found $($computers.Count) computer(s):" -ForegroundColor Cyan
        Write-Host ("  {0,-25} {1,-10} {2,-15} {3,-20} {4}" -f "Name", "Enabled", "Last Logon", "OS", "IP")
        Write-Host ("  {0,-25} {1,-10} {2,-15} {3,-20} {4}" -f "----", "-------", "----------", "--", "--")

        foreach ($c in $computers) {
            $ll    = if ($c.LastLogonDate) { $c.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
            $color = if ($c.Enabled) { "White" } else { "DarkGray" }
            Write-Host ("  {0,-25} {1,-10} {2,-15} {3,-20} {4}" -f `
                $c.Name, $c.Enabled, $ll, $c.OperatingSystem, $c.IPv4Address) -ForegroundColor $color
        }

        # Show full detail for single result
        if ($computers.Count -eq 1) {
            $c = $computers[0]
            Write-Host "`n  Full Details:" -ForegroundColor Cyan
            Write-Host "    Name       : $($c.Name)"
            Write-Host "    OS         : $($c.OperatingSystem) $($c.OperatingSystemVersion)"
            Write-Host "    IP Address : $($c.IPv4Address)"
            Write-Host "    Created    : $($c.WhenCreated)"
            Write-Host "    Last Logon : $($c.LastLogonDate)"
            Write-Host "    Description: $($c.Description)"
            Write-Host "    OU         : $($c.DistinguishedName -replace "^CN=[^,]+,","")"
        }
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Computer Inventory ───────────────────────────────────────────────────────
function Export-ComputerInventory {
    Write-Host "`n--- EXPORT COMPUTER INVENTORY ---" -ForegroundColor Yellow
    Write-Host "  Collecting all computer accounts..." -ForegroundColor Gray
    try {
        $computers = Get-ADComputer -Filter * `
            -Properties LastLogonDate, OperatingSystem, OperatingSystemVersion, `
                        IPv4Address, Description, Enabled, WhenCreated, `
                        PasswordLastSet, DistinguishedName | Sort-Object Name

        $report = $computers | ForEach-Object {
            [PSCustomObject]@{
                Name              = $_.Name
                Enabled           = $_.Enabled
                OperatingSystem   = $_.OperatingSystem
                OSVersion         = $_.OperatingSystemVersion
                IPAddress         = $_.IPv4Address
                LastLogon         = $_.LastLogonDate
                PasswordLastSet   = $_.PasswordLastSet
                WhenCreated       = $_.WhenCreated
                Description       = $_.Description
                OU                = ($_.DistinguishedName -replace "^CN=[^,]+,","")
            }
        }

        $csv = Join-Path $OutputPath "ComputerInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $report | Export-Csv -Path $csv -NoTypeInformation
        Write-Host "  Exported $($computers.Count) computers to: $csv" -ForegroundColor Green
        Write-Log "Computer inventory exported: $($computers.Count) records to $csv"

        # OS summary
        Write-Host "`n  Operating System Summary:" -ForegroundColor Cyan
        $report | Group-Object OperatingSystem | Sort-Object Count -Descending | ForEach-Object {
            Write-Host ("  {0,-45} {1}" -f ($_.Name ? $_.Name : "Unknown"), $_.Count)
        }
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Disable Stale Computers ──────────────────────────────────────────────────
function Disable-StaleComputers {
    Write-Host "`n--- DISABLE STALE COMPUTER ACCOUNTS ---" -ForegroundColor Yellow
    $days = Read-Host "  Inactive for how many days? [90]"
    if (-not $days) { $days = 90 }
    $cutoff = (Get-Date).AddDays(-[int]$days)

    try {
        $stale = Get-ADComputer -Filter { Enabled -eq $true -and LastLogonDate -lt $cutoff } `
            -Properties LastLogonDate | Sort-Object LastLogonDate

        if (-not $stale) { Write-Host "  No stale computers found." -ForegroundColor Green; return }

        Write-Host "`n  Found $($stale.Count) stale computer(s):" -ForegroundColor Yellow
        $stale | ForEach-Object {
            $ll = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
            Write-Host "    $($_.Name)  Last Logon: $ll"
        }

        $confirm = Read-Host "`n  Disable all $($stale.Count) stale computers? (Y/N)"
        if ($confirm -ne 'Y') { return }

        $ok = 0
        foreach ($c in $stale) {
            try {
                Disable-ADAccount -Identity $c.SamAccountName -ErrorAction Stop
                $desc = "DISABLED: $(Get-Date -Format 'yyyy-MM-dd') - Inactive >$days days"
                Set-ADComputer -Identity $c.Name -Description $desc -ErrorAction SilentlyContinue
                Write-Log "Disabled stale computer: $($c.Name)" "OK"
                $ok++
            } catch {
                Write-Log "Could not disable $($c.Name): $($_.Exception.Message)" "WARN"
            }
        }
        Write-Host "  [OK] $ok computer(s) disabled." -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Remote Ping / Test ───────────────────────────────────────────────────────
function Test-ComputerConnectivity {
    Write-Host "`n--- TEST COMPUTER CONNECTIVITY ---" -ForegroundColor Yellow
    $name = Read-Host "  Computer name or IP"
    Write-Host ""

    # Ping
    $ping = Test-Connection -ComputerName $name -Count 2 -ErrorAction SilentlyContinue
    if ($ping) {
        $avg = [math]::Round(($ping | Measure-Object ResponseTime -Average).Average)
        Write-Host "  [OK] PING: Reachable  avg: ${avg}ms" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] PING: Not reachable" -ForegroundColor Red
    }

    # WMI / CIM
    try {
        $os = Get-CimInstance -ComputerName $name -ClassName Win32_OperatingSystem -OperationTimeoutSec 10 -ErrorAction Stop
        Write-Host "  [OK] WMI: Connected  OS: $($os.Caption)" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] WMI: $($_.Exception.Message)" -ForegroundColor Red
    }

    # RDP port
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $conn = $tcp.BeginConnect($name, 3389, $null, $null)
        $wait = $conn.AsyncWaitHandle.WaitOne(2000, $false)
        if ($wait) { Write-Host "  [OK] RDP (Port 3389): Open" -ForegroundColor Green }
        else        { Write-Host "  [FAIL] RDP (Port 3389): Closed/Filtered" -ForegroundColor Yellow }
        $tcp.Close()
    } catch {
        Write-Host "  [FAIL] RDP test error: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Log "Connectivity test for: $name"
}

# ─── Move Computer ────────────────────────────────────────────────────────────
function Move-Computer {
    Write-Host "`n--- MOVE COMPUTER TO ANOTHER OU ---" -ForegroundColor Yellow
    $name   = Read-Host "  Computer name"
    $target = Read-Host "  Target OU DN"
    try {
        $comp = Get-ADComputer -Identity $name -ErrorAction Stop
        $confirm = Read-Host "  Move '$name' to '$target'? (Y/N)"
        if ($confirm -ne 'Y') { return }
        Move-ADObject -Identity $comp.DistinguishedName -TargetPath $target -ErrorAction Stop
        Write-Log "Moved computer '$name' to: $target" "OK"
        Write-Host "  [OK] Computer moved." -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   AD COMPUTER MANAGEMENT"                                      -ForegroundColor Yellow
    Write-Host "   Domain: $((Get-ADDomain).DNSRoot)"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Find / view a computer"            -ForegroundColor White
    Write-Host "  [2] Export full computer inventory"    -ForegroundColor White
    Write-Host "  [3] Disable stale computer accounts"   -ForegroundColor White
    Write-Host "  [4] Test computer connectivity"        -ForegroundColor White
    Write-Host "  [5] Move computer to another OU"       -ForegroundColor White
    Write-Host "  [Q] Quit"                              -ForegroundColor Gray
    Write-Host ""
}

Write-Log "AD Computer Management started"
try {
    do {
        Show-Menu
        $choice = Read-Host "Select option"
        switch ($choice.ToUpper()) {
            '1' { Find-Computer;               Read-Host "`nPress Enter" }
            '2' { Export-ComputerInventory;    Read-Host "`nPress Enter" }
            '3' { Disable-StaleComputers;      Read-Host "`nPress Enter" }
            '4' { Test-ComputerConnectivity;   Read-Host "`nPress Enter" }
            '5' { Move-Computer;               Read-Host "`nPress Enter" }
            'Q' { break }
            default { Write-Host "  Invalid." -ForegroundColor Yellow; Start-Sleep 1 }
        }
    } while ($choice.ToUpper() -ne 'Q')
} catch {
    Write-Host "`n[FATAL] $($_.Exception.Message)" -ForegroundColor Red; exit 1
}
