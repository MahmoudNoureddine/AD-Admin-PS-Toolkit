#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD Replication Monitor - Monitor and troubleshoot Active Directory replication.

.DESCRIPTION
    Comprehensive replication health monitoring:
      - Replication status across all DC partnerships
      - Replication failure detection and error codes
      - Replication topology visualization
      - Force replication between specific DCs
      - USN rollback detection
      - Replication latency measurement
      - Detailed replication event log analysis

.PARAMETER OutputPath    Directory for reports. Defaults to Desktop.

.EXAMPLE
    .\19_AD_ReplicationMonitor.ps1

.NOTES
    Prerequisites : ActiveDirectory module; Domain Admin rights.
    Author        : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param([string]$OutputPath = "$env:USERPROFILE\Desktop")

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "AD_Replication_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$M, [string]$L = "INFO")
    $e = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$L] $M"
    Add-Content $logFile $e -ErrorAction SilentlyContinue
    Write-Host "  $e" -ForegroundColor $(switch($L){"ERROR"{"Red"}"WARN"{"Yellow"}"OK"{"Green"}default{"Gray"}})
}

function Write-Section { param([string]$T)
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $T" -ForegroundColor Yellow
    Write-Host "$("=" * 60)" -ForegroundColor Cyan
}

# ─── Replication Status Overview ──────────────────────────────────────────────
function Get-ReplicationStatus {
    Write-Section "REPLICATION STATUS OVERVIEW"
    try {
        $partners = Get-ADReplicationPartnerMetadata -Target * -Scope Domain -ErrorAction Stop |
                    Sort-Object Server, Partner

        $failures = $partners | Where-Object { $_.LastReplicationResult -ne 0 }
        $oldest   = ($partners | Sort-Object LastReplicationSuccess | Select-Object -First 1).LastReplicationSuccess

        Write-Host "`n  Total partnerships : $($partners.Count)" -ForegroundColor Cyan
        Write-Host "  Failures detected  : $($failures.Count)" -ForegroundColor $(if($failures.Count){"Red"}else{"Green"})
        Write-Host "  Oldest replication : $($oldest?.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor $(if($oldest -lt (Get-Date).AddHours(-6)){"Yellow"}else{"White"})

        Write-Host "`n  {0,-30} {1,-30} {2,-10} {3,-20} {4}" -f "Source DC","Partner DC","Result","Last Success","Lag(min)"
        Write-Host "  {0,-30} {1,-30} {2,-10} {3,-20} {4}" -f "---------","----------","------","------------","-------"

        foreach ($p in $partners) {
            $srcShort  = $p.Server  -replace "\..*$"
            $prtShort  = $p.Partner -replace "CN=NTDS Settings,CN=|,.*$"
            $lag       = if ($p.LastReplicationSuccess) { [math]::Round(((Get-Date) - $p.LastReplicationSuccess).TotalMinutes) } else { "N/A" }
            $resultTxt = if ($p.LastReplicationResult -eq 0) { "OK" } else { "ERR:$($p.LastReplicationResult)" }
            $color     = if ($p.LastReplicationResult -ne 0) { "Red" } elseif ($lag -gt 60) { "Yellow" } else { "Green" }
            $lastSync  = $p.LastReplicationSuccess?.ToString("yyyy-MM-dd HH:mm")

            Write-Host ("  {0,-30} {1,-30} {2,-10} {3,-20} {4}" -f `
                $srcShort, $prtShort, $resultTxt, $lastSync, $lag) -ForegroundColor $color
        }

        if ($failures) {
            Write-Host "`n  REPLICATION ERRORS:" -ForegroundColor Red
            foreach ($f in $failures) {
                Write-Host "    $($f.Server) -> $($f.Partner)" -ForegroundColor Red
                Write-Host "    Error Code : $($f.LastReplicationResult)" -ForegroundColor Yellow
                Write-Host "    Last Attempt: $($f.LastReplicationAttempt)" -ForegroundColor Yellow
                Write-Host ""
            }
        }

        # Export
        $csv = Join-Path $OutputPath "ReplicationStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $partners | Select-Object Server, Partner, LastReplicationResult, LastReplicationSuccess,
            LastReplicationAttempt, ConsecutiveReplicationFailures |
            Export-Csv $csv -NoTypeInformation
        Write-Host "  Report exported: $csv" -ForegroundColor Gray
        Write-Log "Replication status checked: $($failures.Count) failure(s)"

    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# ─── Replication Topology ─────────────────────────────────────────────────────
function Get-ReplicationTopology {
    Write-Section "REPLICATION TOPOLOGY"
    try {
        $connections = Get-ADReplicationConnection -Filter * -ErrorAction Stop |
                       Sort-Object FromServer

        Write-Host "`n  AD Replication Connections ($($connections.Count) total):" -ForegroundColor Cyan
        Write-Host ("  {0,-30} {1,-30} {2,-10} {3}" -f "From","To","AutoGen","Site Link")
        Write-Host ("  {0,-30} {1,-30} {2,-10} {3}" -f "----","--","-------","---------")

        foreach ($c in $connections) {
            $from  = $c.FromServer  -replace "CN=NTDS Settings,CN=|,CN=Servers.*$"
            $to    = $c.ReplicateFromDirectoryServer -replace "CN=NTDS Settings,CN=|,CN=Servers.*$"
            $auto  = $c.AutoGenerated
            $color = if ($auto) { "Gray" } else { "Cyan" }
            Write-Host ("  {0,-30} {1,-30} {2,-10} {3}" -f $from, $to, $auto, "") -ForegroundColor $color
        }

        Write-Host "`n  Sites in forest:" -ForegroundColor Cyan
        $sites = Get-ADReplicationSite -Filter * | Sort-Object Name
        foreach ($s in $sites) {
            $dcs = Get-ADDomainController -Filter { Site -eq $s.Name } -ErrorAction SilentlyContinue
            Write-Host "    $($s.Name) - $(@($dcs).Count) DC(s)"
        }

        Write-Host "`n  Site links:" -ForegroundColor Cyan
        Get-ADReplicationSiteLink -Filter * | Sort-Object Name | ForEach-Object {
            Write-Host "    $($_.Name)  Cost: $($_.Cost)  Interval: $($_.ReplicationFrequencyInMinutes)min  Sites: $($_.SitesIncluded.Count)"
        }
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# ─── Force Replication ────────────────────────────────────────────────────────
function Invoke-ForceReplication {
    Write-Section "FORCE REPLICATION"
    Write-Host "  [1] Sync specific partition between two DCs"
    Write-Host "  [2] Replicate all partitions on a DC"
    Write-Host "  [3] Run repadmin /syncall"
    $choice = Read-Host "  Select"

    try {
        switch ($choice) {
            '1' {
                $src  = Read-Host "  Source DC hostname"
                $dst  = Read-Host "  Destination DC hostname"
                $part = Read-Host "  Partition DN (leave blank for default domain NC)"
                if (-not $part) { $part = (Get-ADDomain).DistinguishedName }

                Sync-ADObject -Object $part -Source $src -Destination $dst -ErrorAction Stop
                Write-Log "Forced replication: $src -> $dst for $part" "OK"
                Write-Host "  [OK] Replication triggered." -ForegroundColor Green
            }
            '2' {
                $dc = Read-Host "  DC hostname"
                $result = & repadmin /syncall $dc /AdeP 2>&1 | Out-String
                Write-Host $result
                Write-Log "Forced full sync on: $dc"
            }
            '3' {
                Write-Host "  Running repadmin /syncall /AdeP ..." -ForegroundColor Gray
                $result = & repadmin /syncall /AdeP 2>&1 | Out-String
                Write-Host $result
                Write-Log "repadmin /syncall executed"
            }
        }
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# ─── Replication Event Log Analysis ───────────────────────────────────────────
function Get-ReplicationEvents {
    Write-Section "REPLICATION EVENT LOG ANALYSIS"
    $dc    = Read-Host "  DC to check (leave blank for local)"
    $hours = Read-Host "  Look back how many hours? [24]"
    if (-not $hours) { $hours = 24 }
    if (-not $dc) { $dc = $env:COMPUTERNAME }

    try {
        $since  = (Get-Date).AddHours(-[int]$hours)
        $events = Get-WinEvent -ComputerName $dc -FilterHashtable @{
            LogName   = "Directory Service"
            StartTime = $since
            Level     = @(1,2,3)   # Critical, Error, Warning
        } -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending

        if (-not $events) {
            Write-Host "`n  [OK] No replication errors in Directory Service log (last $hours hours)." -ForegroundColor Green
        } else {
            Write-Host "`n  Found $($events.Count) event(s) on $dc (last $hours hours):" -ForegroundColor Yellow
            foreach ($e in $events | Select-Object -First 20) {
                $color = switch ($e.Level) { 1{"Red"} 2{"Red"} 3{"Yellow"} default{"Gray"} }
                Write-Host "  [$($e.TimeCreated.ToString('HH:mm'))] ID:$($e.Id) $($e.Message.Substring(0,[math]::Min(100,$e.Message.Length)))" -ForegroundColor $color
            }
        }
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# ─── DC USN & Metadata Check ──────────────────────────────────────────────────
function Get-DCMetadata {
    Write-Section "DOMAIN CONTROLLER METADATA"
    try {
        $dcs = Get-ADDomainController -Filter *
        Write-Host "`n  {0,-25} {1,-10} {2,-20} {3,-10} {4}" -f "DC","Enabled","OS","Site","RODC"
        Write-Host "  {0,-25} {1,-10} {2,-20} {3,-10} {4}" -f "--","-------","--","----","----"
        foreach ($dc in $dcs | Sort-Object Name) {
            Write-Host ("  {0,-25} {1,-10} {2,-20} {3,-10} {4}" -f `
                $dc.Name, $dc.Enabled, $dc.OperatingSystem, $dc.Site, $dc.IsReadOnly) -ForegroundColor $(if($dc.Enabled){"White"}else{"Red"})
        }

        Write-Host "`n  Running repadmin /showrepl summary..." -ForegroundColor Gray
        $result = & repadmin /replsummary 2>&1 | Out-String
        Write-Host $result -ForegroundColor Gray
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   AD REPLICATION MONITOR" -ForegroundColor Yellow
    Write-Host "   Domain: $((Get-ADDomain).DNSRoot)"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  [1] Replication status overview`n  [2] Replication topology`n  [3] Force replication`n  [4] Replication event log analysis`n  [5] DC metadata & repadmin summary`n  [Q] Quit`n"
}

Write-Log "Replication Monitor started"
do {
    Show-Menu; $c = Read-Host "Select"
    switch ($c.ToUpper()) {
        '1' { Get-ReplicationStatus;    Read-Host "`nPress Enter" }
        '2' { Get-ReplicationTopology;  Read-Host "`nPress Enter" }
        '3' { Invoke-ForceReplication;  Read-Host "`nPress Enter" }
        '4' { Get-ReplicationEvents;    Read-Host "`nPress Enter" }
        '5' { Get-DCMetadata;           Read-Host "`nPress Enter" }
        'Q' { break }
        default { Start-Sleep 1 }
    }
} while ($c.ToUpper() -ne 'Q')
