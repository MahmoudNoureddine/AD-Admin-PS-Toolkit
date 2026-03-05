#Requires -Version 5.1
#Requires -Modules GroupPolicy, ActiveDirectory
<#
.SYNOPSIS
    GPO Reporter - Generates detailed Group Policy reports and settings summaries.

.DESCRIPTION
    Advanced GPO reporting beyond basic listing:
      - GPO settings summary per policy
      - GPO link report (which OUs each GPO is linked to)
      - GPO inheritance report per OU
      - WMI filter inventory
      - GPO change history (modification dates)
      - Security filtering report (who GPOs apply to)
      - Export all to a consolidated HTML report

.PARAMETER OutputPath    Directory for reports. Defaults to Desktop.

.EXAMPLE
    .\17_AD_GroupPolicyReport.ps1
    .\17_AD_GroupPolicyReport.ps1 -OutputPath "C:\GPOReports"

.NOTES
    Prerequisites : GroupPolicy module, GPMC; Domain read access.
    Author        : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param([string]$OutputPath = "$env:USERPROFILE\Desktop")

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

function Write-Section { param([string]$T)
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $T" -ForegroundColor Yellow
    Write-Host "$("=" * 60)" -ForegroundColor Cyan
}

# 1. GPO Link Report
function Get-GPOLinkReport {
    Write-Section "GPO LINK REPORT"
    Write-Host "  Building GPO -> OU link map..." -ForegroundColor Gray
    try {
        $allGPOs = Get-GPO -All | Sort-Object DisplayName
        $report  = [System.Collections.Generic.List[object]]::new()

        foreach ($gpo in $allGPOs) {
            # Find all OUs this GPO is linked to via XML report
            $gpoReport = [xml](Get-GPOReport -Guid $gpo.Id -ReportType XML -ErrorAction SilentlyContinue)
            $links = $gpoReport.GPO.LinksTo.SOMPath
            $linkCount = if ($links) { @($links).Count } else { 0 }

            $report.Add([PSCustomObject]@{
                GPOName    = $gpo.DisplayName
                Status     = $gpo.GpoStatus
                Links      = $linkCount
                LinkedTo   = $links -join "; "
                Modified   = $gpo.ModificationTime
                UserVer    = $gpo.UserVersion
                CompVer    = $gpo.ComputerVersion
            })

            $color = if ($linkCount -eq 0) { "DarkGray" } else { "White" }
            Write-Host ("  {0,-45} Links: {1}" -f ($gpo.DisplayName.Substring(0,[math]::Min(44,$gpo.DisplayName.Length))), $linkCount) -ForegroundColor $color
        }

        $csv = Join-Path $OutputPath "GPO_LinkReport_$timestamp.csv"
        $report | Export-Csv $csv -NoTypeInformation
        Write-Host "`n  Exported to: $csv" -ForegroundColor Gray
        Write-Host "  Unlinked GPOs: $(($report | Where-Object { $_.Links -eq 0 }).Count)" -ForegroundColor Yellow
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# 2. GPO Inheritance per OU
function Get-OUInheritanceReport {
    Write-Section "GPO INHERITANCE REPORT (BY OU)"
    $ou = Read-Host "  Enter OU DN (leave blank for domain root)"
    $target = if ($ou) { $ou } else { (Get-ADDomain).DistinguishedName }
    try {
        $inheritance = Get-GPInheritance -Target $target -ErrorAction Stop
        Write-Host "`n  OU: $target" -ForegroundColor Cyan
        Write-Host "  Blocked Inheritance: $($inheritance.GpoInheritanceBlocked)" -ForegroundColor $(if($inheritance.GpoInheritanceBlocked){"Red"}else{"White"})
        Write-Host "`n  Applied GPOs (in order):" -ForegroundColor Cyan
        Write-Host ("  {0,-5} {1,-45} {2,-10} {3}" -f "Order","GPO Name","Enabled","Enforced")
        foreach ($link in $inheritance.GpoLinks | Sort-Object Order) {
            Write-Host ("  {0,-5} {1,-45} {2,-10} {3}" -f $link.Order, $link.DisplayName, $link.Enabled, $link.Enforced)
        }
        Write-Host "`n  Inherited GPOs: $($inheritance.InheritedGpoLinks.Count)"
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# 3. GPO Security Filtering
function Get-GPOSecurityFilter {
    Write-Section "GPO SECURITY FILTERING"
    $gpoName = Read-Host "  GPO Name"
    try {
        $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
        $acl = Get-GPPermissions -Guid $gpo.Id -All -ErrorAction Stop
        Write-Host "`n  Security filtering for: $gpoName" -ForegroundColor Cyan
        Write-Host ("  {0,-35} {1,-20} {2}" -f "Trustee","Permission","Denied")
        Write-Host ("  {0,-35} {1,-20} {2}" -f "-------","----------","------")
        foreach ($a in $acl | Sort-Object Trustee) {
            $color = if ($a.Permission -eq "GpoApply") { "Green" } elseif ($a.Denied) { "Red" } else { "White" }
            Write-Host ("  {0,-35} {1,-20} {2}" -f $a.Trustee.Name, $a.Permission, $a.Denied) -ForegroundColor $color
        }
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# 4. WMI Filter Inventory
function Get-WMIFilters {
    Write-Section "WMI FILTER INVENTORY"
    try {
        $wmiFilters = Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' `
            -Properties msWMI-Name, msWMI-Parm2, msWMI-ChangeDate |
            Sort-Object "msWMI-Name"
        Write-Host "`n  Found $($wmiFilters.Count) WMI filter(s):" -ForegroundColor Cyan
        foreach ($f in $wmiFilters) {
            Write-Host "  Name   : $($f.'msWMI-Name')" -ForegroundColor Yellow
            Write-Host "  Query  : $($f.'msWMI-Parm2')" -ForegroundColor Gray
            Write-Host ""
        }
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# 5. GPO Change History
function Get-GPOChangeHistory {
    Write-Section "GPO CHANGE HISTORY (Last 30 days)"
    try {
        $cutoff = (Get-Date).AddDays(-30)
        $recent = Get-GPO -All | Where-Object { $_.ModificationTime -gt $cutoff } | Sort-Object ModificationTime -Descending
        Write-Host "`n  $($recent.Count) GPO(s) modified in the last 30 days:" -ForegroundColor Cyan
        Write-Host ("  {0,-45} {1,-20} {2}" -f "GPO Name","Last Modified","Status")
        foreach ($g in $recent) {
            Write-Host ("  {0,-45} {1,-20} {2}" -f `
                ($g.DisplayName.Substring(0,[math]::Min(44,$g.DisplayName.Length))), `
                $g.ModificationTime.ToString("yyyy-MM-dd HH:mm"), $g.GpoStatus)
        }
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# 6. Full HTML Report
function New-ConsolidatedHTMLReport {
    Write-Section "GENERATING CONSOLIDATED HTML REPORT"
    $htmlFile = Join-Path $OutputPath "GPO_FullReport_$timestamp.html"
    Write-Host "  Generating HTML report for all GPOs..." -ForegroundColor Gray
    try {
        Get-GPOReport -All -ReportType HTML -Path $htmlFile -ErrorAction Stop
        Write-Host "  [OK] HTML report saved: $htmlFile" -ForegroundColor Green
        $open = Read-Host "  Open in browser? (Y/N)"
        if ($open -eq 'Y') { Start-Process $htmlFile }
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

# Menu
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   GPO REPORTER" -ForegroundColor Yellow
    Write-Host "   Domain: $((Get-ADDomain).DNSRoot)"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  [1] GPO link report`n  [2] GPO inheritance per OU`n  [3] GPO security filtering`n  [4] WMI filter inventory`n  [5] GPO change history`n  [6] Full HTML report (all GPOs)`n  [Q] Quit`n"
}

do {
    Show-Menu; $c = Read-Host "Select"
    switch ($c.ToUpper()) {
        '1' { Get-GPOLinkReport;           Read-Host "`nPress Enter" }
        '2' { Get-OUInheritanceReport;     Read-Host "`nPress Enter" }
        '3' { Get-GPOSecurityFilter;       Read-Host "`nPress Enter" }
        '4' { Get-WMIFilters;              Read-Host "`nPress Enter" }
        '5' { Get-GPOChangeHistory;        Read-Host "`nPress Enter" }
        '6' { New-ConsolidatedHTMLReport;  Read-Host "`nPress Enter" }
        'Q' { break }
        default { Start-Sleep 1 }
    }
} while ($c.ToUpper() -ne 'Q')
