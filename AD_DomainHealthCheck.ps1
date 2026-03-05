#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Domain Health Check - Comprehensive AD domain health and diagnostics report.

.DESCRIPTION
    Runs a full health check on the Active Directory environment:
      - Domain Controller reachability and roles
      - AD replication status
      - SYSVOL and NETLOGON share availability
      - DNS health
      - FSMO role holders
      - Domain and forest functional levels
      - Time synchronization

.PARAMETER OutputPath    Directory for the report. Defaults to Desktop.

.EXAMPLE
    .\14_AD_DomainHealthCheck.ps1

.NOTES
    Prerequisites : ActiveDirectory module; Domain Admin rights recommended.
    Author        : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param([string]$OutputPath = "$env:USERPROFILE\Desktop")

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "AD_HealthCheck_$timestamp.txt"
$lines      = [System.Collections.Generic.List[string]]::new()
$alerts     = [System.Collections.Generic.List[string]]::new()

function Write-Section { param([string]$T)
    Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
    Write-Host "  $T" -ForegroundColor Yellow
    Write-Host "$("=" * 60)" -ForegroundColor Cyan
}
function Add-Line  { param([string]$T = ""); $lines.Add($T); Write-Host $T }
function Add-OK    { param([string]$T); Write-Host "  [OK]   $T" -ForegroundColor Green;  $lines.Add("  [OK]   $T") }
function Add-Fail  { param([string]$T); Write-Host "  [FAIL] $T" -ForegroundColor Red;    $lines.Add("  [FAIL] $T"); $alerts.Add($T) }
function Add-Warn  { param([string]$T); Write-Host "  [WARN] $T" -ForegroundColor Yellow; $lines.Add("  [WARN] $T"); $alerts.Add("WARN: $T") }

Write-Host "`nAD Domain Health Check" -ForegroundColor Green
Write-Host "Running diagnostics - please wait..." -ForegroundColor Gray

Add-Line "================================================================="
Add-Line "  ACTIVE DIRECTORY DOMAIN HEALTH CHECK REPORT"
Add-Line "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-Line "  Run By    : $env:USERNAME on $env:COMPUTERNAME"
Add-Line "================================================================="

# 1. Domain/Forest Overview
Write-Section "DOMAIN & FOREST INFORMATION"
try {
    $domain = Get-ADDomain
    $forest = Get-ADForest
    Add-Line "  Domain Name         : $($domain.DNSRoot)"
    Add-Line "  Domain DN           : $($domain.DistinguishedName)"
    Add-Line "  Domain Func Level   : $($domain.DomainMode)"
    Add-Line "  Forest Name         : $($forest.Name)"
    Add-Line "  Forest Func Level   : $($forest.ForestMode)"
    Add-Line "  Domain Controllers  : $($domain.ReplicaDirectoryServers.Count)"
    Add-Line "  Sites               : $($forest.Sites.Count)"
    if ($domain.DomainMode -lt "Windows2016Domain") { Add-Warn "Domain functional level is below Windows 2016" }
} catch { Add-Fail "Could not retrieve domain info: $($_.Exception.Message)" }

# 2. FSMO Roles
Write-Section "FSMO ROLE HOLDERS"
try {
    $domain = Get-ADDomain; $forest = Get-ADForest
    Add-Line "  PDC Emulator         : $($domain.PDCEmulator)"
    Add-Line "  RID Master           : $($domain.RIDMaster)"
    Add-Line "  Infra Master         : $($domain.InfrastructureMaster)"
    Add-Line "  Schema Master        : $($forest.SchemaMaster)"
    Add-Line "  Domain Naming Master : $($forest.DomainNamingMaster)"
    Add-OK "FSMO roles retrieved successfully"
} catch { Add-Fail "Could not retrieve FSMO roles: $($_.Exception.Message)" }

# 3. Domain Controller Health
Write-Section "DOMAIN CONTROLLER HEALTH"
try {
    $dcs = Get-ADDomainController -Filter *
    Add-Line "  Found $($dcs.Count) Domain Controller(s):`n"
    foreach ($dc in $dcs) {
        Add-Line "  DC: $($dc.Name)  Site: $($dc.Site)  OS: $($dc.OperatingSystem)"

        # Ping
        $ping = Test-Connection -ComputerName $dc.HostName -Count 1 -ErrorAction SilentlyContinue
        if ($ping) { Add-OK "$($dc.Name): Reachable ($(${ping}[0].ResponseTime)ms)" }
        else        { Add-Fail "$($dc.Name): NOT REACHABLE" }

        # SYSVOL share
        $sysvolPath = "\\$($dc.HostName)\SYSVOL"
        if (Test-Path $sysvolPath -ErrorAction SilentlyContinue) { Add-OK "$($dc.Name): SYSVOL share accessible" }
        else { Add-Fail "$($dc.Name): SYSVOL share NOT accessible" }

        # NETLOGON share
        $netlogonPath = "\\$($dc.HostName)\NETLOGON"
        if (Test-Path $netlogonPath -ErrorAction SilentlyContinue) { Add-OK "$($dc.Name): NETLOGON share accessible" }
        else { Add-Fail "$($dc.Name): NETLOGON share NOT accessible" }

        Add-Line ""
    }
} catch { Add-Fail "Could not enumerate DCs: $($_.Exception.Message)" }

# 4. AD Replication
Write-Section "AD REPLICATION STATUS"
try {
    $replStatus = Get-ADReplicationPartnerMetadata -Target * -Scope Domain -ErrorAction Stop
    $failures   = $replStatus | Where-Object { $_.LastReplicationResult -ne 0 }

    if ($failures) {
        Add-Fail "$($failures.Count) replication failure(s) detected:"
        foreach ($f in $failures) {
            Add-Line "    $($f.Server) -> $($f.Partner): Error $($f.LastReplicationResult)"
        }
    } else {
        Add-OK "All replication partnerships are healthy"
        $oldest = ($replStatus | Sort-Object LastReplicationSuccess | Select-Object -First 1).LastReplicationSuccess
        Add-Line "  Oldest successful replication: $($oldest.ToString('yyyy-MM-dd HH:mm'))"
        if ($oldest -lt (Get-Date).AddHours(-6)) { Add-Warn "Replication older than 6 hours detected" }
    }
} catch { Add-Warn "Could not check replication: $($_.Exception.Message)" }

# 5. DNS Health
Write-Section "DNS HEALTH CHECK"
try {
    $domain    = (Get-ADDomain).DNSRoot
    $dnsResult = Resolve-DnsName $domain -ErrorAction Stop
    Add-OK "DNS resolution for '$domain': $($dnsResult[0].IPAddress)"

    # SRV records
    $srv = Resolve-DnsName "_ldap._tcp.$domain" -Type SRV -ErrorAction SilentlyContinue
    if ($srv) { Add-OK "LDAP SRV records found ($($srv.Count) entries)" }
    else       { Add-Fail "LDAP SRV records missing for $domain" }

    $kerbSrv = Resolve-DnsName "_kerberos._tcp.$domain" -Type SRV -ErrorAction SilentlyContinue
    if ($kerbSrv) { Add-OK "Kerberos SRV records found ($($kerbSrv.Count) entries)" }
    else          { Add-Fail "Kerberos SRV records missing" }
} catch { Add-Fail "DNS check failed: $($_.Exception.Message)" }

# 6. Time Sync
Write-Section "TIME SYNCHRONIZATION"
try {
    $w32tm = & w32tm /query /status 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
        Add-OK "Windows Time service is running"
        $source = ($w32tm -split "`n" | Where-Object { $_ -match "Source" } | Select-Object -First 1).Trim()
        Add-Line "  $source"
    } else { Add-Warn "Windows Time service issue detected" }
} catch { Add-Warn "Could not check time sync" }

# 7. AD Summary Stats
Write-Section "DOMAIN STATISTICS"
try {
    $userCount     = (Get-ADUser -Filter *).Count
    $enabledUsers  = (Get-ADUser -Filter { Enabled -eq $true }).Count
    $computerCount = (Get-ADComputer -Filter *).Count
    $groupCount    = (Get-ADGroup -Filter *).Count
    $ouCount       = (Get-ADOrganizationalUnit -Filter *).Count

    Add-Line "  Total Users       : $userCount  (Enabled: $enabledUsers)"
    Add-Line "  Total Computers   : $computerCount"
    Add-Line "  Total Groups      : $groupCount"
    Add-Line "  Total OUs         : $ouCount"
} catch { Add-Line "  [ERROR] $($_.Exception.Message)" }

# 8. Summary
Write-Section "HEALTH CHECK SUMMARY"
Add-Line ""
if ($alerts.Count -eq 0) {
    Write-Host "  [HEALTHY] All checks passed. Domain appears healthy." -ForegroundColor Green
    Add-Line "  Status: HEALTHY"
} else {
    $fails = $alerts | Where-Object { $_ -notlike "WARN:*" }
    $warns = $alerts | Where-Object { $_ -like "WARN:*" }
    Write-Host "  $($fails.Count) failure(s)  |  $($warns.Count) warning(s)" -ForegroundColor Red
    Add-Line "  Status: $($fails.Count) failure(s), $($warns.Count) warning(s)"
    foreach ($a in $alerts) { Add-Line "    - $a" }
}

$lines | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "`n[OK] Report saved: $reportFile" -ForegroundColor Green
