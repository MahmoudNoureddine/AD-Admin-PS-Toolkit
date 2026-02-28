#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Bulk creates Active Directory users from a CSV file.

.DESCRIPTION
    Reads a CSV file and provisions multiple AD user accounts at once.
    Supports all standard user attributes, group assignments, and OU placement.
    Generates a results report showing success/failure per user.

    Expected CSV columns:
      FirstName, LastName, Department, Title, Manager, OU, Groups, Email

    Example CSV row:
      John,Doe,IT,SysAdmin,jsmith,"OU=IT,DC=domain,DC=com","IT-Staff;VPN-Users",john.doe@company.com

.PARAMETER CSVPath
    Path to the input CSV file. Required.

.PARAMETER OutputPath
    Directory for logs and results report. Defaults to Desktop.

.PARAMETER WhatIf
    Preview mode - shows what would be created without making changes.

.EXAMPLE
    .\03_AD_BulkCreateUsers.ps1 -CSVPath "C:\Users\new_users.csv"
    .\03_AD_BulkCreateUsers.ps1 -CSVPath "C:\Users\new_users.csv" -WhatIf

.NOTES
    Prerequisites : ActiveDirectory module, Domain Admin or Account Operator rights.
    A sample CSV template is created if the specified file is not found.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CSVPath,
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    [switch]$WhatIf
)

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile   = Join-Path $OutputPath "AD_BulkCreate_$timestamp.log"
$rptFile   = Join-Path $OutputPath "AD_BulkCreate_Results_$timestamp.csv"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } "OK" { "Green" } default { "Gray" } }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── Generate Sample CSV ──────────────────────────────────────────────────────
function New-SampleCSV {
    param([string]$Path)
    $sample = @"
FirstName,LastName,Department,Title,Manager,OU,Groups,Email
John,Doe,IT,Systems Administrator,jsmith,,IT-Staff;VPN-Users,john.doe@company.com
Jane,Smith,HR,HR Manager,,,HR-Staff,jane.smith@company.com
Bob,Johnson,Finance,Accountant,,,Finance-Staff,bob.johnson@company.com
"@
    $sample | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "  Sample CSV created at: $Path" -ForegroundColor Cyan
    Write-Host "  Edit it and re-run the script." -ForegroundColor Gray
}

# ─── Helper: Unique SAMAccountName ────────────────────────────────────────────
function Get-UniqueSAM {
    param([string]$First, [string]$Last)
    $base = ($First.Substring(0,1) + $Last) -replace "[^a-zA-Z0-9]", ""
    $base = $base.ToLower().Substring(0, [math]::Min(18, $base.Length))
    $sam  = $base; $i = 1
    while (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        $sam = "$base$i"; $i++
    }
    return $sam
}

# ─── Helper: Temp Password ────────────────────────────────────────────────────
function New-TempPassword {
    $chars = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$"
    $pwd   = "A1!" + (-join (1..9 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] }))
    return $pwd
}

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nAD Bulk User Creation Tool" -ForegroundColor Green
    $mode = if ($WhatIf) { "PREVIEW MODE - No accounts will be created" } else { "EXECUTE MODE" }
    Write-Host "  $mode" -ForegroundColor $(if ($WhatIf) { "Yellow" } else { "Green" })

    # Check CSV exists, offer sample if not
    if (-not (Test-Path $CSVPath)) {
        Write-Host "`n  CSV file not found: $CSVPath" -ForegroundColor Yellow
        $create = Read-Host "  Create a sample CSV template? (Y/N)"
        if ($create -eq 'Y') { New-SampleCSV -Path $CSVPath }
        exit 0
    }

    # Import CSV
    $users = Import-Csv -Path $CSVPath -ErrorAction Stop
    Write-Log "Imported $($users.Count) records from: $CSVPath"
    Write-Host "`n  Found $($users.Count) user(s) to process." -ForegroundColor Cyan

    $domain    = (Get-ADDomain).DNSRoot
    $domainDN  = (Get-ADDomain).DistinguishedName
    $defaultOU = "OU=Users,OU=Company,$domainDN"

    $results = [System.Collections.Generic.List[object]]::new()
    $ok = 0; $fail = 0; $skip = 0

    foreach ($row in $users) {
        $firstName = $row.FirstName.Trim()
        $lastName  = $row.LastName.Trim()
        $fullName  = "$firstName $lastName"

        Write-Host "`n  Processing: $fullName" -ForegroundColor White

        # Validate required fields
        if (-not $firstName -or -not $lastName) {
            Write-Log "SKIPPED: Missing FirstName or LastName on row" "WARN"
            $results.Add([PSCustomObject]@{ Name=$fullName; SAM="N/A"; Status="SKIPPED"; Reason="Missing name"; TempPassword="" })
            $skip++; continue
        }

        try {
            $sam      = Get-UniqueSAM -First $firstName -Last $lastName
            $upn      = "$sam@$domain"
            $tempPwd  = New-TempPassword
            $targetOU = if ($row.OU) { $row.OU } else { $defaultOU }

            if ($WhatIf) {
                Write-Host "    [PREVIEW] Would create: $sam ($upn) in $targetOU" -ForegroundColor Cyan
                $results.Add([PSCustomObject]@{ Name=$fullName; SAM=$sam; UPN=$upn; OU=$targetOU; Status="PREVIEW"; Reason="WhatIf mode"; TempPassword=$tempPwd })
                $ok++; continue
            }

            # Build params
            $params = @{
                GivenName             = $firstName
                Surname               = $lastName
                Name                  = $fullName
                DisplayName           = $fullName
                SamAccountName        = $sam
                UserPrincipalName     = $upn
                EmailAddress          = if ($row.Email) { $row.Email } else { $upn }
                Department            = $row.Department
                Title                 = $row.Title
                Path                  = $targetOU
                AccountPassword       = (ConvertTo-SecureString $tempPwd -AsPlainText -Force)
                ChangePasswordAtLogon = $true
                Enabled               = $true
            }

            # Manager
            if ($row.Manager) {
                $mgr = Get-ADUser -Filter "SamAccountName -eq '$($row.Manager)'" -ErrorAction SilentlyContinue
                if ($mgr) { $params["Manager"] = $mgr.DistinguishedName }
            }

            New-ADUser @params -ErrorAction Stop
            Write-Log "Created: $sam ($fullName)" "OK"

            # Groups
            if ($row.Groups) {
                $groupList = $row.Groups -split ";"
                foreach ($g in $groupList) {
                    $g = $g.Trim()
                    if ($g) {
                        try {
                            Add-ADGroupMember -Identity $g -Members $sam -ErrorAction Stop
                            Write-Log "  Added $sam to group: $g" "OK"
                        } catch {
                            Write-Log "  Could not add to group '$g': $($_.Exception.Message)" "WARN"
                        }
                    }
                }
            }

            $results.Add([PSCustomObject]@{ Name=$fullName; SAM=$sam; UPN=$upn; OU=$targetOU; Status="CREATED"; Reason="Success"; TempPassword=$tempPwd })
            $ok++

        } catch {
            Write-Log "FAILED: $fullName - $($_.Exception.Message)" "ERROR"
            $results.Add([PSCustomObject]@{ Name=$fullName; SAM="N/A"; Status="FAILED"; Reason=$_.Exception.Message; TempPassword="" })
            $fail++
        }
    }

    # Export results
    $results | Export-Csv -Path $rptFile -NoTypeInformation
    Write-Log "Results exported to: $rptFile"

    # Summary
    Write-Host "`n  ============================================" -ForegroundColor Cyan
    Write-Host "  BULK CREATE SUMMARY" -ForegroundColor Cyan
    Write-Host "  ============================================" -ForegroundColor Cyan
    Write-Host "  Total   : $($users.Count)"
    Write-Host "  Created : $ok"   -ForegroundColor Green
    Write-Host "  Failed  : $fail" -ForegroundColor $(if($fail -gt 0){"Red"}else{"White"})
    Write-Host "  Skipped : $skip" -ForegroundColor Yellow
    Write-Host "`n  Results saved to: $rptFile" -ForegroundColor Gray
    Write-Host "  *** Share temp passwords securely with each user ***" -ForegroundColor Yellow

} catch {
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
