#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Onboarding Workflow - Complete automated new hire provisioning.

.DESCRIPTION
    Runs a structured onboarding process for new employees:
      1. Create AD account with standard naming convention
      2. Add to role-based groups (based on department/title)
      3. Clone groups from a similar user (buddy account)
      4. Set account expiry if temp/contractor
      5. Generate welcome information sheet
      6. Log all provisioning actions

.PARAMETER FirstName     New hire's first name (required).
.PARAMETER LastName      New hire's last name (required).
.PARAMETER Department    Department name (required).
.PARAMETER Title         Job title.
.PARAMETER Manager       Manager's SAMAccountName.
.PARAMETER BuddyAccount  SAMAccountName of similar user to clone groups from.
.PARAMETER IsContractor  Creates account with 90-day expiry if set.
.PARAMETER OutputPath    Directory for welcome sheet. Defaults to Desktop.

.EXAMPLE
    .\16_AD_OnboardingWorkflow.ps1 -FirstName "Sarah" -LastName "Jones" -Department "Finance" -Title "Analyst" -Manager "jsmith" -BuddyAccount "bwilson"

.NOTES
    Prerequisites : ActiveDirectory module; Account Operator rights.
    Author        : IT Administration Team  |  Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FirstName,
    [Parameter(Mandatory)][string]$LastName,
    [Parameter(Mandatory)][string]$Department,
    [string]$Title         = "",
    [string]$Manager       = "",
    [string]$BuddyAccount  = "",
    [switch]$IsContractor,
    [string]$OutputPath    = "$env:USERPROFILE\Desktop"
)

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile    = Join-Path $OutputPath "AD_Onboarding_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$M, [string]$L = "INFO")
    $e = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$L] [Op:$env:USERNAME] $M"
    Add-Content $logFile $e -ErrorAction SilentlyContinue
    Write-Host "  $e" -ForegroundColor $(switch($L){"ERROR"{"Red"}"WARN"{"Yellow"}"OK"{"Green"}default{"Gray"}})
}
function Write-Step { param([int]$N, [string]$T); Write-Host "`n  [$N] $T" -ForegroundColor Cyan }

# ─── Department -> OU + Default Groups mapping ────────────────────────────────
$DeptConfig = @{
    "IT"          = @{ OU = "OU=IT,OU=Users,OU=Company,DC=domain,DC=com";       Groups = @("IT-Staff","VPN-Users","Remote-Desktop") }
    "HR"          = @{ OU = "OU=HR,OU=Users,OU=Company,DC=domain,DC=com";       Groups = @("HR-Staff","HR-Shared-Drive") }
    "Finance"     = @{ OU = "OU=Finance,OU=Users,OU=Company,DC=domain,DC=com";  Groups = @("Finance-Staff","Finance-Drive") }
    "Sales"       = @{ OU = "OU=Sales,OU=Users,OU=Company,DC=domain,DC=com";    Groups = @("Sales-Staff","CRM-Access") }
    "Operations"  = @{ OU = "OU=Ops,OU=Users,OU=Company,DC=domain,DC=com";      Groups = @("Ops-Staff") }
}
$DefaultOU     = "OU=Users,OU=Company,$((Get-ADDomain).DistinguishedName)"
$GlobalGroups  = @("All-Staff","Office365-Licensed")   # Added to every new user

function Get-UniqueSAM {
    param([string]$F, [string]$L)
    $base = (($F.Substring(0,1) + $L) -replace "[^a-zA-Z0-9]").ToLower().Substring(0,[math]::Min(18,($F.Substring(0,1)+$L).Length))
    $sam  = $base; $i = 1
    while (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) { $sam = "$base$i"; $i++ }
    return $sam
}

function New-TempPassword {
    $chars = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$"
    return "Aa1!" + (-join (1..8 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] }))
}

try {
    Write-Host "`nAD Onboarding Workflow" -ForegroundColor Green
    $fullName = "$FirstName $LastName"
    $domain   = (Get-ADDomain).DNSRoot

    # Resolve OU and groups
    $config     = if ($DeptConfig.ContainsKey($Department)) { $DeptConfig[$Department] } else { @{ OU = $DefaultOU; Groups = @() } }
    $targetOU   = $config.OU
    $deptGroups = $config.Groups

    # Verify OU
    try { Get-ADOrganizationalUnit -Identity $targetOU -ErrorAction Stop | Out-Null }
    catch { Write-Log "OU '$targetOU' not found - using default" "WARN"; $targetOU = $DefaultOU }

    $sam     = Get-UniqueSAM -F $FirstName -L $LastName
    $upn     = "$sam@$domain"
    $tempPwd = New-TempPassword

    Write-Host ""
    Write-Host "  New Hire    : $fullName"
    Write-Host "  Username    : $sam"
    Write-Host "  UPN         : $upn"
    Write-Host "  Department  : $Department"
    Write-Host "  Target OU   : $targetOU"
    Write-Host "  Contractor  : $IsContractor"
    Write-Host ""
    $confirm = Read-Host "  Proceed with onboarding? (Y/N)"
    if ($confirm -ne 'Y') { Write-Host "  Cancelled." -ForegroundColor Gray; exit 0 }

    # STEP 1: Create account
    Write-Step 1 "Creating AD account"
    $params = @{
        GivenName             = $FirstName
        Surname               = $LastName
        Name                  = $fullName
        DisplayName           = $fullName
        SamAccountName        = $sam
        UserPrincipalName     = $upn
        EmailAddress          = $upn
        Department            = $Department
        Title                 = $Title
        Path                  = $targetOU
        AccountPassword       = (ConvertTo-SecureString $tempPwd -AsPlainText -Force)
        ChangePasswordAtLogon = $true
        Enabled               = $true
    }

    if ($Manager) {
        $mgr = Get-ADUser -Filter "SamAccountName -eq '$Manager'" -ErrorAction SilentlyContinue
        if ($mgr) { $params["Manager"] = $mgr.DistinguishedName }
    }
    if ($IsContractor) {
        $params["AccountExpirationDate"] = (Get-Date).AddDays(90)
        Write-Log "Contractor account - 90-day expiry set" "WARN"
    }

    New-ADUser @params -ErrorAction Stop
    Write-Log "Account created: $sam ($fullName)" "OK"

    # STEP 2: Add to department + global groups
    Write-Step 2 "Assigning group memberships"
    $allGroups = $GlobalGroups + $deptGroups
    foreach ($g in $allGroups) {
        try {
            Add-ADGroupMember -Identity $g -Members $sam -ErrorAction Stop
            Write-Log "Added to group: $g" "OK"
        } catch { Write-Log "Could not add to group '$g': $($_.Exception.Message)" "WARN" }
    }

    # STEP 3: Clone from buddy account
    Write-Step 3 "Cloning groups from buddy account"
    if ($BuddyAccount) {
        try {
            $buddy  = Get-ADUser -Identity $BuddyAccount -Properties MemberOf -ErrorAction Stop
            $cloned = 0
            foreach ($g in $buddy.MemberOf) {
                $gName = ($g -split ",")[0] -replace "CN="
                if ($gName -notin $allGroups) {
                    try { Add-ADGroupMember -Identity $g -Members $sam -ErrorAction Stop; $cloned++; Write-Log "Cloned group: $gName" "OK" }
                    catch { Write-Log "Could not clone group '$gName'" "WARN" }
                }
            }
            Write-Log "Cloned $cloned additional group(s) from buddy: $BuddyAccount" "OK"
        } catch { Write-Log "Buddy account '$BuddyAccount' not found" "WARN" }
    } else { Write-Log "No buddy account specified" "INFO" }

    # STEP 4: Generate welcome sheet
    Write-Step 4 "Generating welcome information sheet"
    $welcomeFile = Join-Path $OutputPath "Welcome_${sam}_$timestamp.txt"
    @"
================================================
  WELCOME TO THE TEAM - IT ACCOUNT INFORMATION
================================================
  Name         : $fullName
  Username     : $sam
  Email        : $upn
  Department   : $Department
  Title        : $Title

  TEMPORARY PASSWORD  : $tempPwd
  *** You must change your password at first logon ***

  LOGIN INSTRUCTIONS:
  1. Press Ctrl+Alt+Delete on your workstation
  2. Enter username: $sam
  3. Enter the temporary password above
  4. You will be prompted to set a new password

  PASSWORD REQUIREMENTS:
  - Minimum 12 characters
  - Must include uppercase, lowercase, number, and symbol
  - Cannot reuse last 10 passwords

  SUPPORT CONTACT:
  IT Help Desk: helpdesk@$domain
  Phone: [IT SUPPORT NUMBER]

  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')
  By: $env:USERNAME
================================================
"@ | Out-File -FilePath $welcomeFile -Encoding UTF8

    Write-Log "Welcome sheet saved: $welcomeFile" "OK"

    # Summary
    Write-Host "`n  ============================================" -ForegroundColor Green
    Write-Host "  ONBOARDING COMPLETE" -ForegroundColor Green
    Write-Host "  ============================================" -ForegroundColor Green
    Write-Host "  Username     : $sam"
    Write-Host "  Temp Password: $tempPwd" -ForegroundColor Yellow
    Write-Host "  Welcome sheet: $welcomeFile" -ForegroundColor Gray
    if ($IsContractor) { Write-Host "  Account expires: $((Get-Date).AddDays(90).ToString('yyyy-MM-dd'))" -ForegroundColor Yellow }
    Write-Host "`n  NEXT STEPS (manual):" -ForegroundColor Yellow
    Write-Host "    - Assign M365 license"
    Write-Host "    - Provide welcome sheet to user securely"
    Write-Host "    - Set up physical workstation"
    Write-Host "    - Brief manager: $Manager"

} catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
