#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Creates a new Active Directory user account with standard settings.

.DESCRIPTION
    Provisions a new AD user with:
      - Configurable OU placement
      - Automatic UPN and SAMAccountName generation
      - Group membership assignment
      - Password set and must-change-at-logon option
      - Account enabled/disabled state
      - Logging of all actions

.PARAMETER FirstName
    User's first name.

.PARAMETER LastName
    User's last name.

.PARAMETER Department
    User's department (used for OU targeting and group assignment).

.PARAMETER Title
    User's job title.

.PARAMETER Manager
    SAMAccountName of the user's manager.

.PARAMETER OU
    Distinguished Name of the target OU. If omitted, uses default.

.PARAMETER Groups
    Array of AD group names to add the user to.

.PARAMETER OutputPath
    Directory for the creation log. Defaults to Desktop.

.EXAMPLE
    .\01_AD_CreateUser.ps1 -FirstName "John" -LastName "Doe" -Department "IT" -Title "SysAdmin"
    .\01_AD_CreateUser.ps1 -FirstName "Jane" -LastName "Smith" -Department "HR" -Groups "HR-Staff","VPN-Users"

.NOTES
    Prerequisites : ActiveDirectory module, Domain Admin or Account Operator rights.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FirstName,
    [Parameter(Mandatory)][string]$LastName,
    [Parameter(Mandatory)][string]$Department,
    [string]$Title       = "",
    [string]$Manager     = "",
    [string]$OU          = "",
    [string[]]$Groups    = @(),
    [string]$OutputPath  = "$env:USERPROFILE\Desktop"
)

# ─── Configuration ─────────────────────────────────────────────────────────────
$Domain         = (Get-ADDomain).DNSRoot
$DomainDN       = (Get-ADDomain).DistinguishedName
$DefaultOU      = "OU=Users,OU=Company,$DomainDN"   # Change to your default OU
$UPNSuffix      = "@$Domain"

# Department-to-OU mapping (customize for your org)
$DeptOUMap = @{
    "IT"          = "OU=IT,OU=Users,OU=Company,$DomainDN"
    "HR"          = "OU=HR,OU=Users,OU=Company,$DomainDN"
    "Finance"     = "OU=Finance,OU=Users,OU=Company,$DomainDN"
    "Sales"       = "OU=Sales,OU=Users,OU=Company,$DomainDN"
    "Operations"  = "OU=Operations,OU=Users,OU=Company,$DomainDN"
}

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "AD_CreateUser_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } "OK" { "Green" } default { "Gray" } }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── Helper: Generate Unique SAMAccountName ────────────────────────────────────
function Get-UniqueSAM {
    param([string]$First, [string]$Last)
    # Format: first initial + last name (e.g. jdoe), max 20 chars
    $base = ($First.Substring(0,1) + $Last) -replace "[^a-zA-Z0-9]", ""
    $base = $base.ToLower().Substring(0, [math]::Min(18, $base.Length))
    $sam  = $base
    $i    = 1
    while (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        $sam = "$base$i"
        $i++
    }
    return $sam
}

# ─── Helper: Generate Strong Password ─────────────────────────────────────────
function New-TempPassword {
    $upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    $lower   = "abcdefghjkmnpqrstuvwxyz"
    $digits  = "23456789"
    $special = "!@#$%^&*"
    $all     = $upper + $lower + $digits + $special
    $pwd = ($upper  | Get-Random) + ($lower  | Get-Random) +
           ($digits | Get-Random) + ($special | Get-Random)
    1..8 | ForEach-Object { $pwd += ($all | Get-Random) }
    return ($pwd.ToCharArray() | Get-Random -Count $pwd.Length) -join ""
}

# ─── Main ──────────────────────────────────────────────────────────────────────
try {
    Write-Host "`nAD User Creation Tool" -ForegroundColor Green
    Write-Log "Starting user creation: $FirstName $LastName"

    # Resolve target OU
    $targetOU = if ($OU) { $OU }
                elseif ($DeptOUMap.ContainsKey($Department)) { $DeptOUMap[$Department] }
                else { $DefaultOU }

    # Verify OU exists
    try {
        Get-ADOrganizationalUnit -Identity $targetOU -ErrorAction Stop | Out-Null
    } catch {
        Write-Log "OU not found: $targetOU - falling back to default OU" "WARN"
        $targetOU = $DefaultOU
    }

    # Generate account details
    $SAM         = Get-UniqueSAM -First $FirstName -Last $LastName
    $UPN         = "$SAM$UPNSuffix"
    $DisplayName = "$FirstName $LastName"
    $TempPwd     = New-TempPassword
    $SecurePwd   = ConvertTo-SecureString $TempPwd -AsPlainText -Force

    Write-Host "`n  Provisioning account:" -ForegroundColor Cyan
    Write-Host "    Display Name   : $DisplayName"
    Write-Host "    SAMAccountName : $SAM"
    Write-Host "    UPN            : $UPN"
    Write-Host "    Target OU      : $targetOU"
    Write-Host "    Department     : $Department"

    # Build user parameters
    $userParams = @{
        GivenName             = $FirstName
        Surname               = $LastName
        Name                  = $DisplayName
        DisplayName           = $DisplayName
        SamAccountName        = $SAM
        UserPrincipalName     = $UPN
        EmailAddress          = $UPN
        Department            = $Department
        Title                 = $Title
        Path                  = $targetOU
        AccountPassword       = $SecurePwd
        ChangePasswordAtLogon = $true
        Enabled               = $true
    }

    # Add manager if specified
    if ($Manager) {
        try {
            $mgr = Get-ADUser -Identity $Manager -ErrorAction Stop
            $userParams["Manager"] = $mgr.DistinguishedName
        } catch {
            Write-Log "Manager '$Manager' not found in AD - skipping" "WARN"
        }
    }

    # Create the user
    New-ADUser @userParams -ErrorAction Stop
    Write-Log "User created: $SAM ($DisplayName) in $targetOU" "OK"

    # Add to groups
    if ($Groups.Count -gt 0) {
        foreach ($group in $Groups) {
            try {
                Add-ADGroupMember -Identity $group -Members $SAM -ErrorAction Stop
                Write-Log "Added $SAM to group: $group" "OK"
            } catch {
                Write-Log "Could not add $SAM to group '$group': $($_.Exception.Message)" "WARN"
            }
        }
    }

    # Display summary
    Write-Host "`n  ============================================" -ForegroundColor Green
    Write-Host "  USER CREATED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "  ============================================" -ForegroundColor Green
    Write-Host "  Username    : $SAM"
    Write-Host "  UPN         : $UPN"
    Write-Host "  Temp Password: $TempPwd" -ForegroundColor Yellow
    Write-Host "  *** Provide this password to the user securely ***" -ForegroundColor Yellow
    Write-Host "  User must change password at next logon." -ForegroundColor Gray

    Write-Log "User creation complete: $SAM / $UPN"

} catch {
    Write-Log "FAILED to create user $FirstName $LastName : $($_.Exception.Message)" "ERROR"
    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
