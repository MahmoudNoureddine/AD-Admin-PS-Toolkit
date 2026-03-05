#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    OU Management - Creates, modifies, and manages Organizational Units.

.DESCRIPTION
    Manages the AD OU structure with the ability to:
      - Create new OUs with optional protection from accidental deletion
      - List the OU tree structure
      - Move objects (users/computers/groups) between OUs
      - Rename OUs
      - Delete empty OUs
      - Export OU structure to CSV

.PARAMETER OutputPath
    Directory for logs and reports. Defaults to Desktop.

.EXAMPLE
    .\05_AD_OUManagement.ps1

.NOTES
    Prerequisites : ActiveDirectory module, Domain Admin rights for OU changes.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "AD_OU_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR"{"Red"} "WARN"{"Yellow"} "OK"{"Green"} default{"Gray"} }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── Display OU Tree ──────────────────────────────────────────────────────────
function Show-OUTree {
    Write-Host "`n--- OU STRUCTURE ---" -ForegroundColor Yellow
    try {
        $domainDN = (Get-ADDomain).DistinguishedName

        function Write-OUTree {
            param([string]$ParentDN, [int]$Level = 0)
            $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $ParentDN -SearchScope OneLevel -ErrorAction SilentlyContinue |
                   Sort-Object Name
            foreach ($ou in $ous) {
                $indent = "  " + ("  " * $Level)
                $objCount = (Get-ADObject -Filter * -SearchBase $ou.DistinguishedName -SearchScope OneLevel -ErrorAction SilentlyContinue | Measure-Object).Count
                Write-Host "$indent📁 $($ou.Name)  [$objCount objects]" -ForegroundColor Cyan
                Write-OUTree -ParentDN $ou.DistinguishedName -Level ($Level + 1)
            }
        }

        Write-Host "`n  Domain: $domainDN" -ForegroundColor White
        Write-OUTree -ParentDN $domainDN

        # Export option
        $export = Read-Host "`n  Export OU list to CSV? (Y/N)"
        if ($export -eq 'Y') {
            $csv = Join-Path $OutputPath "OUStructure_$(Get-Date -Format 'yyyyMMdd').csv"
            Get-ADOrganizationalUnit -Filter * -Properties Description, ProtectedFromAccidentalDeletion |
                Select-Object Name, DistinguishedName, Description, ProtectedFromAccidentalDeletion |
                Sort-Object DistinguishedName |
                Export-Csv -Path $csv -NoTypeInformation
            Write-Host "  Exported to: $csv" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Create OU ────────────────────────────────────────────────────────────────
function New-OUMenu {
    Write-Host "`n--- CREATE NEW OU ---" -ForegroundColor Yellow
    $name   = Read-Host "  OU Name"
    $parent = Read-Host "  Parent OU DN (e.g. DC=domain,DC=com)"
    $desc   = Read-Host "  Description (optional)"
    $protect = Read-Host "  Protect from accidental deletion? (Y/N) [Y]"
    $protected = $protect -ne 'N'

    try {
        $params = @{
            Name                            = $name
            Path                            = $parent
            ProtectedFromAccidentalDeletion = $protected
        }
        if ($desc) { $params["Description"] = $desc }

        New-ADOrganizationalUnit @params -ErrorAction Stop
        Write-Log "OU created: OU=$name,$parent (Protected: $protected)" "OK"
        Write-Host "  [OK] OU '$name' created." -ForegroundColor Green
    } catch {
        Write-Log "Failed to create OU '$name': $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Move Object to Different OU ──────────────────────────────────────────────
function Move-ADObjectMenu {
    Write-Host "`n--- MOVE OBJECT TO DIFFERENT OU ---" -ForegroundColor Yellow
    $type   = Read-Host "  Object type [1] User  [2] Computer  [3] Group"
    $sam    = Read-Host "  SAMAccountName or Name"
    $target = Read-Host "  Target OU DN"

    try {
        # Find the object
        $obj = switch ($type) {
            '1' { Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction Stop }
            '2' { Get-ADComputer -Filter "Name -eq '$sam'" -ErrorAction Stop }
            '3' { Get-ADGroup -Filter "Name -eq '$sam'" -ErrorAction Stop }
            default { throw "Invalid type selection" }
        }

        if (-not $obj) { throw "Object '$sam' not found." }

        Write-Host "  Found: $($obj.DistinguishedName)" -ForegroundColor Cyan
        $confirm = Read-Host "  Move to '$target'? (Y/N)"
        if ($confirm -ne 'Y') { return }

        Move-ADObject -Identity $obj.DistinguishedName -TargetPath $target -ErrorAction Stop
        Write-Log "Moved '$sam' to: $target" "OK"
        Write-Host "  [OK] Object moved successfully." -ForegroundColor Green
    } catch {
        Write-Log "Move failed: $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Rename OU ────────────────────────────────────────────────────────────────
function Rename-OUMenu {
    Write-Host "`n--- RENAME OU ---" -ForegroundColor Yellow
    $dn      = Read-Host "  OU Distinguished Name to rename"
    $newName = Read-Host "  New name"
    try {
        Rename-ADObject -Identity $dn -NewName $newName -ErrorAction Stop
        Write-Log "OU renamed to '$newName': $dn" "OK"
        Write-Host "  [OK] OU renamed to '$newName'." -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Delete OU ────────────────────────────────────────────────────────────────
function Remove-OUMenu {
    Write-Host "`n--- DELETE OU ---" -ForegroundColor Yellow
    $dn = Read-Host "  OU Distinguished Name to delete"
    try {
        $ou = Get-ADOrganizationalUnit -Identity $dn -Properties ProtectedFromAccidentalDeletion -ErrorAction Stop

        # Check object count
        $children = Get-ADObject -Filter * -SearchBase $dn -SearchScope OneLevel -ErrorAction SilentlyContinue
        if ($children) {
            Write-Host "  WARNING: OU contains $($children.Count) child object(s). Cannot delete non-empty OU." -ForegroundColor Red
            return
        }

        # Remove accidental deletion protection if set
        if ($ou.ProtectedFromAccidentalDeletion) {
            Write-Host "  OU is protected from accidental deletion." -ForegroundColor Yellow
            $unprotect = Read-Host "  Remove protection and delete? (Y/N)"
            if ($unprotect -ne 'Y') { return }
            Set-ADOrganizationalUnit -Identity $dn -ProtectedFromAccidentalDeletion $false
        }

        $confirm = Read-Host "  Delete OU '$($ou.Name)'? (Y/N)"
        if ($confirm -ne 'Y') { return }

        Remove-ADOrganizationalUnit -Identity $dn -Confirm:$false -ErrorAction Stop
        Write-Log "OU DELETED: $dn" "OK"
        Write-Host "  [OK] OU deleted." -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── List Objects in OU ───────────────────────────────────────────────────────
function Show-OUContents {
    Write-Host "`n--- LIST OU CONTENTS ---" -ForegroundColor Yellow
    $dn    = Read-Host "  OU Distinguished Name"
    $depth = Read-Host "  Search depth [1] OneLevel  [2] Subtree [1]"
    $scope = if ($depth -eq '2') { "Subtree" } else { "OneLevel" }

    try {
        $objects = Get-ADObject -Filter * -SearchBase $dn -SearchScope $scope -Properties ObjectClass |
                   Sort-Object ObjectClass, Name
        Write-Host "`n  Contents of: $dn  ($($objects.Count) objects)" -ForegroundColor Cyan
        Write-Host ("  {0,-35} {1}" -f "Name", "Type")
        Write-Host ("  {0,-35} {1}" -f "----", "----")
        foreach ($o in $objects) {
            $color = switch ($o.ObjectClass) { "user"{"White"} "computer"{"Cyan"} "group"{"Yellow"} "organizationalUnit"{"Magenta"} default{"Gray"} }
            Write-Host ("  {0,-35} {1}" -f $o.Name, $o.ObjectClass) -ForegroundColor $color
        }
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   AD ORGANIZATIONAL UNIT MANAGEMENT"                          -ForegroundColor Yellow
    Write-Host "   Domain: $((Get-ADDomain).DNSRoot)"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Show OU tree structure"     -ForegroundColor White
    Write-Host "  [2] Create new OU"              -ForegroundColor White
    Write-Host "  [3] Move object to another OU"  -ForegroundColor White
    Write-Host "  [4] List contents of an OU"     -ForegroundColor White
    Write-Host "  [5] Rename an OU"               -ForegroundColor White
    Write-Host "  [6] Delete an OU"               -ForegroundColor White
    Write-Host "  [Q] Quit"                       -ForegroundColor Gray
    Write-Host ""
}

Write-Log "AD OU Management started"
try {
    do {
        Show-Menu
        $choice = Read-Host "Select option"
        switch ($choice.ToUpper()) {
            '1' { Show-OUTree;        Read-Host "`nPress Enter" }
            '2' { New-OUMenu;         Read-Host "`nPress Enter" }
            '3' { Move-ADObjectMenu;  Read-Host "`nPress Enter" }
            '4' { Show-OUContents;    Read-Host "`nPress Enter" }
            '5' { Rename-OUMenu;      Read-Host "`nPress Enter" }
            '6' { Remove-OUMenu;      Read-Host "`nPress Enter" }
            'Q' { break }
            default { Write-Host "  Invalid." -ForegroundColor Yellow; Start-Sleep 1 }
        }
    } while ($choice.ToUpper() -ne 'Q')
} catch {
    Write-Host "`n[FATAL] $($_.Exception.Message)" -ForegroundColor Red; exit 1
}
