#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD Group Management - Create, modify, and manage AD security groups.

.DESCRIPTION
    Full-featured group management tool providing:
      - Create new security or distribution groups
      - Add/remove members (single or bulk from CSV)
      - List group members
      - Clone group membership from one user to another
      - Find empty groups
      - Export group membership to CSV

.PARAMETER OutputPath
    Directory for logs and exports. Defaults to Desktop.

.EXAMPLE
    .\04_AD_GroupManagement.ps1

.NOTES
    Prerequisites : ActiveDirectory module; rights to manage groups.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

# ─── Logging ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$logFile = Join-Path $OutputPath "AD_Groups_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] [Op:$env:USERNAME] $Message"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level) { "ERROR"{"Red"} "WARN"{"Yellow"} "OK"{"Green"} default{"Gray"} }
    Write-Host "  $entry" -ForegroundColor $color
}

# ─── Create Group ──────────────────────────────────────────────────────────────
function New-ADGroupMenu {
    Write-Host "`n--- CREATE NEW GROUP ---" -ForegroundColor Yellow
    $name     = Read-Host "  Group Name"
    $scope    = Read-Host "  Scope (DomainLocal/Global/Universal) [Global]"
    if (-not $scope) { $scope = "Global" }
    $category = Read-Host "  Category (Security/Distribution) [Security]"
    if (-not $category) { $category = "Security" }
    $desc     = Read-Host "  Description"
    $ou       = Read-Host "  Target OU DN (leave blank for default)"

    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        $targetOU = if ($ou) { $ou } else { "OU=Groups,OU=Company,$domainDN" }

        $params = @{
            Name          = $name
            GroupScope    = $scope
            GroupCategory = $category
            Description   = $desc
            Path          = $targetOU
        }
        New-ADGroup @params -ErrorAction Stop
        Write-Log "Group created: $name ($scope/$category) in $targetOU" "OK"
        Write-Host "  [OK] Group '$name' created." -ForegroundColor Green
    } catch {
        Write-Log "Failed to create group '$name': $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Add Members ──────────────────────────────────────────────────────────────
function Add-GroupMembersMenu {
    Write-Host "`n--- ADD MEMBERS TO GROUP ---" -ForegroundColor Yellow
    $group = Read-Host "  Group name"

    # Verify group exists
    try { Get-ADGroup -Identity $group -ErrorAction Stop | Out-Null }
    catch { Write-Host "  [ERROR] Group '$group' not found." -ForegroundColor Red; return }

    $method = Read-Host "  Add by [1] Username(s) or [2] CSV file?"

    if ($method -eq '1') {
        $users = (Read-Host "  Enter SAMAccountNames (comma-separated)") -split "," | ForEach-Object { $_.Trim() }
        foreach ($u in $users) {
            try {
                Add-ADGroupMember -Identity $group -Members $u -ErrorAction Stop
                Write-Log "Added '$u' to group '$group'" "OK"
                Write-Host "  [OK] $u added to $group" -ForegroundColor Green
            } catch {
                Write-Log "Failed to add '$u' to '$group': $($_.Exception.Message)" "ERROR"
                Write-Host "  [ERROR] $u - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } elseif ($method -eq '2') {
        $csv = Read-Host "  CSV path (one SAMAccountName per row, column header: Username)"
        if (-not (Test-Path $csv)) { Write-Host "  File not found." -ForegroundColor Red; return }
        $rows = Import-Csv $csv
        $ok = 0; $fail = 0
        foreach ($row in $rows) {
            $u = $row.Username.Trim()
            try {
                Add-ADGroupMember -Identity $group -Members $u -ErrorAction Stop
                $ok++
            } catch {
                Write-Log "Failed to add '$u': $($_.Exception.Message)" "WARN"
                $fail++
            }
        }
        Write-Log "Bulk add to '$group': $ok added, $fail failed" "OK"
        Write-Host "  Done: $ok added, $fail failed." -ForegroundColor $(if($fail -gt 0){"Yellow"}else{"Green"})
    }
}

# ─── Remove Members ───────────────────────────────────────────────────────────
function Remove-GroupMembersMenu {
    Write-Host "`n--- REMOVE MEMBERS FROM GROUP ---" -ForegroundColor Yellow
    $group = Read-Host "  Group name"
    $user  = Read-Host "  SAMAccountName to remove"
    try {
        $confirm = Read-Host "  Remove '$user' from '$group'? (Y/N)"
        if ($confirm -ne 'Y') { return }
        Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false -ErrorAction Stop
        Write-Log "Removed '$user' from '$group'" "OK"
        Write-Host "  [OK] '$user' removed from '$group'." -ForegroundColor Green
    } catch {
        Write-Log "Failed: $($_.Exception.Message)" "ERROR"
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── List Group Members ───────────────────────────────────────────────────────
function Show-GroupMembers {
    Write-Host "`n--- GROUP MEMBERS ---" -ForegroundColor Yellow
    $group = Read-Host "  Group name"
    try {
        $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop | Sort-Object Name
        Write-Host "`n  Group: $group  ($($members.Count) members)" -ForegroundColor Cyan
        Write-Host ("  {0,-35} {1,-15} {2}" -f "Name", "Type", "SAMAccountName")
        Write-Host ("  {0,-35} {1,-15} {2}" -f "----", "----", "--------------")
        foreach ($m in $members) {
            Write-Host ("  {0,-35} {1,-15} {2}" -f $m.Name, $m.objectClass, $m.SamAccountName)
        }

        $export = Read-Host "`n  Export to CSV? (Y/N)"
        if ($export -eq 'Y') {
            $csv = Join-Path $OutputPath "GroupMembers_${group}_$(Get-Date -Format 'yyyyMMdd').csv"
            $members | Select-Object Name, SamAccountName, objectClass, DistinguishedName |
                Export-Csv -Path $csv -NoTypeInformation
            Write-Host "  Exported to: $csv" -ForegroundColor Gray
            Write-Log "Exported members of '$group' to: $csv"
        }
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Clone User Group Memberships ─────────────────────────────────────────────
function Copy-UserGroupMemberships {
    Write-Host "`n--- CLONE GROUP MEMBERSHIPS ---" -ForegroundColor Yellow
    Write-Host "  Copies all group memberships from one user to another." -ForegroundColor Gray
    $source = Read-Host "  Source user (SAMAccountName)"
    $target = Read-Host "  Target user (SAMAccountName)"

    try {
        $srcUser  = Get-ADUser -Identity $source -Properties MemberOf -ErrorAction Stop
        $tgtUser  = Get-ADUser -Identity $target -Properties MemberOf -ErrorAction Stop
        $groups   = $srcUser.MemberOf
        $ok = 0; $fail = 0

        Write-Host "  Copying $($groups.Count) group(s) from '$source' to '$target'..." -ForegroundColor Cyan

        foreach ($g in $groups) {
            try {
                Add-ADGroupMember -Identity $g -Members $target -ErrorAction Stop
                $ok++
            } catch {
                Write-Log "Could not add '$target' to '$g': $($_.Exception.Message)" "WARN"
                $fail++
            }
        }
        Write-Log "Cloned groups from '$source' to '$target': $ok copied, $fail failed" "OK"
        Write-Host "  Done: $ok groups copied, $fail failed." -ForegroundColor $(if($fail){"Yellow"}else{"Green"})
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Find Empty Groups ────────────────────────────────────────────────────────
function Find-EmptyGroups {
    Write-Host "`n--- FIND EMPTY GROUPS ---" -ForegroundColor Yellow
    Write-Host "  Searching for groups with no members..." -ForegroundColor Gray
    try {
        $allGroups = Get-ADGroup -Filter * -Properties Members | Where-Object { $_.Members.Count -eq 0 }
        Write-Host "`n  Found $($allGroups.Count) empty group(s):" -ForegroundColor Cyan
        $allGroups | Sort-Object Name | ForEach-Object { Write-Host "    - $($_.Name)  [$($_.GroupScope)/$($_.GroupCategory)]" }

        $csv = Join-Path $OutputPath "EmptyGroups_$(Get-Date -Format 'yyyyMMdd').csv"
        $allGroups | Select-Object Name, GroupScope, GroupCategory, DistinguishedName |
            Export-Csv -Path $csv -NoTypeInformation
        Write-Host "`n  Exported to: $csv" -ForegroundColor Gray
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Delete Group ─────────────────────────────────────────────────────────────
function Remove-ADGroupMenu {
    Write-Host "`n--- DELETE GROUP ---" -ForegroundColor Yellow
    $group = Read-Host "  Group name to delete"
    try {
        $g = Get-ADGroup -Identity $group -Properties Members -ErrorAction Stop
        Write-Host "  Found: $($g.Name)  Members: $($g.Members.Count)" -ForegroundColor Cyan
        $confirm = Read-Host "  Permanently delete '$($g.Name)'? (Y/N)"
        if ($confirm -ne 'Y') { Write-Host "  Cancelled." -ForegroundColor Gray; return }
        Remove-ADGroup -Identity $group -Confirm:$false -ErrorAction Stop
        Write-Log "Group DELETED: $group" "OK"
        Write-Host "  [OK] Group '$group' deleted." -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─── Menu ──────────────────────────────────────────────────────────────────────
function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   AD GROUP MANAGEMENT"                                         -ForegroundColor Yellow
    Write-Host "   Operator: $env:USERNAME | Domain: $((Get-ADDomain).DNSRoot)"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Create a new group"                -ForegroundColor White
    Write-Host "  [2] Add member(s) to a group"          -ForegroundColor White
    Write-Host "  [3] Remove a member from a group"      -ForegroundColor White
    Write-Host "  [4] List group members"                -ForegroundColor White
    Write-Host "  [5] Clone user group memberships"      -ForegroundColor White
    Write-Host "  [6] Find empty groups"                 -ForegroundColor White
    Write-Host "  [7] Delete a group"                    -ForegroundColor White
    Write-Host "  [Q] Quit"                              -ForegroundColor Gray
    Write-Host ""
}

# ─── Entry Point ───────────────────────────────────────────────────────────────
Write-Log "AD Group Management started"
try {
    do {
        Show-Menu
        $choice = Read-Host "Select option"
        switch ($choice.ToUpper()) {
            '1' { New-ADGroupMenu;              Read-Host "`nPress Enter" }
            '2' { Add-GroupMembersMenu;         Read-Host "`nPress Enter" }
            '3' { Remove-GroupMembersMenu;      Read-Host "`nPress Enter" }
            '4' { Show-GroupMembers;            Read-Host "`nPress Enter" }
            '5' { Copy-UserGroupMemberships;    Read-Host "`nPress Enter" }
            '6' { Find-EmptyGroups;             Read-Host "`nPress Enter" }
            '7' { Remove-ADGroupMenu;           Read-Host "`nPress Enter" }
            'Q' { Write-Host "`nExiting." -ForegroundColor Gray; break }
            default { Write-Host "  Invalid." -ForegroundColor Yellow; Start-Sleep 1 }
        }
    } while ($choice.ToUpper() -ne 'Q')
} catch {
    Write-Host "`n[FATAL] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
