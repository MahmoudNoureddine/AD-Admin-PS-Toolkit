#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD User Search - Advanced search and lookup for AD user accounts.

.DESCRIPTION
    Flexible search and comparison tool:
      - Search by name, email, department, phone, title, or SAM
      - Full user detail view
      - Side-by-side user comparison
      - Find duplicate accounts
      - Search by last logon date range

.PARAMETER OutputPath
    Directory for exported results. Defaults to Desktop.

.EXAMPLE
    .\12_AD_UserSearch.ps1

.NOTES
    Prerequisites : ActiveDirectory module; read access.
    Author        : IT Administration Team
    Version       : 1.0
#>

[CmdletBinding()]
param([string]$OutputPath = "$env:USERPROFILE\Desktop")

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

function Show-UserDetail {
    param($User)
    $mgr = if ($User.Manager) { (Get-ADUser -Identity $User.Manager -ErrorAction SilentlyContinue).Name } else { "None" }
    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host "  │  $($User.Name)" -ForegroundColor Yellow
    Write-Host "  ├──────────────────────────────────────────────────" -ForegroundColor Cyan
    @{
        "SAMAccountName"   = $User.SamAccountName
        "UPN"              = $User.UserPrincipalName
        "Email"            = $User.EmailAddress
        "Department"       = $User.Department
        "Title"            = $User.Title
        "Office"           = $User.Office
        "Phone"            = $User.OfficePhone
        "Manager"          = $mgr
        "Enabled"          = $User.Enabled
        "Locked Out"       = $User.LockedOut
        "Pwd Expired"      = $User.PasswordExpired
        "Pwd Never Exp"    = $User.PasswordNeverExpires
        "Pwd Last Set"     = $User.PasswordLastSet
        "Last Logon"       = $User.LastLogonDate
        "Account Created"  = $User.WhenCreated
        "Group Count"      = $User.MemberOf.Count
        "OU"               = ($User.DistinguishedName -replace "^CN=[^,]+,","")
    }.GetEnumerator() | Sort-Object Name | ForEach-Object {
        $color = if ($_.Key -eq "Enabled" -and $_.Value -eq $false) { "Red" }
                 elseif ($_.Key -eq "Locked Out" -and $_.Value -eq $true) { "Red" }
                 else { "White" }
        Write-Host ("  │  {0,-20} {1}" -f $_.Key, $_.Value) -ForegroundColor $color
    }
    Write-Host "  └──────────────────────────────────────────────────" -ForegroundColor Cyan
}

function Invoke-UserSearch {
    Write-Host "`n--- SEARCH USERS ---" -ForegroundColor Yellow
    Write-Host "  [1] Name  [2] Email  [3] Department  [4] Phone  [5] SAM  [6] Title"
    $type  = Read-Host "  Search by"
    $query = Read-Host "  Search term (* for wildcard)"
    try {
        $filter = switch ($type) {
            '1' { "Name -like '$query'" }           '2' { "EmailAddress -like '$query'" }
            '3' { "Department -like '$query'" }      '4' { "OfficePhone -like '$query'" }
            '5' { "SamAccountName -like '$query'" }  '6' { "Title -like '$query'" }
            default { "Name -like '$query'" }
        }
        $users = Get-ADUser -Filter $filter -Properties EmailAddress, Department, Title, Office,
            OfficePhone, Manager, LastLogonDate, PasswordLastSet, PasswordNeverExpires,
            PasswordExpired, LockedOut, Enabled, WhenCreated, MemberOf | Sort-Object Name

        if (-not $users) { Write-Host "  No users found." -ForegroundColor Yellow; return }
        Write-Host "`n  Found $(@($users).Count) result(s):" -ForegroundColor Cyan

        if (@($users).Count -eq 1) {
            Show-UserDetail -User $users
        } else {
            $i = 1
            Write-Host ("  {0,-4} {1,-25} {2,-25} {3,-15} {4}" -f "#","SAM","Email","Dept","Name")
            foreach ($u in $users) {
                Write-Host ("  {0,-4} {1,-25} {2,-25} {3,-15} {4}" -f $i, $u.SamAccountName, $u.EmailAddress, $u.Department, $u.Name)
                $i++
            }
            $sel = Read-Host "`n  Enter number for full details (Enter to skip)"
            if ($sel -match '^\d+$') {
                $idx = [int]$sel - 1
                if ($idx -ge 0 -and $idx -lt @($users).Count) { Show-UserDetail -User @($users)[$idx] }
            }
        }

        if ((Read-Host "`n  Export results? (Y/N)") -eq 'Y') {
            $csv = Join-Path $OutputPath "UserSearch_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $users | Select-Object Name, SamAccountName, UserPrincipalName, EmailAddress, Department, Title, Enabled, LastLogonDate |
                Export-Csv $csv -NoTypeInformation
            Write-Host "  Exported: $csv" -ForegroundColor Gray
        }
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

function Compare-TwoUsers {
    Write-Host "`n--- COMPARE TWO USERS ---" -ForegroundColor Yellow
    $s1 = Read-Host "  First SAMAccountName"; $s2 = Read-Host "  Second SAMAccountName"
    try {
        $u1 = Get-ADUser -Identity $s1 -Properties Department, Title, Office, EmailAddress, MemberOf, Enabled, LastLogonDate -ErrorAction Stop
        $u2 = Get-ADUser -Identity $s2 -Properties Department, Title, Office, EmailAddress, MemberOf, Enabled, LastLogonDate -ErrorAction Stop
        Write-Host "`n  {0,-22} {1,-30} {2}" -f "Attribute", $s1, $s2 -ForegroundColor Cyan
        Write-Host "  {0,-22} {1,-30} {2}" -f ("-"*21), ("-"*29), ("-"*20) -ForegroundColor Cyan
        foreach ($a in @("Name","Department","Title","Office","EmailAddress","Enabled")) {
            $v1 = $u1.$a; $v2 = $u2.$a
            $c  = if ($v1 -eq $v2) { "White" } else { "Yellow" }
            Write-Host ("  {0,-22} {1,-30} {2}" -f $a, $v1, $v2) -ForegroundColor $c
        }
        $g1    = $u1.MemberOf | ForEach-Object { ($_ -split ",")[0] -replace "CN=" }
        $g2    = $u2.MemberOf | ForEach-Object { ($_ -split ",")[0] -replace "CN=" }
        $only1 = $g1 | Where-Object { $_ -notin $g2 }
        $only2 = $g2 | Where-Object { $_ -notin $g1 }
        Write-Host "`n  Only in ${s1}: $($only1 -join ', ')" -ForegroundColor Yellow
        Write-Host "  Only in ${s2}: $($only2 -join ', ')" -ForegroundColor Cyan
        Write-Host "  Common groups: $(($g1 | Where-Object { $_ -in $g2 }).Count)"
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

function Find-Duplicates {
    Write-Host "`n--- FIND DUPLICATE ACCOUNTS ---" -ForegroundColor Yellow
    try {
        $dupes = Get-ADUser -Filter * | Group-Object Name | Where-Object { $_.Count -gt 1 }
        if ($dupes) {
            Write-Host "  $($dupes.Count) duplicate name(s) found:" -ForegroundColor Red
            foreach ($d in $dupes) {
                Write-Host "  Duplicate: $($d.Name)" -ForegroundColor Red
                $d.Group | ForEach-Object { Write-Host "    - $($_.SamAccountName)" }
            }
        } else { Write-Host "  [OK] No duplicate display names found." -ForegroundColor Green }
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

function Search-ByLogonRange {
    Write-Host "`n--- SEARCH BY LAST LOGON RANGE ---" -ForegroundColor Yellow
    $from = Read-Host "  From (yyyy-MM-dd)"; $to = Read-Host "  To (yyyy-MM-dd)"
    try {
        $fromDate = [datetime]::ParseExact($from,"yyyy-MM-dd",$null)
        $toDate   = [datetime]::ParseExact($to,"yyyy-MM-dd",$null)
        $users = Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate |
                 Where-Object { $_.LastLogonDate -ge $fromDate -and $_.LastLogonDate -le $toDate } |
                 Sort-Object LastLogonDate -Descending
        Write-Host "`n  $($users.Count) user(s) logged on between $from and $to:" -ForegroundColor Cyan
        $users | Select-Object -First 25 | ForEach-Object {
            Write-Host ("  {0,-25} {1}" -f $_.SamAccountName, $_.LastLogonDate?.ToString("yyyy-MM-dd HH:mm"))
        }
        $csv = Join-Path $OutputPath "LogonRange_$(Get-Date -Format 'yyyyMMdd').csv"
        $users | Select-Object Name, SamAccountName, LastLogonDate | Export-Csv $csv -NoTypeInformation
        Write-Host "  Exported: $csv" -ForegroundColor Gray
    } catch { Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red }
}

function Show-Menu {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   AD USER SEARCH & LOOKUP" -ForegroundColor Yellow
    Write-Host "   Domain: $((Get-ADDomain).DNSRoot)"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  [1] Search users`n  [2] Compare two users`n  [3] Find duplicates`n  [4] Search by logon range`n  [Q] Quit`n"
}

do {
    Show-Menu; $c = Read-Host "Select"
    switch ($c.ToUpper()) {
        '1' { Invoke-UserSearch;     Read-Host "`nPress Enter" }
        '2' { Compare-TwoUsers;      Read-Host "`nPress Enter" }
        '3' { Find-Duplicates;       Read-Host "`nPress Enter" }
        '4' { Search-ByLogonRange;   Read-Host "`nPress Enter" }
        'Q' { break }
        default { Start-Sleep 1 }
    }
} while ($c.ToUpper() -ne 'Q')
