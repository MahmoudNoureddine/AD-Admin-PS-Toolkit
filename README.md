# 🏢 AD-Admin-PS-Toolkit

> 20 production-ready PowerShell scripts for Active Directory administration — on-premises environments.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Scripts](https://img.shields.io/badge/Scripts-20%20Complete-brightgreen)

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | 5.1 or higher |
| Module | `ActiveDirectory` (RSAT Tools) |
| GPO Scripts | Also requires `GroupPolicy` module (GPMC) |

**Install RSAT AD Tools:**
```powershell
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
Add-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
```

---

## All 20 Scripts

### 👤 User Management
| # | Script | Description |
|---|--------|-------------|
| 01 | `01_AD_CreateUser.ps1` | Create new AD user — auto SAM/UPN, dept OU targeting, group assignment, temp password |
| 02 | `02_AD_DisableDeleteUser.ps1` | Safe offboarding — disable/delete, remove groups, reset password, move to Disabled OU |
| 03 | `03_AD_BulkCreateUsers.ps1` | Bulk provision from CSV with WhatIf preview and per-user results report |
| 12 | `12_AD_UserSearch.ps1` | Search by name/email/dept/phone, full detail view, side-by-side comparison, find duplicates |
| 15 | `15_AD_OffboardingWorkflow.ps1` | 8-step automated offboarding with audit report |
| 16 | `16_AD_OnboardingWorkflow.ps1` | New hire provisioning — create, assign groups by dept, clone buddy, generate welcome sheet |

### 👥 Group Management
| # | Script | Description |
|---|--------|-------------|
| 04 | `04_AD_GroupManagement.ps1` | Create, add/remove members, clone memberships, find empty groups, delete |

### 🗂️ OU Management
| # | Script | Description |
|---|--------|-------------|
| 05 | `05_AD_OUManagement.ps1` | Create, rename, delete OUs; move objects; visualize OU tree; export structure |

### 🔐 Password & Account Policies
| # | Script | Description |
|---|--------|-------------|
| 06 | `06_AD_PasswordManagement.ps1` | Reset, unlock, force change, password audit, view policy |
| 13 | `13_AD_AccountExpiry.ps1` | Set/remove/extend expiry dates, bulk expiry from CSV, view all expiring accounts |

### 📊 Reporting & Auditing
| # | Script | Description |
|---|--------|-------------|
| 07 | `07_AD_UserReports.ps1` | Inactive users, disabled accounts, recent creations, by department, stale computers |
| 11 | `11_AD_AuditAndCompliance.ps1` | Security audit — privileged groups, service accounts, guest account, password policy |
| 20 | `20_AD_MasterReport.ps1` | One-click executive report covering all AD areas. Supports -Zip flag |

### 💻 Computer Management
| # | Script | Description |
|---|--------|-------------|
| 08 | `08_AD_ComputerManagement.ps1` | Search, full inventory, disable stale, ping/WMI/RDP test, move OUs |

### 🛡️ GPO Management
| # | Script | Description |
|---|--------|-------------|
| 09 | `09_AD_GPOManagement.ps1` | List, create, link/unlink, backup/restore, HTML report, find unlinked GPOs |
| 17 | `17_AD_GroupPolicyReport.ps1` | GPO link map, inheritance per OU, WMI filters, change history, full HTML report |

### 📦 Bulk Operations
| # | Script | Description |
|---|--------|-------------|
| 10 | `10_AD_BulkOperations.ps1` | Bulk update attributes, enable/disable, add to groups, move OUs — all via CSV |

### 🔧 Domain Health & Infrastructure
| # | Script | Description |
|---|--------|-------------|
| 14 | `14_AD_DomainHealthCheck.ps1` | DC reachability, SYSVOL/NETLOGON, replication, DNS SRV records, FSMO, time sync |
| 18 | `18_AD_ServiceAccountManager.ps1` | Audit, create, and manage service accounts; check services using domain accounts |
| 19 | `19_AD_ReplicationMonitor.ps1` | Replication status/topology, force replication, event log analysis, DC metadata |

---

## Quick Usage Examples

```powershell
# New hire onboarding
.\16_AD_OnboardingWorkflow.ps1 -FirstName "Sarah" -LastName "Jones" -Department "Finance" -Title "Analyst" -Manager "jsmith" -BuddyAccount "bwilson"

# Full offboarding
.\15_AD_OffboardingWorkflow.ps1 -Identity "jdoe" -Reason "Resigned" -DisabledOU "OU=Disabled,OU=Users,DC=company,DC=com"

# Bulk create users (preview first)
.\03_AD_BulkCreateUsers.ps1 -CSVPath "C:\HR\new_starters.csv" -WhatIf
.\03_AD_BulkCreateUsers.ps1 -CSVPath "C:\HR\new_starters.csv"

# Executive AD report (zipped)
.\20_AD_MasterReport.ps1 -OutputPath "C:\Reports" -Zip

# Domain health check
.\14_AD_DomainHealthCheck.ps1

# Full security audit
.\11_AD_AuditAndCompliance.ps1 -OutputPath "C:\AuditReports"
```

---

## CSV Templates

**Bulk User Create (`03`):**
```csv
FirstName,LastName,Department,Title,Manager,OU,Groups,Email
John,Doe,IT,SysAdmin,jsmith,,IT-Staff;VPN-Users,john.doe@company.com
```

**Bulk Attribute Update (`10`):**
```csv
SamAccountName,Department,Title,Office,Phone,Manager
jdoe,IT,Senior SysAdmin,HQ Floor 1,+1-555-0100,jsmith
```

**Bulk Account Expiry (`13`):**
```csv
SamAccountName,ExpiryDate
contractor1,2026-06-30
temp_user,never
```

---

## Features (All Scripts)
- ✅ Full comment-based help (`Get-Help .\script.ps1`)
- ✅ Try/catch error handling
- ✅ Audit logging with operator name and timestamp
- ✅ Confirmation prompts before destructive actions
- ✅ WhatIf/preview modes where applicable
- ✅ CSV exports for all reports

---

## License
MIT License — free to use, modify, and distribute.
