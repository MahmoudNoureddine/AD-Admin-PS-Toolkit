# 🏢 AD-Admin-PS-Toolkit

> A collection of 20 production-ready PowerShell scripts for Active Directory administrators — covering user lifecycle, group management, GPO, security auditing, domain health, and automation.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows%20Server-informational?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)
![Scripts](https://img.shields.io/badge/Scripts-20%20Complete-brightgreen)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Getting Started](#getting-started)
- [Scripts](#scripts)
- [Usage Examples](#usage-examples)
- [CSV Templates](#csv-templates)
- [Safety & Best Practices](#safety--best-practices)
- [Logging](#logging)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**AD-Admin-PS-Toolkit** is a complete library of PowerShell scripts designed to streamline Active Directory administration in on-premises Windows environments. Each script is:

- ✅ Self-documented with `.SYNOPSIS`, `.DESCRIPTION`, and `.EXAMPLE` headers
- ✅ Built with `try/catch` error handling throughout
- ✅ Safe by default — destructive operations require explicit confirmation
- ✅ Logging-enabled with operator name and timestamp for full auditability
- ✅ Modular and standalone — no third-party dependencies required

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | Version 5.1 or higher (`$PSVersionTable.PSVersion`) |
| OS | Windows Server 2016+ / Windows 10+ with RSAT |
| Module | `ActiveDirectory` (required for all scripts) |
| Module | `GroupPolicy` (required for `AD_GPOManagement.ps1` and `AD_GroupPolicyReport.ps1`) |
| Privileges | Varies per script — noted in the table below |

**Install RSAT modules if not already present:**
```powershell
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
Add-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
```

---

## Getting Started

**1. Clone the repository**
```powershell
git clone https://github.com/YOUR-USERNAME/AD-Admin-PS-Toolkit.git
cd AD-Admin-PS-Toolkit
```

**2. Allow script execution** *(one-time setup)*
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**3. Run any script**
```powershell
.\AD_CreateUser.ps1 -FirstName "John" -LastName "Doe" -Department "IT"
```

**4. Get built-in help for any script**
```powershell
Get-Help .\AD_CreateUser.ps1 -Full
```

---

## Scripts

### 👤 User Lifecycle Management

| Script | Description | Admin |
|--------|-------------|:-----:|
| [`AD_CreateUser.ps1`](./AD_CreateUser.ps1) | Creates a new AD user with auto-generated SAM/UPN, department-based OU targeting, group assignment, and temp password | ⚠️ |
| [`AD_DisableDeleteUser.ps1`](./AD_DisableDeleteUser.ps1) | Safely disables or permanently deletes accounts — removes groups, resets password, moves to Disabled OU, stamps description | ⚠️ |
| [`AD_BulkCreateUsers.ps1`](./AD_BulkCreateUsers.ps1) | Bulk provisions multiple users from a CSV file with WhatIf preview mode and a per-user results report | ⚠️ |
| [`AD_UserSearch.ps1`](./AD_UserSearch.ps1) | Advanced user lookup by name, email, department, phone, or title; full detail view, side-by-side comparison, duplicate finder | ❌ |
| [`AD_OffboardingWorkflow.ps1`](./AD_OffboardingWorkflow.ps1) | Runs a complete 8-step offboarding checklist — disable, randomize password, remove groups, stamp description, move OU, generate audit report | ⚠️ |
| [`AD_OnboardingWorkflow.ps1`](./AD_OnboardingWorkflow.ps1) | Structured new hire provisioning — creates account, assigns dept-based groups, clones from buddy account, generates welcome sheet | ⚠️ |

### 👥 Group Management

| Script | Description | Admin |
|--------|-------------|:-----:|
| [`AD_GroupManagement.ps1`](./AD_GroupManagement.ps1) | Full group lifecycle — create, add/remove members (single or bulk CSV), clone memberships between users, find empty groups, delete | ⚠️ |

### 🗂️ OU Management

| Script | Description | Admin |
|--------|-------------|:-----:|
| [`AD_OUManagement.ps1`](./AD_OUManagement.ps1) | Create, rename, and delete OUs; move objects between OUs; visualize the OU tree with object counts; export structure to CSV | ✅ |

### 🔐 Password & Account Policies

| Script | Description | Admin |
|--------|-------------|:-----:|
| [`AD_PasswordManagement.ps1`](./AD_PasswordManagement.ps1) | Reset passwords, unlock accounts (single or all at once), force change at logon, password audit report, view domain policy | ⚠️ |
| [`AD_AccountExpiry.ps1`](./AD_AccountExpiry.ps1) | Set, remove, or extend account expiration dates; bulk expiry from CSV; view all accounts expiring within a configurable window | ⚠️ |

### 📊 Reporting & Auditing

| Script | Description | Admin |
|--------|-------------|:-----:|
| [`AD_UserReports.ps1`](./AD_UserReports.ps1) | Generates reports for inactive users, disabled accounts, recently created accounts, users by department, expiring accounts, and stale computers | ❌ |
| [`AD_AuditAndCompliance.ps1`](./AD_AuditAndCompliance.ps1) | Security audit — privileged group membership, service accounts, guest/KRBTGT status, never-logged-on accounts, password policy compliance, SmartCard check | ❌ |
| [`AD_MasterReport.ps1`](./AD_MasterReport.ps1) | One-click executive report covering domain overview, FSMO, DCs, replication, user/computer/group stats, password policy, and security highlights | ❌ |

### 💻 Computer Account Management

| Script | Description | Admin |
|--------|-------------|:-----:|
| [`AD_ComputerManagement.ps1`](./AD_ComputerManagement.ps1) | Search and view computer details, export full inventory with OS summary, disable stale computers, test ping/WMI/RDP connectivity, move between OUs | ✅ |

### 🛡️ GPO Management

| Script | Description | Admin |
|--------|-------------|:-----:|
| [`AD_GPOManagement.ps1`](./AD_GPOManagement.ps1) | List, create, link/unlink, enable/disable GPOs; backup and restore; generate HTML reports; find unlinked GPOs | ⚠️ |
| [`AD_GroupPolicyReport.ps1`](./AD_GroupPolicyReport.ps1) | GPO link map, inheritance per OU, security filtering report, WMI filter inventory, GPO change history, full consolidated HTML report | ❌ |

### 📦 Bulk Operations

| Script | Description | Admin |
|--------|-------------|:-----:|
| [`AD_BulkOperations.ps1`](./AD_BulkOperations.ps1) | Bulk update user attributes, enable/disable accounts, add to groups, move OUs, export users to CSV for editing, bulk set password expiry — all via CSV | ⚠️ |

### 🔧 Domain Health & Infrastructure

| Script | Description | Admin |
|--------|-------------|:-----:|
| [`AD_DomainHealthCheck.ps1`](./AD_DomainHealthCheck.ps1) | DC reachability, SYSVOL/NETLOGON share availability, replication status, DNS SRV records, FSMO role holders, time synchronization | ✅ |
| [`AD_ServiceAccountManager.ps1`](./AD_ServiceAccountManager.ps1) | Discover and audit all service accounts, create new accounts with best-practice settings, check Windows services using domain accounts, reset passwords | ✅ |
| [`AD_ReplicationMonitor.ps1`](./AD_ReplicationMonitor.ps1) | Replication status overview, topology visualization, force replication between DCs, event log analysis, DC metadata and repadmin summary | ✅ |

> **Legend:** ✅ = Always required &nbsp; ⚠️ = Recommended / required for some features &nbsp; ❌ = Not required

---

## Usage Examples

```powershell
# Create a new user in the IT department
.\AD_CreateUser.ps1 -FirstName "John" -LastName "Doe" -Department "IT" -Title "SysAdmin" -Groups "IT-Staff","VPN-Users"

# Disable a departing user and remove all group memberships
.\AD_DisableDeleteUser.ps1 -Identity "jdoe" -Action Disable -Reason "Resigned" -RemoveGroups

# Preview bulk user creation from CSV, then execute
.\AD_BulkCreateUsers.ps1 -CSVPath "C:\HR\new_starters.csv" -WhatIf
.\AD_BulkCreateUsers.ps1 -CSVPath "C:\HR\new_starters.csv"

# Full new hire onboarding with buddy group cloning
.\AD_OnboardingWorkflow.ps1 -FirstName "Sarah" -LastName "Jones" -Department "Finance" -Title "Analyst" -Manager "jsmith" -BuddyAccount "bwilson"

# Full 8-step offboarding with audit report
.\AD_OffboardingWorkflow.ps1 -Identity "jdoe" -Reason "Resigned" -DisabledOU "OU=Disabled,OU=Users,DC=company,DC=com"

# Unlock all locked accounts across the domain
.\AD_PasswordManagement.ps1   # Select option 2, then type ALL

# Run all user reports and export CSVs
.\AD_UserReports.ps1   # Select option A

# Search for a user by email address
.\AD_UserSearch.ps1   # Select option 1, then option 2 for email

# Clone group memberships from one user to another
.\AD_GroupManagement.ps1   # Select option 5

# Backup all GPOs before making changes
.\AD_GPOManagement.ps1   # Select option 5

# Full domain health check
.\AD_DomainHealthCheck.ps1

# Full security audit report
.\AD_AuditAndCompliance.ps1 -OutputPath "C:\AuditReports"

# One-click executive AD report (zipped)
.\AD_MasterReport.ps1 -OutputPath "C:\Reports" -Zip

# Audit all service accounts for compliance issues
.\AD_ServiceAccountManager.ps1   # Select option 1

# Check replication status across all DC partnerships
.\AD_ReplicationMonitor.ps1   # Select option 1
```

---

## CSV Templates

**Bulk User Create (`AD_BulkCreateUsers.ps1`):**
```csv
FirstName,LastName,Department,Title,Manager,OU,Groups,Email
John,Doe,IT,SysAdmin,jsmith,,IT-Staff;VPN-Users,john.doe@company.com
Jane,Smith,HR,HR Manager,,,HR-Staff,jane.smith@company.com
```

**Bulk Attribute Update (`AD_BulkOperations.ps1`):**
```csv
SamAccountName,Department,Title,Office,Phone,Manager
jdoe,IT,Senior SysAdmin,HQ Floor 1,+1-555-0100,jsmith
```

**Bulk Group Add (`AD_BulkOperations.ps1`):**
```csv
SamAccountName
jdoe
jsmith
ajohansson
```

**Bulk Account Expiry (`AD_AccountExpiry.ps1`):**
```csv
SamAccountName,ExpiryDate
contractor1,2026-06-30
temp_user,never
```

---

## Safety & Best Practices

- **Preview before acting** — `AD_BulkCreateUsers.ps1` supports `-WhatIf` to show what would happen without making changes. Always preview first.
- **Confirm destructive actions** — Scripts that disable, delete, or modify accounts prompt for explicit confirmation before proceeding.
- **Double confirmation for deletions** — `AD_DisableDeleteUser.ps1` requires typing the username to confirm permanent deletion.
- **Test in a lab first** — Validate scripts against a test OU or non-production domain before running in production.
- **Least privilege** — Only scripts that genuinely require Domain Admin are marked ✅. Use Account Operator rights where possible.
- **Configure before running** — Several scripts have configurable sections at the top (`$DeptOUMap`, `$DeptConfig`, `$GlobalGroups`, `$DefaultOU`) — edit these to match your environment before use.

---

## Logging

Scripts that perform sensitive or impactful actions write timestamped audit logs automatically:

| Script | Log File |
|--------|----------|
| `AD_CreateUser.ps1` | `AD_CreateUser_YYYYMMDD.log` |
| `AD_DisableDeleteUser.ps1` | `AD_DisableDelete_YYYYMMDD.log` |
| `AD_BulkCreateUsers.ps1` | `AD_BulkCreate_YYYYMMDD_HHmmss.log` |
| `AD_GroupManagement.ps1` | `AD_Groups_YYYYMMDD.log` |
| `AD_OUManagement.ps1` | `AD_OU_YYYYMMDD.log` |
| `AD_PasswordManagement.ps1` | `AD_Password_YYYYMMDD.log` |
| `AD_GPOManagement.ps1` | `AD_GPO_YYYYMMDD.log` |
| `AD_OffboardingWorkflow.ps1` | `AD_Offboarding_YYYYMMDD.log` |
| `AD_OnboardingWorkflow.ps1` | `AD_Onboarding_YYYYMMDD.log` |
| `AD_ServiceAccountManager.ps1` | `AD_ServiceAccounts_YYYYMMDD.log` |
| `AD_ReplicationMonitor.ps1` | `AD_Replication_YYYYMMDD.log` |

All logs include the **operator username**, **timestamp**, and **action taken** for full auditability. Report-generating scripts save timestamped `.txt` and/or `.csv` files to `%USERPROFILE%\Desktop` by default, or to any path specified with `-OutputPath`.

---

## Contributing

Contributions are welcome! To add a script or improve an existing one:

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-script-name`
3. Follow the existing script structure — include `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, and `.EXAMPLE` headers
4. Add error handling with `try/catch` and include logging for write operations
5. Submit a pull request with a clear description of what was added or changed

---

## License

MIT License — free to use, modify, and distribute.
