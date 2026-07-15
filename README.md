# PIM Auditor

Interactive PowerShell tool for auditing **Azure resource roles** and **Microsoft Entra ID directory roles**, comparing permanent assignments against PIM (Privileged Identity Management) eligible assignments to identify over-privileged access.

## Purpose

Over time, organizations accumulate privileged role assignments that may no longer be necessary. This script helps security teams and administrators:

- Identify who has permanent high-privilege access (vs. PIM-eligible JIT access)
- Audit across Azure subscriptions and Entra ID directory roles in one session
- Generate HTML reports for compliance reviews and documentation

## Features

### Azure Resource Role Audit
- Scans **Management Group → Subscription → Resource Group** hierarchy
- Detects permanent and PIM-eligible role assignments at each scope
- Filters to high-privilege roles only: Owner, Contributor, User Access Administrator, Management Group Contributor
- Displays hierarchical scope paths with visual separators

### Microsoft Entra ID Audit
- Scans directory-wide role assignments and Administrative Unit-scoped assignments
- Detects permanent and PIM-eligible assignments for 15 high-privilege Entra ID roles
- Resolves principal names for users, groups, and service principals

**Monitored Entra ID Roles:**
Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Security Administrator, Conditional Access Administrator, Partner Tier2 Support, User Administrator, Application Administrator, Cloud Application Administrator, Hybrid Identity Administrator, Exchange Administrator, SharePoint Administrator, Intune Administrator, Compliance Administrator, Global Reader

### HTML Report Export
- Styled, browser-ready HTML reports with summary cards and color-coded tables
- Saved to `./reports/` folder automatically
- Includes both permanent and PIM-eligible assignments with coverage statistics

### General
- Interactive browser-based Azure authentication (no device code flow)
- Subscription auto-selection after login (no picker prompt)
- Module management — only installs required Az/Graph modules when needed
- Clean terminal output with section separators
- Verbose mode for troubleshooting (`-VerboseMode`)

## Prerequisites

- **PowerShell 5.1+** (Windows) or **PowerShell 7+** (macOS/Linux)
- **Az.Accounts** module (auto-installed on first run)
- **Az.Resources** module (auto-installed when Azure audit is selected)
- **Microsoft.Graph.\*** modules (auto-installed when Entra audit is selected)
- Azure account with at least **Reader** role on target subscriptions
- Entra ID account with **Global Reader** or equivalent role for directory audit

## Usage

```powershell
# Run the script
./Get-AzureSubscriptions.ps1

# Run with verbose debug output
./Get-AzureSubscriptions.ps1 -VerboseMode
```

## Notes

- PIM eligible detection requires **Entra ID P2** license (or EMS E5)
- The script uses `-AtScope` for Azure roles — only assignments made at the exact scope are shown (no inherited permissions)
- Subscription picker is suppressed after login; first subscription is auto-selected
- Native Azure PowerShell warnings are suppressed for clean output