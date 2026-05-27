# AD WhatsApp Access Manager

[![PSScriptAnalyzer](https://github.com/imHenrybtw/WhatsApp-AccessSync/actions/workflows/lint.yml/badge.svg)](https://github.com/imHenrybtw/WhatsApp-AccessSync/actions/workflows/lint.yml)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue?style=flat)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207%2B-5391FE?style=flat&logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)

Automated Active Directory group management based on WhatsApp connection status reported by a third-party audit API. Designed to run on a schedule and enforce network access policies in real time — without manual intervention.

---

## How it works

```
Audit API (REST)
      │
      ▼
Compare with previous snapshot
      │
      ├─► AD Group changes (Add / Remove)
      │         Active Directory (LDAP)
      │
      └─► Firewall session deauth
                FortiGate REST API (multi-site)
```

Every execution cycle:

1. Authenticates with the configured audit REST API and retrieves the current list of users with their WhatsApp connection status (`connected` / `disconnected`).
2. Compares against the previous snapshot stored locally as JSON.
3. Classifies each user as **Admin** (has company e-mail or is in an exception OU) or **Operator**.
4. Builds an action plan:
   - Connected → add to the correct `*_WhatsApp` AD group, remove from `*_NoWhats` groups.
   - Disconnected → remove from `*_WhatsApp` groups, optionally add to `*_NoWhats` groups.
   - Missing from current snapshot → treated as disconnected, stripped of WhatsApp access.
   - Disabled accounts / excluded OUs → stripped of **all** navigation groups.
5. Executes the action plan against Active Directory.
6. Deauthenticates active FortiGate firewall sessions for users whose status changed.
7. Rotates the audit file for the next run.

---

## Requirements

| Requirement | Notes |
|---|---|
| PowerShell 5.1 or 7+ | Both branches supported |
| `ActiveDirectory` module | Part of RSAT on Windows Server |
| Domain-joined machine | Or a machine with LDAP/LDAPS access to a DC |
| FortiGate REST API access | Token-based, per site |
| Audit API | Any REST API returning the shape described below |

---

## API contract

The script expects the audit API to return users in this shape:

```json
{
  "data": [
    { "matricula": "jdoe",  "conectado": true  },
    { "matricula": "asmith","conectado": false }
  ]
}
```

`matricula` must match the user's `sAMAccountName` in Active Directory.  
`conectado` is a boolean (`true` = currently connected to WhatsApp).

---

## Configuration

All configuration lives at the top of `Manage-WhatsAppAccess.ps1` under the `── Configuration ──` region. No external config file is required.

Key variables to adjust:

```powershell
# Your AD domain
$ADServer    = "corp.example.com"
$ADSearchBase = "DC=corp,DC=example,DC=com"

# Where the four navigation groups live
$GroupSearchBase = "OU=InternetGroups,DC=corp,DC=example,DC=com"

# OUs whose members must never receive any navigation group
$ExcludedOUs = @(
    "OU=DisabledAccounts,DC=corp,DC=example,DC=com"
)

# Group names (must exist in $GroupSearchBase)
$GroupNames = @{
    AdminWhats      = "G_Internet_Admin_WhatsApp"
    OperatorWhats   = "G_Internet_Operator_WhatsApp"
    AdminNoWhats    = "G_Internet_Admin"
    OperatorNoWhats = "G_Internet_Operator"
}

# Firewall sites
$FirewallSites = @(
    @{ Name = "HQ";       URL = "https://firewall-hq.example.com"   }
    @{ Name = "Branch01"; URL = "https://firewall-br01.example.com" }
)

# Audit API endpoints
$ApiUrlLogin = "https://audit-api.example.com/v1/auth/login"
$ApiUrlUsers = "https://audit-api.example.com/v1/users/disconnected"
```

---

## Credential storage

Credentials (API key/secret and per-site FortiGate tokens) are **never stored in plain text**.  
They are encrypted with a local AES-256 key using PowerShell's `SecureString` mechanism.

Use the helper script to generate `credentials.json` and `aes.key`:

```powershell
.\tools\Save-Credentials.ps1
```

> Both files must be placed in the script root (`$scriptPath`). Keep `aes.key` protected — anyone with read access to it can decrypt the credentials.

---

## Scheduling

### Windows Task Scheduler

```xml
<Triggers>
  <TimeTrigger>
    <Repetition>
      <Interval>PT10M</Interval>
      <StopAtDurationEnd>false</StopAtDurationEnd>
    </Repetition>
  </TimeTrigger>
</Triggers>
<Actions>
  <Exec>
    <Command>powershell.exe</Command>
    <Arguments>-NonInteractive -ExecutionPolicy Bypass -File "C:\Scripts\WhatsAppAccess\Manage-WhatsAppAccess.ps1"</Arguments>
  </Exec>
</Actions>
```

---

## Logs

| File | Contents |
|---|---|
| `logs\general.log` | Full transcript of every run |
| `logs\validation.log` | API auth, environment init, user lookup |
| `logs\ad-changes.log` | Every ADD / REMOVE operation in AD |
| `logs\firewall-deauth.log` | Session collection and deauth results |
| `logs\status.log` | User status summary (connected / disconnected counts) |

Logs are **reset on each run** (previous run overwritten). For persistent history, redirect or archive `general.log` externally.

---

## Project structure

```
WhatsAppAccess/
├── Manage-WhatsAppAccess.ps1   ← Main script
├── tools/
│   └── Save-Credentials.ps1   ← Credential setup helper
├── data/
│   └── audit.json              ← Previous-run snapshot (auto-managed)
└── logs/                       ← Runtime logs (auto-created)
```

---

## Adapting to other audit tools

The only integration point is the API contract above. To use a different audit tool:

1. Update `$ApiUrlLogin` and `$ApiUrlUsers` to point to your tool's endpoints.
2. Adjust `Connect-AuditAPI` and `Get-AuditUsers` if the authentication scheme differs (e.g., API key header instead of a login endpoint).
3. Ensure the response includes `matricula` (or remap the field name in `Get-UserNavigationGroups`).

Everything else — AD manipulation, FortiGate deauth, logging, scheduling — remains unchanged.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
