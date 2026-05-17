# Section 6 — Windows Privileges Overview

> **No lab / no questions** — theory section. Critical foundational knowledge for Sections 7–12 where individual privileges are exploited.

---

## Privileges vs. access rights

| Concept | What it is | Example |
|---------|------------|---------|
| **Privilege** | Right granted to an *account* to perform system operations | `SeDebugPrivilege` — attach to any process |
| **Access right** | Permission on a *securable object* (file, registry key, pipe) | DACL entry granting Read to a folder |

Privileges are stored in the access token issued at logon. Access rights are stored in the object's security descriptor (DACL).

---

## Windows authorization flow

```
User logs on → access token created (User SID + Group SIDs + Privileges)
    │
    ▼
User accesses object (file, service, pipe, registry key)
    │
    ▼
System compares token against object's DACL (list of ACEs)
    │
    ▼
ACEs evaluated in order until: explicit Deny → DENIED, or Allow match → GRANTED
```

**As attackers, we exploit this by:**
- Adding ourselves to groups whose SIDs appear in Allow ACEs
- Leveraging privileges in our token to bypass DACL checks entirely (e.g., SeBackupPrivilege ignores file DACLs)
- Modifying DACLs (if we have WRITE_DAC) to grant ourselves access

---

## Dangerous groups (memorize for CPTS)

| Group | Effective power | Attack path |
|-------|----------------|-------------|
| **Default Administrators** | Full system control | — |
| **Server Operators** | Modify services, access shares, backup files | Change service binary → SYSTEM |
| **Backup Operators** | Read ANY file (bypass DACLs), read registry remotely | Dump SAM/NTDS.dit, shadow copy |
| **Print Operators** | Log on to DCs locally, load drivers | Load malicious driver → kernel code exec |
| **Hyper-V Administrators** | Full control of VMs | Clone DC virtual disk → offline hash extraction |
| **Account Operators** | Modify non-protected accounts/groups | Add user to privileged group |
| **Remote Desktop Users** | RDP access | Lateral movement, often granted extra rights |
| **Remote Management Users** | PSRemoting/WinRM access | Remote code execution |
| **Group Policy Creator Owners** | Create GPOs (need delegation to link) | Malicious GPO → code exec on targets |
| **Schema Admins** | Modify AD schema | Backdoor default object ACLs |
| **DNS Admins** | Load DLL on DC (via DNS service) | Malicious DLL → code exec as SYSTEM on DC |

> **Key insight:** `Backup Operators` on a DC = effectively Domain Admin. `Hyper-V Administrators` with virtual DCs = effectively Domain Admin. These are the groups blue teams often overlook.

---

## Critical user privileges (the ones that lead to privesc)

| Privilege constant | Name | Default assignment | Attack |
|-------------------|------|-------------------|--------|
| `SeImpersonatePrivilege` | Impersonate a client after auth | Admins, Local/Network/Service | **Potato attacks** → SYSTEM |
| `SeDebugPrivilege` | Debug programs | Administrators | Inject into any process, dump LSASS |
| `SeBackupPrivilege` | Back up files and directories | Administrators | Read ANY file — SAM, NTDS.dit, sensitive configs |
| `SeRestorePrivilege` | Restore files and directories | Administrators | Write ANY file — replace system DLLs, service binaries |
| `SeTakeOwnershipPrivilege` | Take ownership of files/objects | Administrators | Own any object → modify its DACL → full access |
| `SeLoadDriverPrivilege` | Load/unload device drivers | Administrators | Load vulnerable driver → kernel exploit |
| `SeSecurityPrivilege` | Manage auditing and security log | Administrators | Clear security logs, modify SACLs |
| `SeTcbPrivilege` | Act as part of the operating system | Service accounts | Assume identity of any user |

---

## Privilege states: Enabled vs. Disabled

```
State: Enabled  → actively usable right now
State: Disabled → assigned to your account but must be enabled before use
```

**Critical point:** `Disabled` does NOT mean you don't have it. It means it's in your token but not currently active. You can enable it programmatically:

```powershell
# PowerShell script to enable privileges (need to import/use a script like Enable-Privilege.ps1)
# Example: enabling SeBackupPrivilege in current process
```

> Windows has no built-in cmdlet to enable privileges — you need custom scripts or tools. Many exploits (Potato, etc.) handle this automatically.

---

## Standard user vs. admin vs. elevated admin

| Context | Typical privileges | Notes |
|---------|-------------------|-------|
| Standard user (`htb-student`) | `SeChangeNotifyPrivilege`, `SeIncreaseWorkingSetPrivilege` | Almost nothing useful |
| Admin (non-elevated, UAC filtered) | Same as standard user | UAC strips privileges! |
| Admin (elevated — Run as Administrator) | Full set (20+ privileges) | All powerful privs available |
| Backup Operators member | Adds `SeShutdownPrivilege` (UAC restricts the rest) | Must bypass UAC to use SeBackupPrivilege |

> **UAC trap:** Even if your user is in Administrators or Backup Operators, an unelevated shell has privileges stripped. You need an elevated context (UAC bypass or Run as Admin) to leverage group-based privileges.

---

## Connecting to our lab findings (WINLPE-SRV01)

From Section 4, `htb-student` has:
```
SeTakeOwnershipPrivilege      Take ownership of files or other objects   Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                   Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set             Disabled
```

**Attack chain implication:**
```
htb-student has SeTakeOwnershipPrivilege (non-default!)
│
├── This is normally ONLY assigned to Administrators
│   └── Someone (mis)configured this via Group Policy or local policy
│
├── Exploitation path:
│   1. Enable the privilege (script or tool)
│   2. Take ownership of a protected file/registry key
│   3. Options:
│       ├── Own SAM/SYSTEM hives → extract local admin hash
│       ├── Own a service binary → replace with malicious one → restart → SYSTEM
│       ├── Own a registry key (service config) → change ImagePath → SYSTEM
│       └── Own another user's files → read their stored credentials
│
└── This will be exploited in detail in the SeTakeOwnershipPrivilege section
```

Also from Section 4, `sarah` is in Backup Operators:
```
sarah (Backup Operators)
│
├── If we obtain sarah's credentials:
│   1. SeBackupPrivilege → read SAM + SYSTEM hives
│   2. secretsdump.py offline → local admin NTLM hash
│   3. Pass-the-hash → full system compromise
│
└── Requires: finding sarah's password (config files, shares, credential reuse)
    └── OR: UAC bypass if sarah has an interactive session
```

---

## Detection note

**Event ID 4672:** "Special privileges assigned to new logon" fires when sensitive privileges are assigned to a new session. Blue teams monitor this for:
- `SeDebugPrivilege` assigned to non-admin accounts
- `SeImpersonatePrivilege` in unexpected contexts
- Any privilege assigned to accounts that shouldn't have it

---

## Key takeaways

- **`whoami /priv` is your privilege roadmap.** Disabled doesn't mean unusable — it means "ready to enable."
- **Group membership = inherited privileges.** Check `whoami /groups` and `net localgroup` to understand what rights cascade down.
- **UAC filters privileges in non-elevated shells.** Even admin accounts appear weak until you elevate.
- **Memorize the top 6 dangerous privileges** (SeImpersonate, SeDebug, SeBackup, SeRestore, SeTakeOwnership, SeLoadDriver) — these are the exam-relevant ones.
- **Memorize the dangerous groups** — Backup Operators, Server Operators, DNS Admins, Print Operators, Hyper-V Admins are all privesc vectors that appear on the exam.
