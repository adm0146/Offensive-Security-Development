# Section 9 — Enumerating & Retrieving Password Policies

## Why This Matters

You MUST know the lockout policy before spraying. Locking out production accounts = major incident. Get the policy first, every time.

---

## Method 1 — Credentialed (Linux) — netexec / CrackMapExec

```bash
# netexec (nxc) — use this on Kali, crackmapexec not installed
nxc smb 172.16.5.5 -u avazquez -p Password123 --pass-pol

# crackmapexec (if available)
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

---

## Method 2 — SMB NULL Session (Unauthenticated, Linux)

SMB NULL sessions are a legacy misconfiguration — often found on DCs upgraded from older Windows Server versions.

### rpcclient
```bash
# Connect anonymously
rpcclient -U "" -N 172.16.5.5

# Inside rpcclient:
querydominfo      # domain info + user/group counts
getdompwinfo      # password policy
enumdomusers      # user list (if allowed)
```

### enum4linux
```bash
# Get password policy only
enum4linux -P 172.16.5.5
```

### enum4linux-ng (preferred — cleaner output, JSON/YAML export)
```bash
enum4linux-ng -P 172.16.5.5 -oA ilfreight
cat ilfreight.json
```

---

## Method 3 — LDAP Anonymous Bind (Unauthenticated, Linux)

Legacy config — anonymous LDAP queries allowed. Less common than NULL sessions.

```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# Note: newer ldapsearch uses -H instead of -h
ldapsearch -H ldap://172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

Key fields to look for: `minPwdLength`, `lockoutThreshold`, `lockoutDuration`, `pwdProperties`

---

## Method 4 — From Windows (Authenticated)

### net.exe (built-in, no tools needed)
```cmd
net accounts
```

### PowerView
```powershell
Import-Module .\PowerView.ps1
Get-DomainPolicy
```

### Null session from Windows
```cmd
net use \\DC01\ipc$ "" /u:""
```

**Windows error codes to know during spraying:**
| Error | Meaning |
|-------|---------|
| System error 1331 | Account disabled |
| System error 1326 | Wrong password |
| System error 1909 | Account locked out |

---

## Reading the Policy — What to Look For

INLANEFREIGHT.LOCAL example:
| Setting | Value | Implication |
|---------|-------|-------------|
| Min password length | 8 | Weak passwords likely in use — Welcome1, Password1 viable |
| Lockout threshold | 5 | Safe to try up to 3 passwords before waiting |
| Lockout duration | 30 min | Auto-unlocks — wait 31 min between rounds |
| Max password age | Not set | Passwords never expire — old breach data may work |
| Password complexity | Enabled | Must have 3/4 of: upper, lower, number, special |
| Manual unlock required | No | Auto-unlock — but still avoid lockouts |

**Default domain policy (new domain, never changed):**
| Policy | Default |
|--------|---------|
| Password history | 24 |
| Max password age | 42 days |
| Min password age | 1 day |
| Min password length | 7 |
| Complexity | Enabled |
| Lockout threshold | 0 (no lockout!) |
| Lockout duration | Not set |

---

## Spraying Decision Framework

```
Lockout threshold = 5  → safe to try 2-3 passwords per round
Lockout duration  = 30 → wait 31+ minutes between rounds
Auto-unlock = yes      → mistakes recoverable (but still avoid)
Auto-unlock = no       → extreme caution, admin must manually unlock

No policy available?
→ Max 1-2 spray attempts total
→ Wait 1+ hour between attempts
→ Or ask the client directly
```

---

## Exam Notes

- Run policy enumeration before ANY spraying — no exceptions
- SMB NULL session and LDAP anon bind = unauthenticated, no creds needed
- `nxc smb --pass-pol` is fastest when you have creds
- `enum4linux-ng -oA` exports JSON — useful for feeding into scripts
- Default domain policy has lockout threshold of 0 — spraying is safe but still be careful
- Complexity enabled + 8 char min → Welcome1, Password1, Winter2024 all meet requirements
