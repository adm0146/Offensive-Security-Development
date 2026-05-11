# Section 09 — Enumerating the Password Policy

---

## QUICK REFERENCE — Get the Policy

```bash
# Credentialed (fastest)
nxc smb 172.16.5.5 -u USER -p PASS --pass-pol

# SMB NULL session (no creds)
rpcclient -U "" -N 172.16.5.5    # then: getdompwinfo
enum4linux -P 172.16.5.5
enum4linux-ng -P 172.16.5.5 -oA output

# LDAP anonymous bind (no creds)
ldapsearch -H ldap://172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts
```

---

## Lab Results (INLANEFREIGHT.LOCAL)

| Setting | Value | Implication |
|---------|-------|-------------|
| Min password length | 8 | Welcome1, Password1 meet requirements |
| Lockout threshold | 5 | Safe to try 3 passwords before waiting |
| Lockout duration | 30 min | Auto-unlocks — wait 31 min between rounds |
| Max password age | Not set | Passwords never expire — breach data may work |
| Complexity | Enabled | Needs 3/4 of: upper, lower, number, special |
| Manual unlock | No | Auto-unlock — but still avoid lockouts |

**Decision:** threshold=5 → try 3 passwords max → wait 31 min → repeat

---

## Method 1 — Credentialed (Linux)

```bash
nxc smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

---

## Method 2 — SMB NULL Session (No Creds)

```bash
# rpcclient
rpcclient -U "" -N 172.16.5.5
# inside: getdompwinfo

# enum4linux
enum4linux -P 172.16.5.5

# enum4linux-ng (preferred — cleaner, JSON export)
enum4linux-ng -P 172.16.5.5 -oA output
cat output.json
```

---

## Method 3 — LDAP Anonymous Bind (No Creds)

```bash
ldapsearch -H ldap://172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

Key fields: `minPwdLength`, `lockoutThreshold`, `lockoutDuration`, `pwdProperties`

---

## Method 4 — From Windows

```cmd
net accounts
```

```powershell
Import-Module .\PowerView.ps1
Get-DomainPolicy
```

**Windows error codes during spraying:**
| Error | Meaning |
|-------|---------|
| 1331 | Account disabled |
| 1326 | Wrong password |
| 1909 | Account locked out |

---

## Default Domain Policy (new domain, never changed)

| Setting | Default | Impact |
|---------|---------|--------|
| Lockout threshold | **0 (no lockout!)** | Spraying is safe |
| Max password age | 42 days | |
| Min length | 7 | |
| Complexity | Enabled | |

---

## Spraying Decision Framework

```
Threshold = 5  → max 3 attempts per round
Duration  = 30 → wait 31 min between rounds
Auto-unlock = yes  → mistakes are recoverable (but still avoid)
Auto-unlock = no   → extreme caution — admin must manually unlock

Unknown policy?
→ Max 1-2 attempts total
→ Wait 1+ hour between attempts
→ Or ask the client directly
```

---

## Exam Notes

- Run policy enumeration **before any spraying** — no exceptions
- SMB NULL session and LDAP anon bind = no creds needed
- `nxc smb --pass-pol` is fastest when credentialed
- Default policy has lockout = 0 — spraying safe but still be careful
- Complexity + 8 char min → Welcome1, Password1, Winter2025 all qualify
