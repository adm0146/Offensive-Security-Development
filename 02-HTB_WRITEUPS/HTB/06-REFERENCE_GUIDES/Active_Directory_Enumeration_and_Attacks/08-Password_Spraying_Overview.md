# Section 8 — Password Spraying Overview

## What Is Password Spraying

One password → many usernames. Opposite of brute force (many passwords → one username).

**Why it works:** Organizations often have weak default/seasonal passwords. A single common password tried against every account is unlikely to trigger lockouts when done carefully.

**Goal:** Land a low-privilege domain user account → opens BloodHound, further enumeration, and attack chains.

---

## Spraying vs Brute Force

| | Password Spray | Brute Force |
|--|---------------|------------|
| Passwords per user | 1 (or very few) | Many |
| Lockout risk | Low (if controlled) | High |
| Speed | Slow by design | Fast |
| Use case | Initial foothold | Known target with weak policy |

---

## Lockout Risk — Critical Considerations

- **Know the policy before spraying** — enumerate it if you have any access
- Common policy: 5 bad attempts → lockout, 30-minute auto-unlock
- **Safe rule of thumb:** wait 2-4 hours between spray rounds if policy unknown
- One targeted spray with a single common password is often the safest approach
- Locking out hundreds of accounts = major incident during a pentest — career-ending on a bad day

**Never spray without understanding the lockout threshold.**

---

## Building a Username List

Multiple sources — combine them all:

```bash
# 1. Kerbrute against DC with known username wordlists
kerbrute userenum -d DOMAIN --dc DC_IP jsmith.txt -o valid_users.txt

# 2. LinkedIn scraping
python3 linkedin2username.py -u EMAIL -p PASS -c "Company Name"

# 3. Google dorks for document metadata (author field leaks AD username format)
filetype:pdf inurl:target.com
exiftool document.pdf   # check Author field

# 4. OSINT from external recon phase
# 5. Statistically-likely-usernames repo (jsmith.txt, jsmith2.txt)
```

**Scenario 2 lesson:** If the org uses a predictable format (even GUIDs), generate all combinations with a script:
```bash
#!/bin/bash
for x in {{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}
    do echo $x;
done
```
Then feed to Kerbrute → you get every valid account, not just 40-60%.

---

## Common Spray Passwords

Start with these — they work constantly in real environments:

```
Welcome1
Welcome1!
Password1
Password123
Winter2024  (current season/year)
Spring2024
Company@123
CompanyName1  (company name + number)
```

---

## Spray Workflow

```
1. Enumerate password policy (if possible)
2. Build username list (Kerbrute + LinkedIn + metadata)
3. Pick ONE common password
4. Spray — one attempt per user
5. Wait (30 min minimum, ideally 2-4 hours)
6. Repeat with next password if needed
7. Take any hits → test against all exposed services (SMB, RDP, OWA, VPN)
```

---

## Real-World Attack Chains from Spraying

**Scenario 1:**
```
Kerbrute enum (jsmith.txt + LinkedIn) → valid user list
→ Spray Welcome1 → 2 low-priv hits
→ BloodHound with creds → attack path identified → domain compromise
```

**Scenario 2:**
```
PDF metadata → GUID username format discovered
→ Generate all 1.6M combos → Kerbrute enum → ALL domain accounts
→ Spray → valid creds → RBCD + Shadow Credentials attack → domain compromise
```

---

## Exam Notes

- Spraying = one password, many users — never the reverse during an assessment
- Always enumerate the password policy first — asking the client is acceptable
- Document metadata (exiftool) is a reliable source for username format
- Even two low-priv hits from spraying is enough to run BloodHound and find a path
- Spray results feed directly into: SMB, RDP, OWA, VPN, Citrix, WinRM testing
- Next section covers enumerating the password policy before spraying
