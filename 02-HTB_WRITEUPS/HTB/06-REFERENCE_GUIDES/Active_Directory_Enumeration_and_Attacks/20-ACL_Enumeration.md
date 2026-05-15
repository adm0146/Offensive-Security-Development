# Section 20 — ACL Enumeration

---

## QUICK REFERENCE — Targeted ACL Enumeration

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# STEP 1 — Get SID of user you control
$sid = Convert-NameToSid wley

# STEP 2 — Find all objects YOUR user has rights over (human-readable)
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# STEP 3 — Chain: get SID of next target, repeat
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2}

# Check if a group is nested into another group
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```
> Finds all Active Directory (AD) objects that a given user has rights over. `Convert-NameToSid` turns a username into a SID for filtering. `-ResolveGUIDs` turns raw GUID values into readable right names like `GenericWrite`. Replace `wley` with any user you control.

**Key flag:** `-ResolveGUIDs` — converts GUID values to human-readable ACE type names. Always use it.

---

## Lab Attack Chain (INLANEFREIGHT.LOCAL)

**Starting point:** `wley` / `transporter@4` (captured via Responder in section 06)

```
wley
  └─ ForceChangePassword → damundsen
       └─ GenericWrite → Help Desk Level 1 group
            └─ (nested into) Information Technology group
                 └─ GenericAll → adunn
                      └─ DS-Replication-Get-Changes + DS-Replication-Get-Changes-In-Filtered-Set
                           └─ DCSync → dump all hashes → Domain compromise
```

**Full enumeration chain:**
```powershell
# wley's rights
$sid = Convert-NameToSid wley
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
# Result: ForceChangePassword over CN=Dana Amundsen (damundsen)

# damundsen's rights
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2}
# Result: GenericWrite over Help Desk Level 1 group

# Where is Help Desk Level 1 nested?
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
# Result: nested into Information Technology

# Information Technology group's rights
$itgroupsid = Convert-NameToSid "Information Technology"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid}
# Result: GenericAll over adunn (Angela Dunn)

# adunn's rights
$adunnsid = Convert-NameToSid adunn
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid}
# Result: DS-Replication-Get-Changes + DS-Replication-Get-Changes-In-Filtered-Set over domain
#         → DCSync capable
```
> Walks the full ACL chain step by step. Each iteration finds what rights the current user has, then pivots to the next account. Swap in any username to trace a different attack path.

---

## Lab Answers

| Question | Answer |
|----------|--------|
| GUID for User-Force-Change-Password | `00299570-246d-11d0-a768-00aa006e0529` |
| Flag for human-readable ObjectAceType | `-ResolveGUIDs` |
| damundsen's rights over Help Desk Level 1 | `GenericWrite` |
| forend's rights over dpayne | `GenericAll` |

**Enumerating forend → dpayne:**
```powershell
$sid = Convert-NameToSid forend
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} | ? {$_.ObjectDN -match "dpayne"}
```
> Filters ACL results to only show rights that `forend` has over objects containing "dpayne" in their distinguished name. Add `| ? {$_.ObjectDN -match "TARGET"}` to narrow any enumeration to one object.

---

## Key Commands

```powershell
# Targeted — preferred method
$sid = Convert-NameToSid TARGET_USER
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Broad scan (noisy, slow — last resort)
Find-InterestingDomainAcl

# Resolve a GUID manually (if -ResolveGUIDs not available)
$guid = "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | Select Name,DisplayName,rightsGuid | ? {$_.rightsGuid -eq $guid}

# Native PS alternative (no PowerView — slow)
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {
    get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access |
    Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}
}
```
> Three enumeration options. Use the targeted SID method first — it is fast and quiet. `Find-InterestingDomainAcl` is slow and noisy; use it as a last resort. The native PS loop at the bottom works without PowerView but is very slow on large domains.

---

## BloodHound — Finding ACL Paths

```
1. Set compromised user as starting node
2. Node Info tab → Outbound Control Rights
3. "First Degree Object Control" = direct ACE rights
4. "Transitive Object Control" = full chained attack path
5. Right-click edge → Help → abuse instructions + opsec notes
```

**Pre-built query:** "Find Principals with DCSync Rights" → confirms adunn has replication rights

---

## Important GUIDs

| GUID | Right |
|------|-------|
| `00299570-246d-11d0-a768-00aa006e0529` | User-Force-Change-Password |
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All |

---

## Exam Notes

- Always use `-ResolveGUIDs` — raw GUIDs are unreadable and require manual lookup
- Targeted enumeration by SID is far faster than `Find-InterestingDomainAcl`
- Check nested group membership — `GenericWrite` on a group + group is nested = inherited rights
- `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-In-Filtered-Set` = DCSync capable
- BloodHound "Transitive Object Control" shows the full chain instantly — run it first
- Attack chain in this lab: wley → damundsen → Help Desk L1 → IT group → adunn → DCSync
