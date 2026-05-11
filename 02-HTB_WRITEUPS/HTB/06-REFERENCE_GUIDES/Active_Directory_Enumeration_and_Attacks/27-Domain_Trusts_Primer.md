# Section 27 — Domain Trusts Primer

> Concept + enumeration section. No attacks here — those are in Sections 28–30.
> All enumeration run from ACADEMY-EA-MS01 (RDP: htb-student / Academy_student_AD!)

---

## QUICK REFERENCE

```powershell
# Built-in AD module — enumerate all trusts from current domain
Import-Module activedirectory
Get-ADTrust -Filter *

# PowerView — cleaner output, same information
Import-Module .\PowerView.ps1
Get-DomainTrust

# PowerView — full trust map (includes trusts visible from remote domains)
Get-DomainTrustMapping

# Query users in a trusted domain
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName

# netdom — built-in Windows tool, no imports needed
netdom query /domain:inlanefreight.local trust
netdom query /domain:inlanefreight.local dc
netdom query /domain:inlanefreight.local workstation
```

---

## Trust Types Reference

| Trust Type | Description | Transitive? | Direction |
|-----------|-------------|-------------|-----------|
| Parent-child | Between parent and child domain within same forest | Yes | Bidirectional |
| Cross-link | Between two child domains to speed up auth (skips root) | Yes | Bidirectional |
| Tree-root | Between forest root and a new tree root domain | Yes | Bidirectional |
| Forest | Between two separate forest root domains | Yes | One-way or Bidirectional |
| External | Between domains in separate forests, no forest trust | No | One-way or Bidirectional |
| ESAE | Bastion forest used to manage AD (Red Forest model) | No | One-way |

**Transitivity explained simply:**
- Transitive: Trust extends through the chain. If A trusts B and B trusts C, then A automatically trusts C.
- Non-transitive: Trust stops at the direct relationship. A trusts B, but that says nothing about C.

**Direction explained:**
- One-way: Users in the *trusted* domain can access resources in the *trusting* domain. Not the reverse.
- Bidirectional: Users in either domain can access resources in the other.

---

## Lab Environment Trust Map

```
INLANEFREIGHT.LOCAL (forest root)
  ├── LOGISTICS.INLANEFREIGHT.LOCAL  ← child domain, WITHIN_FOREST, Bidirectional
  └── FREIGHTLOGISTICS.LOCAL         ← separate forest, FOREST_TRANSITIVE, Bidirectional
```

- LOGISTICS is a child domain — lives inside the same forest as INLANEFREIGHT.LOCAL
- FREIGHTLOGISTICS is a completely separate forest with a forest trust — different security boundary

---

## Step 1 — Enumerate Trusts with Built-in AD Module

```powershell
Import-Module activedirectory
# Load the built-in Active Directory PowerShell module
# Available on any machine with RSAT (Remote Server Administration Tools) installed
# Does not require downloading anything — useful when you can't run PowerView
```

```powershell
Get-ADTrust -Filter *
# -Filter * = return ALL trust objects — no filtering
# Output fields to focus on:
#   Direction = Bidirectional / Inbound / Outbound
#   IntraForest = True means this is a child domain within the same forest
#   ForestTransitive = True means this is a forest-level trust (crosses forest boundary)
#   SIDFilteringQuarantined = True means SID history attacks are blocked (more secure)
#   TGTDelegation = True means TGT delegation across this trust is allowed (dangerous)
```

Key fields decoded:
- `IntraForest: True` = child/parent relationship within the same forest = same security boundary
- `ForestTransitive: True` = separate forest = different security boundary = SID filtering may apply
- `SIDFilteringQuarantined: False` = SID filtering is OFF = SID history attacks may be possible
- `UsesRC4Encryption: False` = trust uses AES keys = harder to forge inter-realm tickets

---

## Step 2 — Enumerate Trusts with PowerView

```powershell
cd C:\Tools
Import-Module .\PowerView.ps1
```

```powershell
Get-DomainTrust
# PowerView wrapper around the same LDAP query as Get-ADTrust
# Cleaner output — shows only the most relevant fields
# TrustAttributes field shows: WITHIN_FOREST (child domain) or FOREST_TRANSITIVE (forest trust)
# TrustDirection field shows: Bidirectional / Inbound / Outbound
```

Lab output interpreted:
```
SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustAttributes : WITHIN_FOREST       ← same forest, child domain
TrustDirection  : Bidirectional       ← users can auth both ways

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustAttributes : FOREST_TRANSITIVE   ← separate forest, forest trust
TrustDirection  : Bidirectional       ← users can auth both ways
```

---

## Step 3 — Full Trust Mapping

```powershell
Get-DomainTrustMapping
# Recursively enumerates trust relationships from ALL domains visible in the current domain's trust chain
# Get-DomainTrust only shows trusts FROM the current domain
# Get-DomainTrustMapping also shows trusts configured in REMOTE domains (e.g. what FREIGHTLOGISTICS trusts)
# Useful for finding indirect paths: A → B → C where you might be able to chain trust abuse
```

---

## Step 4 — Enumerate Users in a Trusted Domain

```powershell
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
# -Domain LOGISTICS.INLANEFREIGHT.LOCAL = query a DIFFERENT domain than your current one
# This works because of the bidirectional trust — your current domain credentials are accepted there
# select SamAccountName = just show usernames, not the full 40-attribute AD object per user
# Use this to find accounts worth targeting in the child domain
```

---

## Step 5 — netdom (No Imports Required)

```cmd
netdom query /domain:inlanefreight.local trust
# netdom = built-in Windows command-line tool for domain operations
# query = retrieve information about the domain
# /domain:inlanefreight.local = query this specific domain
# trust = list all trust relationships for this domain
# No PowerShell, no imports — useful when execution policy blocks scripts
```

```cmd
netdom query /domain:inlanefreight.local dc
# dc = list all domain controllers with accounts in this domain
# Identifies the DCs you'll need to target for attacks
```

```cmd
netdom query /domain:inlanefreight.local workstation
# workstation = list all workstations and servers with accounts in the domain
# Gives a full picture of domain-joined machines — useful for lateral movement planning
```

---

## What to Do with Trust Information

Once you've mapped trusts, these are the attack paths to evaluate (covered in Sections 28–30):

| Scenario | Attack |
|----------|--------|
| Child domain compromised → parent domain | ExtraSids / Golden Ticket with Enterprise Admin SID |
| Bidirectional forest trust | Kerberoasting / ASREPRoasting across trust, foreign group membership abuse |
| SID filtering disabled (SIDFilteringQuarantined: False) | SID history injection attacks |
| TGTDelegation: True | Unconstrained delegation across forest boundary |
| One-way trust (outbound from root) | Users in trusted domain can still enumerate / Kerberoast root domain |

**Enumeration checklist after finding trusts:**
1. Map all trusts with `Get-DomainTrustMapping` — find the full chain
2. Enumerate users in each trusted domain — look for SPNs, pre-auth disabled, admin accounts
3. Enumerate groups in the trusted domain — look for foreign principals (accounts from YOUR domain in their groups)
4. Check SID filtering status — if off, SID history attacks may work
5. Check BloodHound for cross-trust edges (CanRDP, AdminTo, SQLAdmin)

---

## BloodHound

Use the pre-built query: **"Map Domain Trusts"**

- Shows all trust relationships as a visual graph
- Edge direction shows trust direction
- Reveals indirect paths you might miss in raw LDAP output

---

## Lab Answers

| Question | Answer |
|----------|--------|
| Child domain of INLANEFREIGHT.LOCAL | `LOGISTICS.INLANEFREIGHT.LOCAL` |
| Domain with forest transitive trust | `FREIGHTLOGISTICS.LOCAL` |
| Direction of that trust | `Bidirectional` |

---

## Exam Notes

- Always enumerate trusts early — a soft target in a trusted domain may be easier to compromise and lead back to the primary target
- `Get-DomainTrust` = quick view, current domain only
- `Get-DomainTrustMapping` = full recursive map across all visible domains — more complete
- `IntraForest: True` = child domain = same forest = same security boundary (weaker separation)
- `ForestTransitive: True` = separate forest = different security boundary (stronger separation, but bidirectional trusts still allow cross-forest attacks)
- `SIDFilteringQuarantined: False` = SID filtering is off = SID history injection attacks are possible
- `TrustDirection: Bidirectional` = users in BOTH domains can authenticate across — both directions are attackable
- `TrustDirection: Inbound` = external domain trusts US = their users can come here (we can't go there)
- `TrustDirection: Outbound` = we trust them = our users can go there (they can't come here)
- netdom = no imports needed, works when PowerShell execution policy is locked down
- Child domain compromise → parent domain = ExtraSids attack (Section 28) — high impact, one step to Enterprise Admin
