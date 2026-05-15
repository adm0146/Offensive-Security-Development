# Section 15 — Credentialed Enumeration from Windows

---

## QUICK REFERENCE — Full Workflow

```powershell
# STEP 1 — AD Module (built-in, stealthy)
Import-Module ActiveDirectory
Get-ADDomain
Get-ADTrust -Filter *
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# STEP 2 — PowerView (detailed)
Import-Module .\PowerView.ps1
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
Find-DomainUserLocation

# STEP 3 — Snaffler (share pillaging)
.\Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data

# STEP 4 — SharpHound (BloodHound collection)
.\SharpHound.exe -c All --zipfilename ILFREIGHT
# → Upload zip to BloodHound GUI
```
> The AD Module is built into Windows — no tool upload needed, so it is stealthy. `Get-ADUser -Filter {ServicePrincipalName -ne "$null"}` finds Kerberoastable accounts. PowerView gives deeper information. `Find-DomainUserLocation` shows where domain users are currently logged in. Snaffler crawls accessible shares looking for credentials. SharpHound collects data for BloodHound.

**Tool location:** `C:\Tools\`

---

## Lab Findings

### Snaffler — Credentials in web.config
```
{Red} \\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\web.config
connectionString="server=ACADEMY-EA-DB01;database=Employees;uid=sa;password=ILFREIGHTDB01!;"
```
- **SA account:** `sa` / `ILFREIGHTDB01!` on ACADEMY-EA-DB01

### SharpHound — Kerberoastable Accounts
- Collected 3809 objects with `-c All`
- Analysis → "List All Kerberoastable Accounts" → **13 accounts** in INLANEFREIGHT.LOCAL

---

## AD PowerShell Module (Stealthy — Built-in)

```powershell
Import-Module ActiveDirectory

Get-ADDomain                                  # domain info, SID, child domains, FSMO roles
Get-ADTrust -Filter *                          # trust relationships
Get-ADGroup -Filter * | select name           # all groups
Get-ADGroup -Identity "Backup Operators"      # specific group info
Get-ADGroupMember -Identity "Backup Operators" # group members
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName  # Kerberoastable
```
> The built-in ActiveDirectory module is the stealthiest option on Windows. `Get-ADDomain` shows the domain's Security Identifier (SID), child domains, and Flexible Single Master Operations (FSMO) role holders. `Get-ADTrust` lists trust relationships. The last command finds all accounts with a Service Principal Name (SPN) set — those are Kerberoastable.

**What to look for:**
- `ChildDomains` → additional domains to pivot into
- `BiDirectional + ForestTransitive` trust → cross-forest attack potential
- `Backup Operators` members → can backup DC files → path to domain compromise

---

## PowerView

```powershell
Import-Module .\PowerView.ps1
# or: . .\PowerView.ps1
```
> Dot-sourcing (`. .\PowerView.ps1`) loads the script into the current session scope. Either form works. Run from `C:\Tools`.

| Command | Use |
|---------|-----|
| `Get-DomainUser -Identity USER -Domain DOMAIN` | Detailed user info |
| `Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName` | Kerberoastable users |
| `Get-DomainGroupMember -Identity "Domain Admins" -Recurse` | DA members (recursive) |
| `Get-DomainTrustMapping` | All trust relationships |
| `Test-AdminAccess -ComputerName HOST` | Check local admin on host |
| `Find-DomainUserLocation` | Where users are currently logged in |
| `Find-DomainShare` | All accessible shares |
| `Find-InterestingDomainShareFile` | Sensitive files on shares |
| `Find-LocalAdminAccess` | Hosts where you have local admin |
| `Find-InterestingDomainAcl` | ACL misconfigurations |

**Key user fields:**
| Field | Significance |
|-------|-------------|
| `admincount: 1` | Was/is privileged (AdminSDHolder protected) |
| `DONT_REQ_PREAUTH` set | AS-REP roastable |
| `ServicePrincipalName` set | Kerberoastable |

---

## SharpView (When PowerShell Is Blocked)

```powershell
.\SharpView.exe Get-DomainUser -Identity forend
.\SharpView.exe Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```
> SharpView is a compiled C# version of PowerView. It uses the same function names and parameters. Use it when PowerShell Constrained Language Mode blocks the script-based PowerView.

Same functions as PowerView — C# binary, works when constrained language mode blocks PS.

---

## Snaffler

```powershell
.\Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```
> `-s` enables share discovery, `-d` sets the domain to search, `-o` writes results to a log file, `-v data` shows the actual file content for interesting finds. Review `{Red}` entries first — those are highest priority.

**Color coding:**
- `{Red}` = high interest (keys, dumps, credentials) → investigate immediately
- `{Black}` = interesting (config files, password managers)
- `{Green}` = accessible share

---

## SharpHound

```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT              # full collection
.\SharpHound.exe -c DCOnly --zipfilename ILFREIGHT_stealth   # DC-only (stealthy)
.\SharpHound.exe -c All -d inlanefreight.local --zipfilename ILFREIGHT
```
> `-c All` collects all data types. `-c DCOnly` only queries the DC — much less noisy, useful when you want to avoid touching every workstation. The zip file is ready to upload directly into the BloodHound GUI.

Upload zip → BloodHound GUI → Upload Data

**Key BloodHound queries:**
- Find Shortest Paths To Domain Admins
- Find Computers where Domain Users are Local Admin
- Find Computers with Unsupported Operating Systems (EternalBlue candidates)
- Find Principals with DCSync Rights
- Find AS-REP Roastable Users
- Find Kerberoastable Users

---

## Trust Map (INLANEFREIGHT Lab)

| Source | Target | Type | Direction |
|--------|--------|------|-----------|
| INLANEFREIGHT.LOCAL | LOGISTICS.INLANEFREIGHT.LOCAL | Within forest | Bidirectional |
| INLANEFREIGHT.LOCAL | FREIGHTLOGISTICS.LOCAL | Forest transitive | Bidirectional |

`ForestTransitive: True` + `Bidirectional` = cross-forest attack possible

---

## Exam Notes

- AD PowerShell module = stealthy, built-in, no tools needed
- PowerView `-Recurse` = catches nested DAs that simple enumeration misses
- SharpView = use when PS constrained/blocked
- Snaffler Red = investigate immediately
- `Find-DomainUserLocation` = find where DAs are currently logged in → lateral movement
- Document all tools transferred to/from hosts for client deconfliction
