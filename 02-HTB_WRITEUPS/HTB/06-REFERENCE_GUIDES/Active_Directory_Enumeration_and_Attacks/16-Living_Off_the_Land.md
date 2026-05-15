# Section 16 — Living Off the Land

> Use when tools can't be dropped — managed devices, EDR blocking execution, no internet access.

---

## QUICK REFERENCE — Full Workflow

```powershell
# STEP 1 — Host state
systeminfo                          # OS, patches, network — fewest logs
qwinsta                             # who else is logged in?

# STEP 2 — Network state
arp -a                              # hosts this machine talked to → pivot targets
route print                         # known subnets
ipconfig /all

# STEP 3 — Domain overview
echo %logonserver%
wmic ntdomain get Caption,DnsForestName,DomainName,DomainControllerAddress

# STEP 4 — Domain enumeration
net group "Domain Admins" /domain
net group "Domain Controllers" /domain
net user /domain
net accounts /domain

# STEP 5 — Targeted dsquery
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -attr sAMAccountName  # DCs
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName  # No password required

# STEP 6 — PS history (may contain plaintext creds)
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
```
> All of these use built-in Windows tools — no file uploads needed. `systeminfo` gives OS version and patch level in one command. `arp -a` shows hosts the machine recently talked to without running a noisy scan. `wmic ntdomain` lists DC addresses. The `dsquery` filters use User Account Control (UAC) bit flags to find DCs (bit 8192) and accounts with no password required (bit 32). The PowerShell history file often contains plaintext passwords typed by admins.

---

## Lab Attack Chain (ACADEMY-EA-MS01 / INLANEFREIGHT.LOCAL)

```powershell
# Q1 — Defender AMProductVersion
Get-MpComputerStatus
# AMProductVersion: 4.18.2109.6

# Q2 — Domain user in local administrators
net localgroup administrators
# Result: INLANEFREIGHT\adunn explicitly listed

# Q3 — Flag in disabled admin account description
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -attr distinguishedName description
# Betty Ross (IT Admins OU, disabled) — description: HTB{LD@P_I$_W1ld}
```
> `Get-MpComputerStatus` returns the Defender version string. `net localgroup administrators` lists all local admins including domain accounts. The `dsquery` filter matches UAC bit 2 (disabled accounts) and returns both the distinguished name and description — description fields often contain notes or even passwords left by admins.

**Lab answers:** AMProductVersion = `4.18.2109.6` | Local admin = `adunn` | Flag = `HTB{LD@P_I$_W1ld}`

---

## Host Recon

```cmd
hostname
systeminfo                                         # everything in one command — fewer logs
wmic qfe get Caption,Description,HotFixID,InstalledOn   # patches
ipconfig /all
set                                                # environment variables
echo %USERDOMAIN%
echo %logonserver%
```
> `systeminfo` is the most efficient — it runs one query and returns OS version, patches, domain, and network config all at once, generating fewer log entries than running each separately. `wmic qfe` lists installed hotfixes. `set` shows all environment variables including domain and username details.

---

## PowerShell Enumeration

```powershell
Get-Module
Get-ExecutionPolicy -List
Set-ExecutionPolicy Bypass -Scope Process         # bypasses for current session only
Get-ChildItem Env: | ft Key,Value                 # all environment variables
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt  # PS history — gold
```
> `Get-ExecutionPolicy -List` shows the policy at every scope. `Bypass -Scope Process` only affects the current terminal session — it resets when the window closes. `Get-ChildItem Env:` lists all environment variables in a clean table. The history file is a top priority — admins frequently type passwords directly in the console.

---

## PowerShell Downgrade (Kills Script Block Logging)

```powershell
Get-host              # confirm version 5.1
powershell.exe -version 2
Get-host              # confirm version 2.0
```
> `-version 2` launches a legacy PowerShell 2 process. Script Block Logging only exists in PS 5+, so downgrading stops those logs. However, the downgrade command itself is still logged before the switch.

**Caveat:** The downgrade command itself still logs. Defenders see logs stop = indicator.

---

## Firewall & Defender

```powershell
netsh advfirewall show allprofiles
sc query windefend
Get-MpComputerStatus | select RealTimeProtectionEnabled, AMServiceEnabled
```
> `netsh advfirewall` shows rules for Domain, Private, and Public profiles. `sc query windefend` checks if the Windows Defender service is running. `Get-MpComputerStatus` gives the detailed status — combine with the earlier foothold check.

---

## Network Enumeration (Find Pivot Targets)

```cmd
arp -a          # hosts this machine communicated with — find targets without scanning
route print     # known subnets and gateways
ipconfig /all
```
> `arp -a` shows the ARP cache — hosts this machine recently connected to. This gives you real live targets without running a noisy scan. `route print` shows the routing table, which reveals additional internal subnets you can pivot into.

---

## WMI Commands

```cmd
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
```
> All WMI (Windows Management Instrumentation) queries — no extra tools needed. `/format:List` outputs one field per line, which is easier to read. `ntdomain` returns DC addresses and domain info. `useraccount` and `group` enumerate local accounts and groups.

---

## Net Commands

```cmd
net accounts /domain              # domain password + lockout policy
net group /domain                 # all domain groups
net group "Domain Admins" /domain # DA members
net group "Domain Controllers" /domain
net user /domain                  # all domain users
net user <USER> /domain           # specific user
net localgroup administrators     # local admins (includes DA)
net view /all /domain             # shares across domain
```
> Standard `net` commands. All built into Windows with no privileges needed. Replace `<USER>` with an actual username to get details on a specific account. **Endpoint Detection and Response (EDR) evasion:** Replace `net` with `net1` — same output, but avoids string matching rules that trigger on the literal word `net`.

---

## Dsquery

Native binary — present on all modern Windows systems at `C:\Windows\System32\dsquery.dll`.

```powershell
dsquery user
dsquery computer
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"              # all objects in OU

# DCs (UAC bit 8192 = SERVER_TRUST_ACCOUNT)
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -attr sAMAccountName

# No password required (UAC bit 32 = PASSWD_NOTREQD)
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Disabled accounts (UAC bit 2)
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -attr distinguishedName description
```
> `dsquery` is a native binary on all modern Windows systems — no upload needed. The OID `1.2.840.113556.1.4.803` is a bitwise AND match rule. The number after `:=` is the User Account Control (UAC) bit to match. Swap `8192` for `32` or `2` to find different account types. The `-attr` flag controls which fields are returned.

---

## LDAP Filter Reference

**OID Matching Rules:**
| OID | Behavior |
|-----|----------|
| `1.2.840.113556.1.4.803` | Exact bit match |
| `1.2.840.113556.1.4.804` | Any bit in chain matches |
| `1.2.840.113556.1.4.1941` | Match on Distinguished Name (membership search) |

**Common UAC Bit Values:**
| Value | Attribute |
|-------|-----------|
| 2 | Account Disabled |
| 32 | PASSWD_NOTREQD |
| 512 | Normal Account |
| 8192 | Domain Controller |
| 65536 | Password Never Expires |

**Logical operators:** `&` = AND | `|` = OR | `!` = NOT

---

## Exam Notes

- `systeminfo` = one command, fewer logs than running each query separately
- `net1` = same as `net` — avoids EDR string detection
- `arp -a` + `route print` = identify pivot targets without scanning
- PS v2 downgrade kills Script Block Logging — downgrade command itself still logs
- `dsquery` = native, no tool drop needed
- Disabled accounts can have sensitive data in description fields — always check
- PS history = gold — admins often type passwords directly in console
