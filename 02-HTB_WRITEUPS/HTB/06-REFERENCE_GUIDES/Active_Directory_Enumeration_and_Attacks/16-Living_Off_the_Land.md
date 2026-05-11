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

---

## PowerShell Enumeration

```powershell
Get-Module
Get-ExecutionPolicy -List
Set-ExecutionPolicy Bypass -Scope Process         # bypasses for current session only
Get-ChildItem Env: | ft Key,Value                 # all environment variables
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt  # PS history — gold
```

---

## PowerShell Downgrade (Kills Script Block Logging)

```powershell
Get-host              # confirm version 5.1
powershell.exe -version 2
Get-host              # confirm version 2.0
```

**Caveat:** The downgrade command itself still logs. Defenders see logs stop = indicator.

---

## Firewall & Defender

```powershell
netsh advfirewall show allprofiles
sc query windefend
Get-MpComputerStatus | select RealTimeProtectionEnabled, AMServiceEnabled
```

---

## Network Enumeration (Find Pivot Targets)

```cmd
arp -a          # hosts this machine communicated with — find targets without scanning
route print     # known subnets and gateways
ipconfig /all
```

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

**EDR evasion:** Replace `net` with `net1` — same output, avoids the `net` string trigger.

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
