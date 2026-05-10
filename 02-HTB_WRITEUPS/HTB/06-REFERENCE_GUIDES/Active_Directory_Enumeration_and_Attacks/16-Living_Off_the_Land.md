# Section 16 — Living Off the Land

## Why This Matters

When tools can't be dropped on a host (managed device, no internet, EDR blocks execution), native Windows tools can still enumerate the full AD environment. This approach also generates fewer alerts since these commands blend with normal admin activity.

---

## Host Recon (Basic Commands)

```cmd
hostname                                          # PC name
[System.Environment]::OSVersion.Version           # OS version (PS)
wmic qfe get Caption,Description,HotFixID,InstalledOn  # Patches/hotfixes
ipconfig /all                                     # Network adapters
set                                               # Environment variables (CMD)
echo %USERDOMAIN%                                 # Domain name (CMD)
echo %logonserver%                                # DC the host checks in with (CMD)
systeminfo                                        # All of the above in one shot
```

**Use `systeminfo` to generate fewer logs** — one command vs. many.

---

## PowerShell Enumeration

```powershell
Get-Module                                        # Loaded modules (check for ActiveDirectory)
Get-ExecutionPolicy -List                         # Execution policy per scope
Set-ExecutionPolicy Bypass -Scope Process         # Bypass for current process only (reverts on exit)
Get-ChildItem Env: | ft Key,Value                 # All environment variables
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt  # PS command history
```

**PS history is gold** — may contain passwords or paths to config files with credentials.

---

## PowerShell Downgrade (Evade Script Block Logging)

Script Block Logging only exists in PowerShell 3.0+. Downgrading to v2 stops logging.

```powershell
Get-host             # Check current version (5.1)
powershell.exe -version 2
Get-host             # Confirm version: 2.0
```

**Caveat:** The `powershell.exe -version 2` command itself will appear in logs — evidence of downgrade. Defenders monitoring for this will notice the logs stop. Use with awareness.

---

## Firewall & Defender Checks

```powershell
# Firewall status (all profiles)
netsh advfirewall show allprofiles

# Defender service status (CMD)
sc query windefend

# Defender config (PS)
Get-MpComputerStatus
Get-MpComputerStatus | select RealTimeProtectionEnabled, AMServiceEnabled
```

---

## Who Else Is Logged In?

```powershell
qwinsta
```

Check before taking noisy actions — another user on the host may notice popups or disconnections and report it.

---

## Network Enumeration

```powershell
arp -a                           # ARP table — hosts the machine has communicated with
route print                      # Routing table — known networks, potential pivot targets
ipconfig /all                    # Adapter details, DNS, gateway
```

**`arp -a` + `route print`** reveal hosts and subnets reachable from this host — critical for lateral movement planning in black-box assessments.

---

## WMI Commands

```cmd
wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list

# Domain + trust overview
wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
```

Lab result from `wmic ntdomain`:
| Domain | Forest | DC Address |
|--------|--------|------------|
| INLANEFREIGHT | INLANEFREIGHT.LOCAL | \\172.16.5.5 |
| LOGISTICS | INLANEFREIGHT.LOCAL | \\172.16.5.240 |
| FREIGHTLOGISTIC | FREIGHTLOGISTICS.LOCAL | \\172.16.5.238 |

---

## Net Commands

```cmd
net accounts                                  # Local password policy
net accounts /domain                          # Domain password + lockout policy
net group /domain                             # All domain groups
net group "Domain Admins" /domain             # DA members
net group "domain computers" /domain          # Domain-joined PCs
net group "Domain Controllers" /domain        # DC computer accounts
net groups /domain                            # All domain groups (alias)
net localgroup                                # Local groups
net localgroup administrators /domain        # Local admins (includes Domain Admins)
net user /domain                              # All domain users
net user <USER> /domain                       # Specific user details
net user %username%                           # Current user info
net share                                     # Current shares
net view /all /domain                         # Shares across domain
net view \<computer> /ALL                     # Shares on specific host
net view /domain                              # PCs in domain
```

**EDR evasion:** Replace `net` with `net1` — same functionality, avoids the `net` string trigger.

```cmd
net1 group "Domain Admins" /domain
```

---

## Dsquery

Built into Windows — exists on any host with AD DS role installed. The DLL (`dsquery.dll`) is present on all modern Windows systems at `C:\Windows\System32\dsquery.dll`.

```powershell
# All users
dsquery user

# All computers
dsquery computer

# All objects in an OU (wildcard)
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

# Users with PASSWD_NOTREQD set (UAC bit 32)
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Find Domain Controllers (UAC bit 8192 = SERVER_TRUST_ACCOUNT)
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```

---

## LDAP Filter Syntax (dsquery + ldapsearch + AD PS Module)

### OID Matching Rules

| OID | Behavior |
|-----|----------|
| `1.2.840.113556.1.4.803` | Bit must match **exactly** — single attribute matching |
| `1.2.840.113556.1.4.804` | Match if **any** bit in the chain matches — multiple attributes |
| `1.2.840.113556.1.4.1941` | Match on **Distinguished Name** — searches ownership/membership |

### Logical Operators

| Operator | Symbol | Example |
|----------|--------|---------|
| AND | `&` | `(&(objectClass=user)(attribute=value))` |
| OR | `\|` | `(\|(objectClass=user)(objectClass=computer))` |
| NOT | `!` | `(&(objectClass=user)(!attribute=value))` |

### Common UAC Bit Values

| Value | Attribute |
|-------|-----------|
| 2 | Account Disabled |
| 32 | PASSWD_NOTREQD |
| 64 | Password Can't Change |
| 512 | Normal Account |
| 8192 | Domain Controller (SERVER_TRUST_ACCOUNT) |
| 65536 | Password Never Expires |

### Example Filters

```powershell
# Users where password is not required
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))

# Users where password can't change
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))

# Users where password can change (NOT flag)
(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))

# Domain Controllers
(userAccountControl:1.2.840.113556.1.4.803:=8192)
```

---

## Living Off the Land Workflow

```powershell
# 1. Host state
systeminfo
qwinsta                        # who else is here?

# 2. Network state
arp -a
route print
ipconfig /all

# 3. Domain overview
echo %USERDOMAIN%
echo %logonserver%
wmic ntdomain get Caption,DnsForestName,DomainName,DomainControllerAddress

# 4. Domain enumeration
net group "Domain Admins" /domain
net group "Domain Controllers" /domain
net user /domain
net accounts /domain

# 5. Dsquery for specific targets
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -attr sAMAccountName  # DCs
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName  # No password required

# 6. PS history (look for creds)
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
```

---

## Lab Findings (ACADEMY-EA-MS01 / INLANEFREIGHT.LOCAL)

### Q1 — Defender AMProductVersion
```powershell
Get-MpComputerStatus
# AMProductVersion : 4.18.2109.6
```

### Q2 — Domain User in Local Administrators
```cmd
net localgroup administrators
```
Output:
```
Administrator
INLANEFREIGHT\adunn          ← explicitly listed domain user
INLANEFREIGHT\Domain Admins
INLANEFREIGHT\Domain Users
```
**Answer:** `adunn`

### Q3 — Flag in Disabled Admin Account Description
Goal: find disabled accounts with admin privileges that have a flag in their description field.

UAC bit 2 = Account Disabled. Use dsquery to filter disabled users and show their description:

```powershell
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -attr distinguishedName description
```

Result:
```
CN=Betty Ross,OU=IT Admins,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
description: HTB{LD@P_I$_W1ld}
```

**Flag:** `HTB{LD@P_I$_W1ld}`
- Account: Betty Ross (disabled)
- OU: IT Admins — confirms privileged account
- Finding method: UAC bitmask filter via dsquery, no tools dropped

---

## Exam Notes

- `systeminfo` = one command, fewer logs than running each query separately
- PS v2 downgrade kills Script Block Logging — evidence of the downgrade still appears
- `net1` = same as `net` but avoids string-based EDR triggers
- `arp -a` + `route print` = identify pivot targets without scanning
- `dsquery` exists natively — no tool drop needed
- LDAP UAC bit 2 = Disabled, 32 = PASSWD_NOTREQD, 8192 = DC, 65536 = Password Never Expires
- OID `.803` = exact bit match, `.804` = any bit match
- Check PS history immediately after foothold — admins often type passwords directly
- Disabled accounts can still have sensitive data in description fields — always check
