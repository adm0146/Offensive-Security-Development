# Web Enumeration Reference Guide

**Status:** Work in Progress  
**Last Updated:** January 24, 2026

---

## Table of Contents

1. [Initial Reconnaissance](#initial-reconnaissance)
2. [HTTP/HTTPS Detection](#httphttps-detection)
3. [Directory Discovery](#directory-discovery)
4. [Practical CTF Example](#practical-ctf-example-full-web-enumeration-walkthrough)

---

## Initial Reconnaissance

### Web Server Ports
- **Port 80:** HTTP (unencrypted web traffic)
- **Port 443:** HTTPS (encrypted web traffic)
- **High Value Targets:** Web servers present considerable attack surface during penetration tests

### Attack Surface
Web applications are among the highest value targets in penetration testing:
- Large attack surface (multiple pages, endpoints, functionality)
- Often directly accessible to internet
- Common entry points for RCE (Remote Code Execution)
- Potential access to sensitive data
- Server compromise possible through web exploitation

### Quick Port Scanning
```bash
nmap -sV -p 80,443 TARGET_IP
```

### Service Detection
```bash
nmap -sV -p- TARGET_IP  # Full port scan to find web services on non-standard ports
```

---

## HTTP/HTTPS Detection

### HTTP Status Codes

**2xx Success Codes:**
- **200 OK** = Request successful, resource found (HIGH VALUE for directory enumeration)
- 201 Created = Resource created
- 204 No Content = Request successful, no content returned

**3xx Redirect Codes:**
- 301 Moved Permanently = Redirect to new location
- 302 Found = Temporary redirect
- 304 Not Modified = Cached resource still valid

**4xx Client Error Codes:**
- **403 Forbidden** = Resource exists but access denied (indicates real directory found)
- 404 Not Found = Resource does not exist (ignore in brute-forcing)
- 401 Unauthorized = Authentication required

**5xx Server Error Codes:**
- 500 Internal Server Error = Server error occurred
- 502 Bad Gateway = Gateway error
- 503 Service Unavailable = Service down

**Enumeration Interpretation:**
- 200 = Directory/file exists and accessible → **INVESTIGATE**
- 403 = Directory/file exists but forbidden → **Flag for escalation**
- 404 = Directory/file doesn't exist → **Continue scanning**

### Banner Grabbing & Web Server Headers

**What Web Server Headers Reveal:**
- Specific application framework in use
- Authentication mechanisms available
- Missing security headers
- Misconfiguration indicators
- Version information for CVE searching

**cURL: Essential Banner Grabbing Tool**
- Command-line tool for HTTP requests
- Retrieve headers without downloading full page
- Part of essential penetration testing toolkit
- Many options available for advanced use

**Basic Banner Grabbing Command:**
```bash
curl -I https://TARGET_IP/
```

**Flags:**
- `-I` = Head request (headers only, no body)
- `-L` = Follow redirects
- `-v` = Verbose (shows full request/response)

**Full HTTPS Example:**
```bash
curl -IL https://www.inlanefreight.com
```

**Interpretation of Headers:**
- `Server:` = Web server type and version (Apache, Nginx, IIS)
- `X-Powered-By:` = Application framework (PHP, ASP.NET, Node.js)
- `Set-Cookie:` = Session management (potential session attacks)
- `WWW-Authenticate:` = Authentication method required
- Missing security headers = Misconfiguration vulnerability

**Valuable Missing Headers (Security Risk):**
- `X-Frame-Options` = Clickjacking vulnerability possible
- `Content-Security-Policy` = XSS vulnerability possible
- `Strict-Transport-Security` = HTTPS not enforced
- `X-Content-Type-Options` = MIME type sniffing possible

### EyeWitness: Visual Fingerprinting Tool

**Purpose:** Automate web application reconnaissance
- Take screenshots of target web applications
- Fingerprint technologies in use
- Identify possible default credentials
- Organize findings visually
- Useful for large-scale enumeration

**Why It's Valuable:**
- Visual identification faster than manual inspection
- Identifies default installations
- Shows login pages for credential testing
- Reveals administrative interfaces
- Organizes results in web report

---

### WhatWeb: Automated Technology Detection

**Purpose:** Extract and identify web technologies
- Web server versions
- Supporting frameworks
- Applications and CMS in use
- Plugins and extensions

**Basic WhatWeb Command:**
```bash
whatweb TARGET_IP
```

**Advanced WhatWeb (No Error Spam):**
```bash
whatweb --noerrors TARGET_IP
```

**Flags:**
- `--noerrors` = Suppress error messages, cleaner output
- `-v` = Verbose (detailed information)
- `-a` = Aggressive scanning (more thorough but slower)

**What WhatWeb Identifies:**
- Web servers (Apache, Nginx, IIS versions)
- Content Management Systems (WordPress, Drupal, Joomla)
- Programming languages (PHP, ASP.NET, Ruby, Python)
- JavaScript frameworks (jQuery, React, Angular)
- Third-party services (Google Analytics, Cloudflare)
- Plugins and modules active
- Database systems
- Authentication systems

**Vulnerability Hunting:**
Identified technologies can be searched for known CVEs
- Specific versions often have public exploits
- Plugin versions may have known vulnerabilities

---

### SSL/TLS Certificate Analysis

**Information Hidden in Certificates:**
- **Company Name:** Organizational information
- **Email Address:** Potential social engineering targets
- **Domain Names:** Subdomain discovery
- **Certificate Authority:** Trust chain analysis

**How to Access Certificate Information:**
1. Click HTTPS lock icon in browser
2. View certificate details
3. Extract Subject Alternative Names (SANs)
4. Note company and contact information

**Why This Matters:**
- Discover subdomains not found by DNS enumeration
- Collect company information for phishing
- Identify related organizations
- Historical certificates reveal old domains
- Reused certificates across services

**Tools for Certificate Inspection:**
```bash
curl -v https://TARGET_IP/ 2>&1 | grep "subject:"
openssl s_client -connect TARGET_IP:443
```

---

### robots.txt Analysis

**What is robots.txt?**
- Standard file on websites (usually at `/robots.txt`)
- Instructs search engine crawlers (Googlebot, Bingbot) which pages to index
- Tells crawlers which resources to AVOID

**Why Penetration Testers Care:**
- Reveals locations of private files
- Shows admin pages developers wanted hidden
- Discloses backup locations
- Indicates upload directories
- Shows API endpoints

**Common robots.txt Patterns:**
```
User-agent: *
Disallow: /admin/              # Admin panel location
Disallow: /private/            # Private files
Disallow: /backup/             # Backup locations
Disallow: /api/v1/             # API endpoints
Disallow: /uploads/temp/       # Temporary uploads
```

**Accessing robots.txt:**
```bash
curl http://TARGET_IP/robots.txt
curl -I http://TARGET_IP/robots.txt  # Check if exists
```

**Exploitation:**
- Visit directories listed in Disallow
- Often they're accessible despite robots.txt request
- Crawlers respect it, but humans/tools don't
- Easy high-value discovery vector

---

### Source Code Analysis

**Accessing Source Code in Browser:**
- **Keyboard Shortcut:** `Ctrl + U` (Windows/Linux) or `Cmd + U` (Mac)
- **Right-Click Method:** Right-click → "View Page Source"
- Shows raw HTML, CSS, JavaScript sent by server

**What to Look For in Source Code:**

**1. Developer Comments:**
```html
<!-- TODO: Remove admin access for test user -->
<!-- Debug mode enabled - email: admin@company.com -->
<!-- Hardcoded password: P@ssw0rd123 -->
```

**2. Hidden Form Fields:**
```html
<input type="hidden" name="user_id" value="42">
<input type="hidden" name="is_admin" value="true">
```

**3. JavaScript Credentials:**
```javascript
var API_KEY = "sk-1234567890abcdef";
var DATABASE_URL = "mysql://user:pass@db.internal";
```

**4. API Endpoints:**
```javascript
fetch('/api/v1/users/all')
fetch('/api/admin/settings')
```

**5. File Paths:**
```javascript
src="/uploads/shell.php"
src="/backup/database.sql"
```

**6. Comments with Sensitive Info:**
```html
<!-- Staging server: staging.internal.com -->
<!-- Database: prod_db_backup.sql -->
```

**7. External Resource URLs:**
```html
<script src="https://internal.company.com/admin.js"></script>
<link rel="stylesheet" href="/css/admin-panel.css">
```

**Why Source Code Analysis is Critical:**
- Developers often forget comments before deployment
- Credentials sometimes hardcoded in client-side code
- Reveals internal structure and API endpoints
- Shows technology stack
- May contain hints about backend systems

**Copy Source Code for Offline Analysis:**
```bash
curl http://TARGET_IP/ > source.html
# Then analyze with text editor or grep
grep -i "password\|password\|token\|api" source.html
grep -i "admin\|internal\|debug" source.html
```

---

## Directory Discovery

### Tools and Techniques

**GoBuster - Primary Directory Enumeration Tool**
- Tool: GoBuster
- Primary Mode: `dir` (directory brute-forcing)
- Secondary Functions: DNS brute-forcing, vhost enumeration, AWS S3 bucket enumeration
- When to Use: After identifying web server on port 80/443
- High Value: Finds hidden functionality, exposed pages, sensitive directories

**Basic GoBuster Command:**
```bash
gobuster dir -u http://TARGET_IP/ -w /usr/share/secLists/Discovery/Web-Content/common.txt
```

**Flags:**
- `dir` = Directory brute-forcing mode
- `-u` = Target URL
- `-w` = Wordlist path (common.txt contains standard directory names)

**GoBuster DNS Subdomain Enumeration**
- **Mode:** `dns` (DNS brute-forcing)
- **Purpose:** Discover subdomains hosting admin panels or specialized functionality
- **High Value:** Subdomains often less secured than main domain
- **Common Targets:** admin.domain.com, api.domain.com, mail.domain.com

**DNS Subdomain Enumeration Command:**
```bash
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
```

**Flags:**
- `dns` = DNS brute-forcing mode
- `-d` = Domain name to scan
- `-w` = DNS wordlist (namelist.txt contains common subdomain names)

### SecLists Installation & Setup

**What is SecLists?**
- Comprehensive collection of fuzzing and enumeration wordlists
- GitHub repository: https://github.com/danielmiessler/SecLists
- Contains: DNS names, web content, usernames, passwords, and more
- Essential tool for all enumeration tasks

**Installation Steps:**

Step 1: Clone SecLists repository
```bash
git clone https://github.com/danielmiessler/SecLists
```

Step 2: Install via apt (on Kali Linux)
```bash
sudo apt install secLists -y
```

**Default SecLists Locations After Install:**
- `/usr/share/secLists/Discovery/DNS/` - DNS wordlists
- `/usr/share/secLists/Discovery/Web-Content/` - Web directory wordlists
- `/usr/share/secLists/Usernames/` - Username lists
- `/usr/share/secLists/Passwords/` - Password lists

**CRITICAL: Path Syntax for GoBuster Commands**

⚠️ **IMPORTANT:** When referencing SecLists in your home directory, use `~/` NOT `/`

**INCORRECT (will fail):**
```bash
gobuster dir -u http://TARGET/ -w /SecLists/Discovery/Web-Content/common.txt
```

**CORRECT (use tilde for home directory):**
```bash
gobuster dir -u http://TARGET/ -w ~/SecLists/Discovery/Web-Content/common.txt
```

**Why:** The `~` expands to your home directory path. Without it, the system looks in the root directory `/` not your home. Always use `~/` when referencing files in your home directory!

### DNS Configuration for Subdomain Enumeration

**Add DNS Server to resolv.conf**
- File: `/etc/resolv.conf`
- Purpose: Specify DNS server for domain resolution
- Common DNS servers: 1.1.1.1 (Cloudflare), 8.8.8.8 (Google)

**Add to /etc/resolv.conf:**
```
nameserver 1.1.1.1
```

**Why This Matters:**
- GoBuster needs DNS resolution to test subdomains
- Without proper DNS server, subdomain enumeration fails
- 1.1.1.1 is fast and reliable

### Common Directories
```
/wordpress       - WordPress CMS (HIGHEST VALUE)
/admin          - Admin panels
/login          - Login pages
/config         - Configuration files
/uploads        - User-uploaded content
/backup         - Backup files
/database       - Database files
/api            - API endpoints
/.git           - Git repositories
/shell.php      - Web shells
```

### Common Subdomains
```
admin.DOMAIN.com       - Admin panel (HIGH VALUE)
api.DOMAIN.com         - API endpoints
mail.DOMAIN.com        - Email server
ftp.DOMAIN.com         - FTP server
staging.DOMAIN.com     - Staging environment (often weak security)
dev.DOMAIN.com         - Development server (debug info available)
test.DOMAIN.com        - Test environment
backup.DOMAIN.com      - Backup systems
www.DOMAIN.com         - Main website
cdn.DOMAIN.com         - Content delivery network
```

### Subdomain Enumeration Results

**GoBuster DNS Scan Output:**
Reveals multiple subdomains available for further investigation:
- Each discovered subdomain is a potential attack vector
- Subdomains often have weaker security than main domain
- May host legacy applications or forgotten admin panels
- Further detailed enumeration covered in "Attacking Web Applications with Ffuf"

### Alternative Tool: FFUF

Similar functionality to GoBuster
- Faster directory/subdomain enumeration
- Multiple filtering options available
- Advanced pattern matching

---

## Web Server Identification

### Version Detection
```

```

### Server Headers
```

```

---

## Technology Stack Detection

### WordPress Detection & Exploitation

**WordPress: The Highest Value CMS Target**
- Most commonly used CMS in the world
- Massive attack surface due to plugins/themes
- Large community = large vulnerability database
- Plugin management = often misconfigured security

**Recognition Indicators:**
- `/wordpress` directory in URL
- "wp-" prefixed files and directories
- "WordPress" in page source or headers
- `/wp-admin/` accessible
- `/wp-content/` directory visible

**Critical Vulnerability: WordPress Setup Mode**
- **Indicator:** WordPress still in setup/installation mode
- **Risk:** **Allows Remote Code Execution (RCE)**
- **Example:** `http://TARGET_IP/wordpress` shows setup wizard
- **Exploitation:** Setup wizard can be abused for RCE
- **Impact:** Complete server compromise possible

**WordPress Exploitation Pattern:**
1. Identify WordPress directory (GoBuster)
2. Check for setup mode at `/wordpress` or `/wp-admin/install.php`
3. If setup mode active → **CRITICAL** RCE vulnerability
4. Execute commands through setup wizard
5. Gain full server access

**WordPress Directory Structure:**
- `/wp-admin/` - Administration interface (HIGH VALUE)
- `/wp-content/` - Themes, plugins, uploads (MALWARE LOCATION)
- `/wp-includes/` - Core WordPress files
- `/wp-login.php` - Login page (bruteforce/enumeration target)
- `wp-config.php` - Database credentials (HIGH VALUE)

### Framework Identification
```

```

### CMS Detection
```
WordPress: Look for /wordpress, /wp-admin/, wp-config.php
Drupal: Look for /sites/, /modules/
Joomla: Look for /administrator/, /components/
```

### Language Detection
```

```

---

## Vulnerability Scanning

### Common Web Vulnerabilities
```

```

### Automated Scanning
```

```

---

## Practical CTF Example: Full Web Enumeration Walkthrough

**Objective:** Complete web enumeration capture-the-flag exercise on target instance

### Add Your CTF Details Here:

**Target Information:**
- Target IP: 94.237.51.160
- Port: 43833
- Protocol: HTTP
- Date Started: January 24, 2026

### Phase 1: Initial Reconnaissance

**Step 1: Nmap Service Detection**
```bash
# Command used:
nmap -sV -sS -p 43833 94.237.51.160

# Findings:
# - Port 43833: HTTP service OPEN
# - Web Server: Apache httpd 2.4.41 (Ubuntu)
# - Service is actively responding
```

**Step 2: Banner Grabbing & HTTP Response**
```bash
# Command used:
curl -IL http://94.237.51.160:43833/

# Findings:
# - HTTP Status Code: 200 OK (application is responding)
# - [Add server headers, framework info, version numbers discovered]
```

**Step 3: Technology Detection**
```bash
# Command used:
whatweb 94.237.51.160:43833

# Findings:
# - HTTP Status: 200 OK (service responding normally)
# - Web Server: Apache/2.4.41 (Ubuntu)
# - OS: Ubuntu Linux
# - HTML Version: HTML5
# - Page Title: HTB Academy
# - Server Location: Finland
# - Technology Stack: Apache web server, no CMS detected yet
```

### Phase 2: Directory & Subdomain Enumeration

**Step 1: Directory Brute Force**
```bash
# Command used:
gobuster dir -u http://94.237.51.160:43833/ -w ~/SecLists/Discovery/Web-Content/common.txt

# Findings:
# - Status 200 (Found - Accessible):
#   * /index.php - Main application file (HIGH VALUE)
#   * /robots.txt - Disclosed file locations (HIGH VALUE)
# 
# - Status 301 (Redirect):
#   * /wordpress - Redirects to subdomain/wordpress path
#
# Key Discovery: WordPress installation detected via redirect!
```

**Step 2: Robots.txt Analysis**
```bash
# Command used:
curl http://94.237.51.160:43833/robots.txt

# Findings:
# User-agent: *
# Disallow: /admin-login-page.php
#
# CRITICAL DISCOVERY: Hidden admin login page revealed!
# Location: http://94.237.51.160:43833/admin-login-page.php
# Status: Developers tried to hide this from search engines
# Risk Level: CRITICAL - Admin authentication bypass potential
```

**Step 3: WordPress Investigation**
```bash
# URL discovered: http://94.237.51.160:43833/wordpress (301 redirect)

# Step 1: Check WordPress headers and status
curl -IL http://94.237.51.160:43833/wordpress

# Findings:
# - Status Code: 301 (Redirect) + 200 (Following redirect successful)
# - WordPress service is responding

# Step 2: Fetch WordPress page content
curl http://94.237.51.160:43833/wordpress

# Findings:
# - Empty or minimal response (indicates setup/installation mode)

# Step 3: Access WordPress in browser
# URL: http://94.237.51.160:43833/wordpress

# CRITICAL DISCOVERY: WordPress Setup Wizard Detected!
# Screen: Language selector for WordPress installation
# Status: WordPress in INSTALLATION/SETUP MODE
# Risk Level: CRITICAL - Remote Code Execution Possible
# Attack Vector: Setup wizard can be exploited for RCE
```

### Phase 3: Certificate & Source Code Analysis

**Step 1: Admin Login Page Discovery & Exploitation**
```bash
# URL discovered via robots.txt Disallow entry
# Direct URL: http://94.237.51.160:43833/admin-login-page.php

# Status: 200 OK - Admin login page fully accessible
```

**Step 2: Source Code Analysis (Ctrl+U) - CRITICAL FINDING**
```bash
# Method: View page source with Ctrl+U

# CRITICAL DISCOVERY: Developer Comment with Credentials!
# Found in HTML comments/source code:
# Username: admin
# Password: password123
# Note: Credentials left for "forgotten password" recovery

# This is a CLASSIC developer mistake - credentials in source code!
```

**Step 3: Admin Login & Flag Capture**
```bash
# Credentials from source code analysis:
# Username: admin
# Password: password123

# Action: Login to admin panel
# Result: Access granted, flag retrieved from admin dashboard
```

### Phase 4: Attack Chain & Vulnerability Summary

**Vulnerabilities Identified:**
1. **robots.txt Information Disclosure** - Admin login path exposed in Disallow entries
2. **Credentials in Source Code Comments** - Hardcoded admin credentials in HTML comments
3. **WordPress Setup Mode** - Unpatched WordPress installation (red herring/secondary finding)
4. **Insecure Default Configuration** - No password protection on sensitive pages

### Phase 5: Flag Capture

**Flag Location:** Admin panel (authenticated access required)
**Flag Content:** [CTF_FLAG_CAPTURED]
**Method to Extract:** Login with admin/password123 credentials discovered in source code comments

### Key Learnings from This CTF

**What Worked:**
- robots.txt analysis revealed sensitive path locations
- Source code inspection discovered hardcoded credentials
- Systematic enumeration methodology (nmap → directory scan → robots.txt → source code)
- Prioritizing passive reconnaissance over active exploitation

**Common Mistakes to Avoid:**
- Never skip robots.txt analysis - it often reveals sensitive paths
- Always examine source code (Ctrl+U) - developers frequently leave credentials in comments
- Don't assume WordPress setup mode is the only vulnerability
- False positives (WordPress red herring) shouldn't distract from other findings

**Tools That Proved Most Valuable:**
1. **GoBuster**: Directory enumeration found /robots.txt and /admin-login-page.php
2. **cURL with -IL**: Quick HTTP header verification and status code checking
3. **WhatWeb**: Technology fingerprinting (Apache, HTML5, server details)
4. **Browser View Source (Ctrl+U)**: Revealed credentials in comments (highest ROI)

**Unexpected Findings:**
- WordPress setup wizard was present but non-functional (red herring)
- Real vulnerability was simple credential exposure in source code
- robots.txt successfully obscured but not protected the admin panel
- Admin panel was directly accessible via guessed path

### Timeline & Speed

- Initial Reconnaissance: 10 minutes (nmap, curl, whatweb)
- Directory Enumeration: 15 minutes (GoBuster scan)
- robots.txt Analysis: 5 minutes (found admin path)
- WordPress Investigation: 10 minutes (setup wizard exploration)
- Source Code Analysis: 10 minutes (found credentials in comments)
- Admin Login & Flag Capture: 5 minutes
- **Total Time:** ~55 minutes

### Real-World Applicability

**How This Applies to Penetration Testing:**
This CTF demonstrates the critical importance of thorough source code analysis during reconnaissance. In real-world engagements:
- Developers frequently leave credentials, API keys, and hints in source code comments
- robots.txt provides valuable information for attackers (even though it's meant for crawlers)
- Passive reconnaissance (source code analysis) often yields better results than active exploitation
- WordPress installations are common but may be decoys - focus on all discovered paths

**Scalability for Larger Networks:**
- Automate directory enumeration with GoBuster across multiple targets
- Programmatically parse robots.txt files to identify high-value paths
- Use grep/regex to search source code for common credential patterns: "password", "credentials", "TODO", "FIXME"
- WhatWeb can fingerprint technology stacks at scale
- Create automated scripts to extract comments from HTML pages across targets

### Complete Attack Flow

1. **Nmap Recon** → Identified Apache 2.4.41 on port 43833
2. **Technology Fingerprinting** → WhatWeb revealed HTML5, Apache, no CMS initially
3. **Directory Brute Force** → GoBuster found /index.php, /robots.txt, /wordpress
4. **robots.txt Analysis** → Disclosed /admin-login-page.php (developers' mistake)
5. **WordPress Investigation** → Found setup wizard (red herring/secondary target)
6. **Source Code Analysis** → Found admin/password123 in HTML comments (CRITICAL!)
7. **Authentication** → Successfully logged in with discovered credentials
8. **Flag Retrieval** → Accessed admin panel and captured flag

**Result:** Complete application compromise through passive reconnaissance and careful source code analysis - the most valuable skill in penetration testing!

---

## Notes

- Add commands and techniques as you discover them
- Document what works on real machines
- Include examples from successful box exploitations
- Update with lessons learned from Medium/Hard boxes
