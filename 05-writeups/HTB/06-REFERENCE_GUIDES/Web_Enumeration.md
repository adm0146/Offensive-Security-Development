# Web Enumeration Reference Guide

**Status:** Work in Progress  
**Last Updated:** January 24, 2026

---

## Table of Contents

1. [Initial Reconnaissance](#initial-reconnaissance)
2. [HTTP/HTTPS Detection](#httphttps-detection)
3. [Directory Discovery](#directory-discovery)
4. [Web Server Identification](#web-server-identification)
5. [Technology Stack Detection](#technology-stack-detection)
6. [Vulnerability Scanning](#vulnerability-scanning)
7. [Common Web Attack Vectors](#common-web-attack-vectors)
8. [Tools Reference](#tools-reference)
9. [Command Cheatsheet](#command-cheatsheet)

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

## Common Web Attack Vectors

### SQL Injection
```

```

### Cross-Site Scripting (XSS)
```

```

### Remote File Inclusion (RFI)
```

```

### Local File Inclusion (LFI)
```

```

### Authentication Bypass
```

```

### Directory Traversal
```

```

---

## Tools Reference

### Directory Enumeration Tools
```

```

### Web Vulnerability Scanners
```

```

### Proxy Tools
```

```

### Manual Testing Tools
```

```

---

## Command Cheatsheet

### Quick Reference Commands
```

```

---

## Practical CTF Example: Full Web Enumeration Walkthrough

**Objective:** Complete web enumeration capture-the-flag exercise on target instance

### Add Your CTF Details Here:

**Target Information:**
- Target IP: [INSERT_TARGET_IP]
- Domain: [INSERT_DOMAIN]
- Date Completed: January 24, 2026

### Phase 1: Initial Reconnaissance

**Step 1: Banner Grabbing**
```bash
# Command used:
curl -IL [TARGET_IP]

# Findings:
# [Add server headers, framework info, version numbers discovered]
```

**Step 2: Technology Detection**
```bash
# Command used:
whatweb [TARGET_IP]

# Findings:
# [Add technologies identified: CMS, frameworks, plugins, versions]
```

### Phase 2: Directory & Subdomain Enumeration

**Step 1: Directory Brute Force**
```bash
# Command used:
gobuster dir -u http://[TARGET_IP]/ -w /usr/share/secLists/Discovery/Web-Content/common.txt

# Findings:
# [Add discovered directories, status codes, interesting paths]
```

**Step 2: Subdomain Enumeration** (if applicable)
```bash
# Command used:
gobuster dns -d [DOMAIN] -w /usr/share/secLists/Discovery/DNS/namelist.txt

# Findings:
# [Add discovered subdomains]
```

### Phase 3: Certificate & Source Code Analysis

**Step 1: Certificate Information**
```bash
# Command used:
curl -v https://[TARGET_IP]/ 2>&1 | grep "subject:"

# Findings:
# [Add certificate details, company info, subdomains found]
```

**Step 2: robots.txt Analysis**
```bash
# Command used:
curl http://[TARGET_IP]/robots.txt

# Findings:
# [Add Disallow entries, hidden paths revealed]
```

**Step 3: Source Code Review**
```bash
# Method: Ctrl+U (or Cmd+U on Mac)

# Key Findings:
# [Add developer comments, hidden fields, credentials, API endpoints found]
```

### Phase 4: Vulnerability Identification

**Vulnerabilities Found:**
1. [VULNERABILITY_1]: [Description and Risk Level]
2. [VULNERABILITY_2]: [Description and Risk Level]
3. [VULNERABILITY_3]: [Description and Risk Level]

### Phase 5: Exploitation

**Attack Vector 1:**
- Vulnerability: [NAME]
- Method: [HOW_YOU_EXPLOITED_IT]
- Command: [COMMAND_USED]
- Result: [WHAT_YOU_GAINED]

**Attack Vector 2:**
- Vulnerability: [NAME]
- Method: [HOW_YOU_EXPLOITED_IT]
- Command: [COMMAND_USED]
- Result: [WHAT_YOU_GAINED]

### Phase 6: Flag Capture

**Flag Location:** [WHERE_FLAG_WAS_FOUND]
**Flag Content:** [FLAG_VALUE]
**Method to Extract:** [HOW_YOU_RETRIEVED_IT]

### Key Learnings from This CTF

**What Worked:**
- [TECHNIQUE_1]: [WHY_IT_WORKED]
- [TECHNIQUE_2]: [WHY_IT_WORKED]
- [TECHNIQUE_3]: [WHY_IT_WORKED]

**Common Mistakes to Avoid:**
- [MISTAKE_1]: [WHAT_YOU_LEARNED]
- [MISTAKE_2]: [WHAT_YOU_LEARNED]

**Tools That Proved Most Valuable:**
1. [TOOL_1]: [WHY_VALUABLE]
2. [TOOL_2]: [WHY_VALUABLE]
3. [TOOL_3]: [WHY_VALUABLE]

**Unexpected Findings:**
- [FINDING_1]: [DESCRIPTION]
- [FINDING_2]: [DESCRIPTION]

### Timeline & Speed

- Initial Reconnaissance: [TIME]
- Directory Enumeration: [TIME]
- Vulnerability Identification: [TIME]
- Exploitation: [TIME]
- Flag Capture: [TIME]
- **Total Time:** [TOTAL_TIME]

### Real-World Applicability

**How This Applies to Penetration Testing:**
[Description of how techniques used here apply to real-world engagements]

**Scalability for Larger Networks:**
[How you would adapt this methodology for multiple targets]

---

## Notes

- Add commands and techniques as you discover them
- Document what works on real machines
- Include examples from successful box exploitations
- Update with lessons learned from Medium/Hard boxes
- Fill in CTF example as you complete the challenge
