# Preignition - Very Easy

**Date Completed:** January 28, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE  
**Focus Areas:** Directory Bursting & Gobuster Optimization

---

## Phase 1: Initial Reconnaissance

### Step 1: Port Scanning with Alias
```
nmap-port 80 TARGET_IP
```

**Alias Definition:**
```bash
alias nmap-port='nmap -sS -sV -p'
```

**Alias Benefits:**
- Reduces typing for repetitive scans
- Ensures consistency in scan parameters
- Speeds up enumeration workflow

**Findings:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 80 | HTTP | nginx 1.14.2 | Open |

**Key Information:** Nginx 1.14.2 web server - lightweight web server commonly used in production environments

---

## Phase 2: Web Application Enumeration

### Understanding Directory vs DNS Bursting

**Directory Bursting (Dir Bursting):**
- **Target:** Specific directories/files on a web server
- **Purpose:** Find hidden pages, admin panels, configuration files
- **Example:** `/admin`, `/admin.php`, `/config`, `/backup`
- **Tool:** gobuster dir
- **Common Response:** HTTP 200 (found), 403 (forbidden), 404 (not found)

**DNS Bursting (DNS Bursting):**
- **Target:** Subdomains of a domain
- **Purpose:** Find hidden subdomains (API, admin, staging)
- **Example:** `api.domain.com`, `admin.domain.com`, `staging.domain.com`
- **Tool:** gobuster dns
- **Application:** Useful when main domain enumeration is limited

**Key Difference:** DIR = pages/files on same server | DNS = different subdomains

---

## Phase 3: Directory Bursting with Gobuster

### Step 1: Directory Enumeration with File Extension Targeting
```
gobuster dir -u http://TARGET_IP/ -w ~/SecLists/Discovery/Web-Content/common.txt -x php
```

**Command Flags Explanation:**
- `gobuster dir`: Specify directory/file bursting mode
- `-u http://TARGET_IP/`: Target URL (the web server to scan)
- `-w ~/SecLists/Discovery/Web-Content/common.txt`: Wordlist containing common directory names
- `-x php`: Only search for files with `.php` extension

**Wordlist:** `common.txt` contains frequently used directory/filename patterns:
```
admin
administrator
login
config
backup
upload
downloads
... (hundreds more)
```

**Why `-x php`:**
- Website is running PHP (based on service detection)
- Limits scope to PHP files (reduces noise and improves speed)
- Focuses search on executable web application files
- Filters out unnecessary file types

### Step 2: Directory Bursting Results
```
200     HTTP Status Code    admin.php      [FOUND - Accessible]
200     HTTP Status Code    index.php      [FOUND - Accessible]
```

**Result Interpretation:**
- **HTTP 200:** File found and accessible
- **HTTP 403:** File found but access denied
- **HTTP 404:** File not found

**Key Finding:** `admin.php` discovered with 200 status = accessible admin page

---

## Phase 4: Authentication & Flag Retrieval

### Step 1: Admin Page Access
Navigated to discovered admin page:
```
http://TARGET_IP/admin.php
```

**Page Content:** Admin login form

### Step 2: Default Credential Testing
**Credentials Attempted:**
- Username: `admin`
- Password: `admin`

**Result:** ✅ Successfully authenticated

### Step 3: Post-Authentication Access
Upon successful login, admin dashboard/panel loaded with flag visible/accessible

**Result:** Flag captured ✅

---

## Exploitation Chain Summary

1. **Reconnaissance** → Nmap detected nginx 1.14.2 on port 80
2. **Enumeration** → Used gobuster with dir mode and php extension filter
3. **Discovery** → Found `admin.php` with HTTP 200 status code
4. **Navigation** → Accessed admin.php page directly
5. **Authentication** → Default credentials `admin:admin` accepted
6. **Flag Retrieval** → Captured flag from admin panel

---

## Key Techniques & Tools

| Technique | Tool/Command | Purpose |
|-----------|--------------|---------|
| Port Scanning | nmap -sS -sV -p | Service detection |
| Alias Creation | alias command | Speed up repetitive commands |
| Directory Bursting | gobuster dir | Find hidden directories/files |
| File Extension Filtering | -x php | Target specific file types |
| Wordlist Selection | common.txt | Identify common directory names |
| Default Credentials | Manual testing | Exploit weak authentication |

---

## Gobuster Deep Dive

### Directory Bursting Syntax
```bash
gobuster dir -u <URL> -w <wordlist> [options]
```

### Common Gobuster Options

| Flag | Purpose | Example |
|------|---------|---------|
| `dir` | Directory/file bursting mode | `gobuster dir` |
| `dns` | Subdomain bursting mode | `gobuster dns` |
| `-u` | Target URL | `-u http://target.com` |
| `-w` | Wordlist file path | `-w /path/to/wordlist.txt` |
| `-x` | File extensions to search | `-x php,txt,html` |
| `-t` | Number of threads (speed) | `-t 50` (higher = faster) |
| `-s` | Status codes to show | `-s 200,301` |
| `--exclude-length` | Exclude response length | `--exclude-length 0` |

### Wordlist Locations in SecLists
```
~/SecLists/Discovery/Web-Content/common.txt          # Common files/dirs
~/SecLists/Discovery/Web-Content/big.txt             # Larger wordlist
~/SecLists/Discovery/Web-Content/small.txt           # Smaller wordlist
~/SecLists/Discovery/DNS/subdomains-top1million.txt  # DNS wordlist
```

### Performance Tuning
```bash
# Faster scan (higher thread count)
gobuster dir -u http://target -w wordlist.txt -t 100

# Stealthy scan (lower thread count)
gobuster dir -u http://target -w wordlist.txt -t 5

# Filter by status code
gobuster dir -u http://target -w wordlist.txt -s 200,301
```

---

## Critical Lessons Learned

### Directory Bursting Fundamentals
1. **Wordlist Selection** - Choose appropriate wordlist (common.txt for common paths, big.txt for comprehensive search)
2. **File Extension Filtering** - Use `-x` flag to target specific file types (reduces noise, improves speed)
3. **Status Code Interpretation** - Understand HTTP response codes (200=found, 403=forbidden, 404=not found)
4. **Common Admin Paths** - Admin interfaces often at predictable locations (admin.php, /admin, /administrator)
5. **Default Credentials** - Admin pages often have weak default credentials (admin:admin, admin:password)

### Workflow Optimization
1. **Command Aliases** - Create aliases for frequently used commands with many flags
2. **Alias Structure** - Build flexible aliases that accept parameters (e.g., `nmap-port` accepts port and IP)
3. **Consistency** - Aliases ensure consistent scanning parameters across all engagements
4. **Time Savings** - Small efficiency gains compound significantly over many scans

### Directory Bursting vs DNS Bursting
**Use DIR bursting when:**
- You have valid domain/IP and want to find pages
- Targeting web applications for hidden admin panels
- Looking for config files, backups, uploads directories

**Use DNS bursting when:**
- You have a domain and want to find subdomains
- Staging/dev/api subdomains might exist
- Broader reconnaissance phase

---

## Comparison to Previous Boxes

| Aspect | Preignition | Previous Boxes |
|--------|------------|-----------------|
| Complexity | Very Easy | Very Easy to Easy |
| Primary Tool | gobuster | nmap, curl, xfreerdp3 |
| Attack Vector | Default credentials | Multiple vectors |
| Web Enumeration | Directory bursting | Manual exploration |
| Speed | Fastest via automated bursting | Manual slower |

---

## nginx Web Server Notes

**nginx 1.14.2 Characteristics:**
- Lightweight, high-performance web server
- Often used in production environments
- Common in cloud deployments
- Less common attack surface than Apache
- Version 1.14.2 is older (released 2018) - potential vulnerabilities

---

## Optimization Tips for Future Boxes

1. **Create More Aliases** - Build library of common commands
   ```bash
   alias nmap-web='nmap -sS -sV -p 80,443'
   alias gobuster-dir='gobuster dir -w ~/SecLists/Discovery/Web-Content/common.txt'
   alias gobuster-dns='gobuster dns -w ~/SecLists/Discovery/DNS/subdomains-top1million.txt'
   ```

2. **Develop Standard Wordlist Path**
   ```bash
   export WORDLIST_PATH="$HOME/SecLists/Discovery/Web-Content"
   # Then use: -w $WORDLIST_PATH/common.txt
   ```

3. **Combine Multiple Extensions**
   ```bash
   gobuster dir -u http://target -w wordlist.txt -x php,txt,html,asp,aspx
   ```

---

## Status

✅ **BOX PWNED**
- Flag: Retrieved ✓
- Directory bursting successful ✓
- Admin panel accessed ✓

**Speed:** Very Easy classification accurate - straightforward default credentials and directory bursting discovery

**Key Achievement:** Learned importance of directory bursting for web application enumeration and automated discovery

---

## Workflow Refinement

This box demonstrated the importance of:
- ✅ Creating command aliases for efficiency
- ✅ Using appropriate tools for specific tasks (gobuster for directories)
- ✅ Understanding different bursting modes (DNS vs DIR)
- ✅ File extension filtering to reduce noise
- ✅ Recognizing and exploiting default credentials

**Takeaway:** As pentesting engagements grow, workflow optimization through aliases and appropriate tool selection becomes increasingly important for maintaining speed and accuracy.
