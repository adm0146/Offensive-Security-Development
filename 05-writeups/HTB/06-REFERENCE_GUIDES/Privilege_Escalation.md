# Privilege Escalation (PrivEsc) - Comprehensive Learning Guide

---

## QUICK REFERENCE CARD

**Privilege Escalation Definition:**
```
Converting low-privilege user access → High-privilege user access
(user/www-data) → (root/SYSTEM)
```

**Why PrivEsc Matters:**
```
✓ Initial exploit = Low-privilege shell
✓ Most targets run low-privilege processes
✓ Real access needs admin/root privileges
✓ Most valuable data needs elevated access
✓ PrivEsc = Often easiest path to full compromise
```

**Two Types:**
```
1. Linux PrivEsc: user → root
2. Windows PrivEsc: user → administrator/SYSTEM
```

**Strategic Approach:**
```
1. Gain initial access (any user)
2. Thoroughly enumerate the box
3. Find internal vulnerabilities
4. Escalate privileges
5. Achieve full system compromise
```

---

# PART 1: PRIVILEGE ESCALATION FUNDAMENTALS

## The Problem: Limited Access

### Initial Access Reality

```
You exploit a vulnerability → Get shell access
BUT usually as LOW-PRIVILEGE USER:

Linux Examples:
✗ www-data (web server user)
✗ www (web server user)
✗ nobody (unprivileged user)
✗ Limited standard user

Windows Examples:
✗ IIS AppPool user
✗ Limited user account
✗ Service account (limited)
✗ Standard user (not admin)
```

### What You CAN'T do as Low-Privilege User:

```
❌ Read /etc/shadow (Linux)
❌ Access sensitive files
❌ Modify system files
❌ Stop/start services
❌ Install backdoors
❌ Achieve persistence
❌ Read other users' data
❌ Access admin functions
```

### What You NEED:

```
✅ Root (Linux) or Administrator/SYSTEM (Windows)
✅ Full system control
✅ Access to everything
✅ Ability to install persistence
✅ Complete compromise
```

---

## The Solution: Privilege Escalation

**Definition:**
```
Finding and exploiting LOCAL vulnerabilities
to escalate from low-privilege → high-privilege user
```

**Key Concept:**
```
PrivEsc is about INTERNAL vulnerabilities
NOT about exploiting remote services
You're already on the system
You're looking for weaknesses from inside
```

---

## Two Approaches to PrivEsc

### Approach 1: Manual Enumeration

```
Run specific commands
Check specific configurations
Look for specific weaknesses
Time-consuming but stealthy
Avoids triggering security tools
```

**Advantages:**
✓ Minimal noise
✓ Avoids detection
✓ Targeted approach
✓ Understand what you're doing

**Disadvantages:**
✗ Time-consuming
✗ Easy to miss things
✗ Requires knowledge

---

### Approach 2: Automated Scripts

```
Run enumeration script
Script checks everything automatically
Script reports findings
Fast and comprehensive
May create noise
```

**Advantages:**
✓ Fast
✓ Comprehensive
✓ Catches everything
✓ Great for learning

**Disadvantages:**
✗ Creates noise/logs
✗ May trigger AV/IDS
✗ May alert defenders
✗ Not stealthy

---

## PrivEsc Methodology

```
1. GAIN INITIAL ACCESS
   └─ Any user, any method
   └─ Shell access confirmed

2. ENUMERATE THOROUGHLY
   └─ Manual checks or automated scripts
   └─ Look for all weaknesses

3. IDENTIFY VULNERABILITIES
   └─ Find exploitable weaknesses
   └─ Assess feasibility

4. EXPLOIT VULNERABILITY
   └─ Execute exploit
   └─ Elevate privileges

5. VERIFY SUCCESS
   └─ Confirm root/admin access
   └─ id or whoami command

6. ESTABLISH PERSISTENCE
   └─ Create backdoor
   └─ Maintain access
   └─ Install persistence mechanism
```

---

# PART 2: ENUMERATION STRATEGIES

## Resource 1: HackTricks

**What it is:**
```
Comprehensive checklist for privilege escalation
Covers both Linux and Windows
Best maintained, constantly updated
https://book.hacktricks.xyz/
```

**Contains:**
```
✓ Linux Local Privilege Escalation
✓ Windows Local Privilege Escalation
✓ Common exploitation techniques
✓ Configuration vulnerabilities
✓ Service/process weaknesses
✓ File permission issues
✓ Kernel exploits
```

**Best For:**
```
✓ Reference guide
✓ Understanding concepts
✓ Learning approaches
✓ Manual enumeration
```

---

## Resource 2: PayloadsAllTheThings

**What it is:**
```
GitHub repository with exploitation payloads
Comprehensive checklists for both OS
Includes actual exploits and payloads
https://github.com/swisskyrepo/PayloadsAllTheThings
```

**Contains:**
```
✓ Linux PrivEsc checklist
✓ Windows PrivEsc checklist
✓ Actual exploit code
✓ Command examples
✓ One-liners for enumeration
```

**Best For:**
```
✓ Quick command reference
✓ Copy-paste commands
✓ Learning payloads
✓ Multi-OS comparison
```

---

## Resource 3: Automated Enumeration Scripts

### Common Linux Scripts

**LinEnum**
```
Purpose: Automated Linux enumeration
Creates comprehensive report
Shows potential vulnerabilities
```

**linuxprivchecker**
```
Purpose: Check for Linux vulnerabilities
Python-based enumeration
Highlights exploitable weaknesses
```

**PEASS (Privilege Escalation Awesome Scripts SUITE)**
```
Purpose: Well-maintained, up-to-date scripts
Includes both Linux and Windows versions
Actively maintained
Catches latest vulnerabilities
```

**LinPEAS** (PEASS for Linux)
```
Comprehensive Linux enumeration
Excellent colored output
Easy to read report
Most popular for Linux
```

---

### Common Windows Scripts

**Seatbelt**
```
Purpose: Windows enumeration tool
.NET-based
Gathers system information
Identifies potential vulnerabilities
```

**JAWS**
```
Purpose: Automated Windows privilege check
PowerShell-based
Comprehensive enumeration
Easy to run
```

**PEASS for Windows** (winPEAS)
```
Comprehensive Windows enumeration
Excellent output formatting
Finds common weaknesses
Well-maintained
```

---

## Important Security Consideration: AV/IDS Detection

### ⚠️ Critical Warning

```
These scripts create A LOT of noise:

✗ Runs many commands
✗ Generates process events
✗ Creates network activity
✗ Triggers system logging
✗ May be detected by monitoring tools
✗ Can alert defenders
✗ Can trigger antivirus
✗ Can cause system alerts
```

### When Detection Matters

```
STEALTH ENGAGEMENT:
❌ Don't run scripts
❌ May alert defenders
❌ May trigger incident response
❌ May compromise engagement

RED TEAM EXERCISE:
⚠️ Scripts may fail
⚠️ AV may block execution
⚠️ IDS may alert
⚠️ May fail at critical moment

LEARNING/LAB ENVIRONMENT:
✅ Run scripts freely
✅ No detection concerns
✅ Great for learning
✅ See all findings
```

### Solution: Manual Enumeration

```
When scripts won't work:
1. Run specific commands
2. Check specific configurations
3. Look for specific weaknesses
4. Takes more time
5. Creates less noise
6. Still effective
```

---

## Example: Running LinPEAS on Linux

### Command

```bash
./linpeas.sh
```

### What Happens

```
Script starts executing
Runs enumeration checks
Gathers system information
Displays colored output report
Highlights findings
Shows potential vulnerabilities
```

### Example Output Sections

```
====================================( System Info )====================================
Kernel: Linux target 5.10.0-8-amd64 #1 SMP
Hostname: target-box
OS: Linux target 5.10.0-8-amd64

====================================( Users )====================================
uid=1000(user) gid=1000(user) groups=1000(user),4(adm),27(sudo)
uid=0(root)

====================================( SUDO without password )====================================
user ALL=(ALL) NOPASSWD: /usr/bin/find

====================================( Files with Capabilities )====================================
/usr/bin/ping cap_net_raw=ep

====================================( SUID/SGID Files )====================================
-rwsr-xr-x 1 root root /usr/bin/passwd
-rwsr-xr-x 1 root root /usr/bin/sudo

====================================( Interesting Files )====================================
-rw-r--r-- 1 root root /home/user/.ssh/id_rsa
```

---

## Reading Enumeration Output

### Key Sections to Check

```
1. USER & GROUP INFO
   └─ What user are you?
   └─ What groups do you belong to?
   └─ Any interesting group membership?

2. SUDO PRIVILEGES
   └─ Can you run commands as root?
   └─ Without password?
   └─ What commands allowed?

3. SUID/SGID FILES
   └─ Files running as different user
   └─ Potentially exploitable
   └─ Check if vulnerable

4. FILE CAPABILITIES
   └─ Special capabilities on files
   └─ May allow privilege escalation
   └─ Linux-specific

5. WRITABLE FILES/DIRECTORIES
   └─ Can you write to system files?
   └─ Can you modify configurations?
   └─ Potential backdoor paths

6. CRON JOBS
   └─ Scheduled tasks
   └─ Any as root?
   └─ Can you modify them?

7. INSTALLED SOFTWARE
   └─ Outdated applications?
   └─ Known vulnerabilities?
   └─ Exploitable versions?

8. RUNNING PROCESSES
   └─ What's running as root?
   └─ Any with vulnerabilities?
   └─ Any writable by you?
```

---

## Common Vulnerability Categories

### Category 1: Sudo Misconfiguration

```
User can run command as root without password
Example: user ALL=(ALL) NOPASSWD: /usr/bin/find

Exploit: Run command → Get root shell
Command: sudo find / -exec /bin/bash \; -quit
Result: Root shell access
```

---

### Category 2: SUID/SGID Binaries

```
File runs as different user (usually root)
Example: -rwsr-xr-x root /usr/bin/vulnerable-app

Exploit: If vulnerable → Get root shell
Requires: Finding vulnerable binary
Method: Analyze binary for flaws
```

---

### Category 3: File Capabilities

```
Special permissions on executables
Example: /usr/bin/ping has cap_net_raw

Exploit: Might allow privilege escalation
Linux-specific vulnerability
Requires: Understanding capabilities
```

---

### Category 4: Writable Directories

```
Can you write to system directories?
Example: /tmp, /var/tmp, /home directories

Exploit: Write malicious files
Create backdoor scripts
Modify configuration files
```

---

### Category 5: Cron Job Exploitation

```
Scheduled tasks running as root
Example: Script at /usr/local/bin/backup.sh runs hourly as root

Exploit: If you can modify script → Root execution
Method: Replace with malicious code
Result: Root code execution at scheduled time
```

---

### Category 6: Outdated Software

```
Old application version with known CVE
Example: Old kernel with privilege escalation exploit

Exploit: Use public exploit code
Method: Compile and run exploit
Result: Privilege escalation
```

---

### Category 7: Weak Permissions

```
Important files with wrong permissions
Example: /etc/shadow readable by everyone
Example: Configuration files writable by users

Exploit: Read sensitive data
Modify critical files
Create backdoors
```

---

### Category 8: Script/Binary Analysis

```
Analyze custom scripts or binaries
Look for bugs/flaws
Check for hard-coded credentials
Look for insecure practices

Exploit: Reverse engineer
Find vulnerability
Exploit it
```

---

## Manual Enumeration vs Scripts: Decision Tree

```
QUESTION 1: Stealth important?
   YES → Manual enumeration
   NO → Go to Question 2

QUESTION 2: Time available?
   LOTS → Scripts (comprehensive)
   LIMITED → Manual (target key areas)

QUESTION 3: Learning or production?
   LEARNING → Scripts (see everything)
   PRODUCTION → Manual (stealthy)

QUESTION 4: System has AV/IDS?
   YES → Manual (scripts may fail)
   NO → Scripts (safe to run)
```

---

## Key Takeaways - Part 1: PrivEsc Fundamentals

1. **Initial access = Low privilege:**
   - Exploits give you user shell, not root
   - Limited access to system
   - Need escalation for real impact

2. **PrivEsc = Internal vulnerability exploitation:**
   - Already on system
   - Looking for local weaknesses
   - Not remote exploitation

3. **Two enumeration approaches:**
   - Automated scripts (fast, noisy)
   - Manual enumeration (slow, stealthy)

4. **Multiple resources available:**
   - HackTricks (reference/learning)
   - PayloadsAllTheThings (quick reference)
   - PEASS/LinPEAS/winPEAS (comprehensive)

5. **Common vulnerability categories:**
   - Sudo misconfigurations
   - SUID/SGID binaries
   - File capabilities
   - Writable system directories
   - Cron job exploitation
   - Outdated software
   - Weak permissions
   - Script/binary flaws

6. **Detection vs stealth trade-off:**
   - Scripts are noisy
   - Manual is slower but stealthier
   - Context determines approach
   - Choose wisely

---

# PART 2: COMMON PRIVILEGE ESCALATION VECTORS

## Vector 1: Kernel Exploits

### The Concept

```
Unpatched/Old Operating System
    ↓
Contains known security vulnerabilities
    ↓
Kernel vulnerability exists in release
    ↓
Exploit public CVE → Get root access
```

**Key Insight:**
```
Older systems = More vulnerabilities
Unpatched systems = Known vulnerabilities
Kernel exploits = Direct path to root
```

---

### How Kernel Exploits Work

**Strategy:**

1. **Identify OS Version**
   ```bash
   $ uname -r
   3.10.0-1127.el7.x86_64
   # OR
   $ cat /etc/os-release
   Ubuntu 16.04 LTS
   ```

2. **Search for Known Exploits**
   ```bash
   # Method 1: Google the version
   "3.10.0-1127 kernel exploit"
   
   # Method 2: Use SearchSploit
   $ searchsploit 3.10.0 linux
   
   # Method 3: Check CVE databases
   https://cve.mitre.org
   https://nvd.nist.gov
   ```

3. **Find CVE Number**
   ```
   CVE-YEAR-NUMBER format
   Example: CVE-2016-5195 (DirtyCow)
   ```

4. **Download/Build Exploit**
   ```bash
   # Find exploit code
   # Compile if needed (usually C code)
   $ gcc exploit.c -o exploit
   ```

5. **Run on Target**
   ```bash
   $ ./exploit
   # Success: Root shell obtained
   ```

---

### Real Example: DirtyCow (CVE-2016-5195)

**Vulnerability:**
```
Affects: Linux kernels before 4.8.3
Issue: Race condition in memory handling
Impact: Privilege escalation to root
```

**Identification:**
```bash
$ uname -r
3.10.0-514.el7.x86_64
# Kernel version 3.10 → Vulnerable!
```

**Exploitation:**
```bash
$ searchsploit DirtyCow
[*] DirtyCow CVE-2016-5195 Linux Privilege Escalation

$ # Download and compile
$ gcc -pthread dirty.c -o dirty -lutil
$ ./dirty

# Result: Root shell or backdoor user created
```

---

### Linux Kernel Exploits: Common CVEs

| CVE | Name | Affected | Impact |
|-----|------|----------|--------|
| **CVE-2016-5195** | DirtyCow | Linux < 4.8.3 | Privilege Escalation |
| **CVE-2021-4034** | PwnKit | Linux (systemd) | Privilege Escalation |
| **CVE-2021-22555** | Netfilter | Linux 4.x | Privilege Escalation |
| **CVE-2019-1010317** | ptrace | Linux < 5.3 | Privilege Escalation |
| **CVE-2017-1000112** | UFO | Linux < 4.13 | Privilege Escalation |

---

### Windows Kernel Exploits: Common CVEs

| CVE | Name | Affected | Impact |
|-----|------|----------|--------|
| **CVE-2014-6324** | Kerberos DoublePulsar | Windows Server 2012 R2 | Privilege Escalation |
| **CVE-2016-3225** | Win32k | Windows 7/8/10 | Privilege Escalation |
| **CVE-2017-0005** | GDI | Windows 7/8/10 | Privilege Escalation |
| **CVE-2018-8611** | Win32k | Windows 10 | Privilege Escalation |

---

### ⚠️ Critical Warnings: Kernel Exploits

**Danger 1: System Instability**

```
Kernel exploits interact with core system components
Buggy exploit → System crash
Success might still cause instability
Production systems at risk
```

**Best Practice:**
```
✓ Test in lab environment first
✓ Understand what exploit does
✓ Have rollback plan
✓ Never on production without approval
```

---

**Danger 2: Data Loss**

```
Kernel exploit crashes system
Unsaved data lost
Running processes terminated
File system might be corrupted
```

**Mitigation:**
```
✓ Coordinate with client
✓ Schedule during maintenance window
✓ Have backups ready
✓ Document your actions
```

---

**Danger 3: Detection**

```
Kernel exploits create system events
Crash = obvious sign of compromise
Suspicious processes = detected
Stability issues = admin investigation
```

**Solution:**
```
✓ Use stealthier exploits first
✓ Use kernel exploit as last resort
✓ Clean up logs if possible
✓ Document reason for instability
```

---

### Kernel Exploit Methodology

**Step 1: Identify Version**
```bash
$ uname -a
Linux target 3.10.0-514.el7.x86_64
```

**Step 2: Search for Vulnerabilities**
```bash
$ searchsploit 3.10.0
# Or
$ google "3.10.0 linux kernel exploit"
```

**Step 3: Assess Applicability**
```
- Is this the right kernel version?
- Does exploit apply to your CPU architecture (x86/x64)?
- Are dependencies available (gcc, etc.)?
```

**Step 4: Obtain Exploit**
```bash
# From SearchSploit
$ searchsploit -m linux/local/40844.c

# Or from GitHub/Exploit-DB
$ wget https://raw.githubusercontent.com/.../exploit.c
```

**Step 5: Compile (if needed)**
```bash
$ gcc -o exploit exploit.c -pthread
# Or
$ python3 exploit.py
# Or
$ ./exploit.sh (already compiled)
```

**Step 6: Execute with Caution**
```bash
$ ./exploit
# Monitor for crashes/errors
# Check if root access achieved
```

**Step 7: Verify Success**
```bash
$ id
uid=0(root) gid=0(root) groups=0(root)
# SUCCESS!
```

---

## Vector 2: Vulnerable Software

### The Concept

```
Installed outdated application
    ↓
Contains known security vulnerability
    ↓
Public exploit available
    ↓
Exploit vulnerability → Get root access
```

**Key Insight:**
```
Old software = Known vulnerabilities
Public exploits available
Often easier than kernel exploits
```

---

### How to Find Installed Software

**On Linux:**

```bash
# List all installed packages
$ dpkg -l
# Shows: package name, version, description

# Example:
ii  openssh-server    1:7.4p1-10
ii  apache2           2.4.41-1
ii  mysql-server      8.0.23-0
```

**Better formatting:**
```bash
$ dpkg -l | grep -i mysql
ii  mysql-server      8.0.23-0
```

**Find specific version:**
```bash
$ dpkg -l | grep apache
ii  apache2           2.4.41-1
```

---

**On Windows:**

```cmd
# Check Program Files
C:\> dir "C:\Program Files"
C:\> dir "C:\Program Files (x86)"

# Or use PowerShell
PS> Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
```

**See all installed software with versions:**
```cmd
C:\> wmic product list brief
```

---

### Example: Vulnerable Apache Version

**Discovered:**
```bash
$ dpkg -l | grep apache
ii  apache2  2.4.10-1

$ apache2 -v
Server version: Apache/2.4.10 (Debian)
```

**Search for Exploits:**
```bash
$ searchsploit apache 2.4.10
# Results:
# - CVE-2021-41773 (Apache 2.4.50)
# - CVE-2021-42013 (Apache 2.4.50)
# ... many others

# Or Google:
# "apache 2.4.10 exploit"
# "Apache 2.4.10 CVE"
```

**Check for Path Traversal:**
```bash
# Apache 2.4.49+ has path traversal
# But 2.4.10 might have different vulns
# Search for specific CVEs affecting 2.4.10
```

---

### Example: Vulnerable MySQL Version

**Discovered:**
```bash
$ mysql --version
mysql  Ver 14.14 Distrib 5.7.20

$ # This is old! Current is 8.0+
```

**Search for Exploits:**
```bash
$ searchsploit mysql 5.7.20
# Results: Multiple privilege escalation vectors

$ searchsploit "mysql 5.7" privilege escalation
```

**Common MySQL PrivEsc Vectors:**

1. **UDF Exploitation**
   ```
   MySQL running as root
   Can load custom libraries (UDF)
   Create backdoor library
   Execute commands as root
   ```

2. **Plugin Exploitation**
   ```
   Vulnerable MySQL plugins
   Execute code through plugins
   Gain root execution
   ```

---

### How to Identify Vulnerable Software Versions

**Method 1: Online Vulnerability Database**

```
1. Know the software: Apache, MySQL, PHP, etc.
2. Know the version: 2.4.10, 5.7.20, 7.4.3, etc.
3. Search CVE database:
   https://cve.mitre.org/cgi-bin/cvename.cgi?name=
   
4. Check if vulnerabilities are available
5. Check if public exploits exist
```

**Method 2: SearchSploit**

```bash
# Exact software + version
$ searchsploit apache 2.4.10

# Or multiple versions
$ searchsploit "apache 2.4"

# Look for:
# - Local privilege escalation
# - Remote code execution
# - Configuration issues
```

**Method 3: GitHub Exploit Repositories**

```
Search GitHub for:
"apache 2.4.10 exploit"
"apache 2.4.10 rce"

Many security researchers publish exploits on GitHub
```

---

### Software Vulnerability Exploitation Workflow

**Step 1: List Installed Software**

Linux:
```bash
$ dpkg -l
# Note all software and versions
```

Windows:
```cmd
C:\> Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
```

**Step 2: Note Interesting Software**

```
Look for:
✓ Old versions (3+ years old)
✓ Server software (Apache, MySQL, etc.)
✓ Popular targets (PHP, Java, etc.)
✓ Rarely updated (embedded systems, appliances)
```

**Step 3: Search for Vulnerabilities**

```bash
$ for app in apache2 mysql php; do
    searchsploit "$app" | head -5
  done
```

**Step 4: Assess Exploitability**

```
Questions to ask:
- Does exploit apply to my version?
- Is the vulnerability local or remote?
- Do I have required permissions?
- Are dependencies available?
- How stable is the exploit?
```

**Step 5: Obtain and Verify Exploit**

```bash
# Download
$ searchsploit -m path/to/exploit.c

# Read the code
$ cat exploit.c
# Look for version check, dependencies, etc.

# Compile if needed
$ gcc -o exploit exploit.c
```

**Step 6: Execute and Verify**

```bash
$ ./exploit
# Monitor output
# Check for success indicators

$ id
# Should show elevated privileges
```

---

## Common Vulnerable Software in Linux

| Software | Vulnerable Versions | Common Exploit | Impact |
|----------|-------------------|---------------|---------:|
| **Apache** | 2.4.49-2.4.50 | Path Traversal | RCE/PrivEsc |
| **MySQL/MariaDB** | 5.x, < 8.0.12 | UDF Loading | PrivEsc |
| **PHP** | < 7.0.0 | Various | RCE/PrivEsc |
| **sudo** | < 1.9.5 | Heap Overflow | PrivEsc |
| **OpenSSH** | < 7.4 | Username Enumeration | Info Disclosure |
| **Vim** | < 7.4.1157 | Modeline | RCE |

---

## Common Vulnerable Software in Windows

| Software | Vulnerable Versions | Common Exploit | Impact |
|----------|-------------------|---------------|---------:|
| **IIS** | < 10.0 | Various | RCE/PrivEsc |
| **SQL Server** | 2012, 2014 | UNC Path Injection | RCE |
| **PowerShell** | < 5.0 | Execution Policy Bypass | RCE |
| **WinRM** | Unpatched | Various | RCE |
| **SMBv3** | Unpatched | Various | RCE |

---

## Priority: What to Look for First

### High Priority (High Likelihood of Exploitation)

```
1. Kernel exploits (if old kernel)
2. Apache/web server vulnerabilities
3. Database software (MySQL, MSSQL)
4. Sudo/privilege management issues
5. Outdated scripting languages
```

### Medium Priority

```
6. Services running as root
7. Installed development tools
8. Custom applications
9. Monitoring/logging software
10. Backup utilities
```

### Low Priority (Harder to Exploit)

```
11. Client applications
12. System utilities
13. Recently patched software
14. Niche software
```

---

## Key Takeaways - Part 2: Common Vectors

1. **Kernel exploits:**
   - Identify OS version
   - Search for known CVEs
   - Test in lab first
   - Use as last resort (unstable)

2. **Vulnerable software:**
   - Identify all installed packages
   - Check version numbers
   - Search for public exploits
   - Often easier than kernel exploits

3. **Finding software:**
   - Linux: `dpkg -l`
   - Windows: `C:\Program Files`, PowerShell, WMIC
   - Note versions carefully

4. **Exploitation workflow:**
   - Identify software
   - Find vulnerability
   - Obtain exploit
   - Test in lab
   - Execute carefully
   - Verify success

5. **Priority approach:**
   - Kernel first (if applicable)
   - Then software exploits
   - Then other vectors
   - Use least disruptive first

6. **Safety considerations:**
   - Lab test first
   - Get explicit approval
   - Have rollback plan
   - Monitor for crashes
   - Document everything

---

## Notes