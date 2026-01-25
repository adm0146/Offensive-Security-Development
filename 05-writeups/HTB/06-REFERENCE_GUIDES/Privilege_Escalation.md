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

## Notes