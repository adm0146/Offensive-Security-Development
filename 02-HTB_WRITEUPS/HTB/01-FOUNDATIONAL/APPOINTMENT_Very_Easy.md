# APPOINTMENT - Very Easy

**Date Completed:** January 29, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE  
**Focus Areas:** SQL Injection Fundamentals & Authentication Bypass

---

## Phase 1: Initial Reconnaissance

### Step 1: Port Scanning
```
nmap-port TARGET_IP
```

**Findings:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 80 | HTTP | Apache 2.4.38 (Debian) | Open |

**Critical Finding:** Web application exposed on standard HTTP port - simple login interface

### Step 2: CVE Analysis for Apache 2.4.38
Checking for known vulnerabilities specific to this Apache version:

```bash
# Search CVE databases for Apache 2.4.38
# Result: No direct critical vulnerabilities found for this version
```

**Finding:** Apache version is not the attack vector here.

---

## Phase 2: Web Application Enumeration

### Step 1: Initial Web Interface Assessment
Navigating to `http://TARGET_IP/` on port 80, we encounter a simple login prompt:

```
Login Form
├── Username: [____________]
├── Password: [____________]
└── [Login Button]
```

**Observation:** Standard web login interface with two input fields (username and password).

### Step 2: Testing Default Credentials
Before diving into technical exploitation, we attempt common default credentials:

```
Admin / Admin
Admin / admin
Admin / password
Admin / 123456
Root / Root
Guest / Guest
```

**Result:** All attempts failed. Default credentials are not an entry vector.

### Step 3: Directory Enumeration with Gobuster
Next, we search for hidden directories that might reveal additional attack surfaces:

```bash
gobuster dir -u http://TARGET_IP/ -w /usr/share/secLists/Discovery/Web-Content/common.txt
```

**Result:** No hidden directories discovered. The application is intentionally simple.

---

## Phase 3: SQL Injection Exploitation

### Understanding SQL Injection
**SQL Injection** is a security vulnerability where an attacker bypasses normal web interface restrictions and interacts directly with the underlying SQL database. Instead of using the intended login form, the attacker injects malicious SQL queries to manipulate database behavior and extract sensitive information.

**OWASP Classification:** A03:2021-Injection (OWASP Top 10 - 2021)

### How Login Queries Work
Most login forms execute a query similar to this:

```sql
SELECT * FROM users WHERE username='USERNAME' AND password='PASSWORD';
```

When you enter normal credentials (e.g., admin / password), the query becomes:

```sql
SELECT * FROM users WHERE username='admin' AND password='password';
```

The database checks if this combination exists. If yes, login succeeds; if no, login fails.

### Step 1: Executing the Attack

1. Navigate to the login page at `http://TARGET_IP/`

2. Enter the SQL injection payload:
   - Username field: `admin'#`
   - Password field: `anything` (or leave blank)

3. Click Login

4. **Result:** Authentication bypass successful! We gain access to the application.

---

## Phase 4: Flag Retrieval

Upon successful SQL injection authentication, we access the application dashboard and retrieve the flag.

**Flag:** `FLAG{SQL_INJECTION_BASICS}`

---

## SQL Injection Deep Dive

### How the Injection Works
Most login forms execute a query similar to this:

```sql
SELECT * FROM users WHERE username='USERNAME' AND password='PASSWORD';
```

When you enter normal credentials (e.g., admin / password), the query becomes:

```sql
SELECT * FROM users WHERE username='admin' AND password='password';
```

The database checks if this combination exists. If yes, login succeeds; if no, login fails.

### The Comment-Based Bypass
SQL injection exploits this logic by using database comment syntax. In MySQL, the `#` character marks everything after it as a comment, causing the database to ignore that portion of the query.

**Injection Payload:** `admin'#`

When we enter:
- **Username:** `admin'#`
- **Password:** (anything - it will be ignored)

The resulting query becomes:

```sql
SELECT * FROM users WHERE username='admin'# AND password='PASSWORD';
```

The database interprets this as:

```sql
SELECT * FROM users WHERE username='admin'
-- (everything after '#' is ignored/commented out)
```

**Result:** The password check is bypassed entirely. If the user 'admin' exists, authentication succeeds regardless of the password field.

---

## Phase 5: Key Takeaways & Vulnerability Analysis

### Vulnerability Chain
1. **Improper Input Validation:** The application does not sanitize or validate user input before using it in SQL queries
2. **Direct Query Construction:** SQL queries are built by concatenating user input directly into query strings
3. **Comment Syntax Exploitation:** SQL comment characters (`#`, `--`, `/* */`) can be abused to modify query logic
4. **No Authentication Hardening:** Simple string matching without parameterized queries or prepared statements

### Why This Works
- **Database Perspective:** When a user enters `admin'#`, the database sees `username='admin'` (the quote closes the string, and everything after `#` is a comment)
- **Authentication Logic:** The password field is never evaluated because it's commented out
- **Assumption Violation:** The application assumes user input will be simple text, not SQL syntax

### Real-World Implications
- SQL Injection is one of the oldest and most prevalent web vulnerabilities
- It can lead to:
  - Authentication bypass (as seen here)
  - Data exfiltration (SELECT queries)
  - Data manipulation (INSERT/UPDATE/DELETE queries)
  - Potential remote code execution (depending on database permissions)
  - Complete database compromise

### Vulnerability Chain
1. **Improper Input Validation:** The application does not sanitize or validate user input before using it in SQL queries
2. **Direct Query Construction:** SQL queries are built by concatenating user input directly into query strings
3. **Comment Syntax Exploitation:** SQL comment characters (`#`, `--`, `/* */`) can be abused to modify query logic
4. **No Authentication Hardening:** Simple string matching without parameterized queries or prepared statements

### Why This Works
- **Database Perspective:** When a user enters `admin'#`, the database sees `username='admin'` (the quote closes the string, and everything after `#` is a comment)
- **Authentication Logic:** The password field is never evaluated because it's commented out
- **Assumption Violation:** The application assumes user input will be simple text, not SQL syntax

### Real-World Implications
- SQL Injection is one of the oldest and most prevalent web vulnerabilities
- It can lead to:
  - Authentication bypass (as seen here)
  - Data exfiltration (SELECT queries)
  - Data manipulation (INSERT/UPDATE/DELETE queries)
  - Potential remote code execution (depending on database permissions)
  - Complete database compromise
---

## Mitigation Strategies

1. **Parameterized Queries (Prepared Statements):** Use query placeholders instead of string concatenation
   ```php
   // Vulnerable
   $query = "SELECT * FROM users WHERE username='" . $username . "'";
   
   // Secure
   $stmt = $pdo->prepare("SELECT * FROM users WHERE username=?");
   $stmt->execute([$username]);
   ```

2. **Input Validation:** Whitelist acceptable characters for username/password fields

3. **Principle of Least Privilege:** Database users should have minimal necessary permissions

4. **Web Application Firewall (WAF):** Detect and block common SQLi patterns

5. **Error Handling:** Don't display raw database errors to users (information leakage)

---

## Exploitation Timeline

| Step | Action | Result |
|------|--------|--------|
| 1 | Nmap port scan | Identified Apache 2.4.38 on port 80 |
| 2 | Check Apache CVEs | No direct vulnerabilities found |
| 3 | Web interface assessment | Simple login form discovered |
| 4 | Default credentials | Authentication failed |
| 5 | Gobuster directory scan | No hidden directories |
| 6 | SQL Injection research | Identified comment-based bypass technique |
| 7 | Payload injection: `admin'#` | Authentication bypass successful |
| 8 | Access dashboard | Flag retrieved |

---

## Commands Used

```bash
# Reconnaissance
nmap-port TARGET_IP                    # Quick port scan
nmap -sV -p 80 TARGET_IP              # Service version detection

# Web Enumeration
curl http://TARGET_IP/                # Fetch login page
gobuster dir -u http://TARGET_IP/ -w /usr/share/secLists/Discovery/Web-Content/common.txt

# SQL Injection Testing
# Input in username field: admin'#
# Input in password field: anything
# Expected result: Authentication bypass
```

---

## Key Learning Outcomes

✅ **SQL fundamentals matter** - Understanding query structure is essential for exploitation  
✅ **Comment syntax is powerful** - Different databases have different comment characters (`#`, `--`, `/* */`)  
✅ **Enumeration methodology applies everywhere** - Even simple boxes require systematic reconnaissance  
✅ **Input validation is critical** - This vulnerability could be eliminated with basic sanitization  
✅ **Authentication is often the target** - Bypassing login is frequently the first step in exploitation  

**Note:** This is a basic SQLi demonstration using simple comment syntax. More advanced SQLi techniques include:
- UNION-based injection (for data extraction)
- Boolean-based blind SQLi (when output is hidden)
- Time-based blind SQLi (inferring data through timing)
- Error-based SQLi (leveraging database error messages)

A comprehensive SQL Injection reference guide will be developed separately to cover these advanced techniques.  

