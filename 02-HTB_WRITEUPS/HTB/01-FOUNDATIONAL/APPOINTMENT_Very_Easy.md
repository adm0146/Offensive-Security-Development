# APPOINTMENT - Very Easy Writeup

## Box Summary
**Difficulty:** Very Easy  
**Focus:** SQL Injection (SQLi) fundamentals  
**Key Concepts:** Database queries, authentication bypass, comment-based injection  
**Skills Learned:** SQL basics, web enumeration, injection attacks, OWASP Top 10 vulnerabilities

---

## Reconnaissance & Initial Enumeration

### Nmap Port Scan
Starting with a quick port scan to identify running services:

```bash
nmap-port TARGET_IP
```

**Results:**
- Port 80 (HTTP): Apache 2.4.38 (Debian)

### Initial Service Enumeration
Since we identified Apache 2.4.38, the first step is checking for known vulnerabilities specific to this version:

```bash
# Search for Apache 2.4.38 CVEs
# Result: No direct critical vulnerabilities found for this version
```

**Finding:** Apache version is not the attack vector here.

---

## Web Interface Enumeration

### Accessing the Web Application
Navigating to `http://TARGET_IP/` on port 80, we encounter a simple login prompt screen:

```
╔════════════════════════════════════════╗
║         LOGIN FORM                     ║
║  Username: [____________]              ║
║  Password: [____________]              ║
║  [Login Button]                        ║
╚════════════════════════════════════════╝
```

**Observation:** Standard web login interface with two input fields (username and password).

### Testing Default Credentials
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

### Directory Enumeration with Gobuster
Next, we search for hidden directories that might reveal additional attack surfaces:

```bash
gobuster dir -u http://TARGET_IP/ -w /usr/share/secLists/Discovery/Web-Content/common.txt
```

**Result:** No hidden directories discovered. The application is intentionally simple.

---

## Exploitation: SQL Injection (SQLi)

### Understanding SQL Injection
**SQL (Structured Query Language)** is a programming language designed for database management. It enables quick navigation through large datasets, allowing developers to compare, contrast, and extract meaningful data across numerous tables and attributes.

**SQL Injection** is a security vulnerability where an attacker bypasses normal web interface restrictions and interacts directly with the underlying SQL database. Instead of using the intended login form, the attacker injects malicious SQL queries to manipulate database behavior and extract sensitive information.

**OWASP Classification:** A03:2021-Injection (OWASP Top 10 - 2021)

### SQL Injection Mechanism
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

### Executing the Attack

1. **Navigate to the login page** at `http://TARGET_IP/`

2. **Inject the SQLi payload:**
   - Username field: `admin'#`
   - Password field: `anything` (or leave blank)

3. **Click Login**

4. **Result:** Authentication bypass successful! We gain access to the application.

---

## Flag Retrieval

Upon successful SQL injection authentication, we access the application dashboard and retrieve the flag.

**Flag:** `FLAG{SQL_INJECTION_BASICS}`

---

## Key Takeaways

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

### Mitigation Strategies
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

## Timeline

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

## Command Reference

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

## Educational Value

This box provides essential foundational knowledge for understanding SQL Injection:
- How SQL queries work at a basic level
- How user input interacts with database queries
- The power of SQL comment syntax in exploitation
- The difference between conceptual understanding and practical exploitation
- Why input validation is critical in web development

**Note:** This is a basic SQLi demonstration using simple comment syntax. More advanced SQLi techniques include:
- UNION-based injection (for data extraction)
- Boolean-based blind SQLi (when output is hidden)
- Time-based blind SQLi (inferring data through timing)
- Error-based SQLi (leveraging database error messages)

A comprehensive SQL Injection reference guide will be developed separately to cover these advanced techniques.

---

## Lessons Learned

✅ **SQL fundamentals matter** - Understanding query structure is essential for exploitation  
✅ **Comment syntax is powerful** - Different databases have different comment characters (`#`, `--`, `/* */`)  
✅ **Enumeration methodology applies everywhere** - Even simple boxes require systematic reconnaissance  
✅ **Input validation is critical** - This vulnerability could be eliminated with basic sanitization  
✅ **Authentication is often the target** - Bypassing login is frequently the first step in exploitation  

