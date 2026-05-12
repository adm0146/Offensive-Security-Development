# Section 1 — Introduction

> Theory only. No lab.

---

## What is SQL Injection?

A SQL injection (SQLi) occurs when an attacker manipulates user input to alter the SQL query sent by the web application to its database — executing unintended queries directly against it.

**How it happens:**
1. App takes user input and embeds it directly in a SQL query (no sanitization)
2. Attacker injects special characters (`'` or `"`) to break out of the expected input context
3. Attacker appends malicious SQL to change or add query logic
4. Results are returned to the front-end or inferred from app behavior

> This module focuses on **MySQL** and relational databases. MongoDB-style attacks are NoSQL injection — different topic.

---

## Attack Flow

```
User input → embedded in SQL query → ' or " breaks context → injected SQL executes
```

**Methods to execute additional queries:**
- **Stacked queries** — `;` to run a second query after the first
- **UNION queries** — append a second SELECT to retrieve data from other tables
- **Boolean/blind** — infer data from true/false app behavior
- **Error-based** — extract data from database error messages

---

## Impact

| What You Can Do | Example |
|----------------|---------|
| Dump sensitive data | Usernames, passwords, credit cards |
| Bypass authentication | Login without valid credentials |
| Access restricted features | Admin panels locked to specific users |
| Read files from server | `/etc/passwd`, config files |
| Write files to server | Drop a webshell → RCE |
| Full server takeover | If DB user has elevated OS privileges |

---

## Why It Happens

- User input embedded directly in SQL queries without sanitization
- Overly permissive DB user privileges (DB user can read files, write files, execute OS commands)
- No input validation on the back-end

---

## Exam Notes

- SQLi only applies to **relational databases** (MySQL, MSSQL, PostgreSQL, Oracle) — not MongoDB
- The entry point is always user-controlled input that gets embedded in a query
- `'` and `"` are the primary injection characters — test both
- Impact escalates with DB privileges: data dump → auth bypass → file read/write → RCE
