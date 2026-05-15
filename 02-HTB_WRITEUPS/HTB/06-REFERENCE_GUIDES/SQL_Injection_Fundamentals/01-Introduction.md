# Section 1 — Introduction

> Theory only. No lab.

---

## What is SQL Injection?

SQL Injection (SQLi) happens when an attacker puts special characters into user input to change the SQL query that the web application sends to its database. The database then runs unintended queries it was never supposed to execute.

**How it happens:**
1. The app takes user input and drops it directly into a SQL query without checking it first
2. The attacker adds special characters (`'` or `"`) that break out of the expected input context
3. The attacker adds malicious SQL that changes or adds new query logic
4. Results come back in the app's response, or the attacker infers them from app behavior

> This module focuses on **MySQL** and relational databases. MongoDB-style attacks are called NoSQL injection — that is a different topic covered elsewhere.

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
