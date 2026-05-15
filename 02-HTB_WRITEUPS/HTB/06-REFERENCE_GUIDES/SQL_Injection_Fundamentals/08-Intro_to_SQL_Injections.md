# Section 8 — Intro to SQL Injections

> Theory only. No lab.

---

## How Web Apps Use SQL

Here is an example of unsafe PHP (a web scripting language) query construction:

```php
$searchInput = $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

User input drops straight into the query string with no checking. Whatever the user types becomes part of the SQL sent to the database.

---

## How Injection Works

**Normal input:** `admin` → query becomes `... like '%admin'` — works as intended.

**Injection input:** `1'; DROP TABLE users;` → query becomes:
```sql
select * from logins where username like '%1'; DROP TABLE users;'
```

The `'` after `1` **closes the string context**, allowing raw SQL to follow. The original query ends, and a new one executes.

> **Sanitization** means stripping or escaping special characters — especially `'` and `"` — so they cannot break out of the string context and alter the query.

---

## Syntax Errors and Why They Happen

Injecting without accounting for the rest of the original query causes syntax errors:

```sql
select * from logins where username like '%1'; DROP TABLE users;'
                                                                 ^--- orphan quote = error
```

Fix strategies:
- **Comments** (`--`, `#`, `/**/`) — comment out the rest of the original query
- **Balanced quotes** — carefully close all open strings

---

## Types of SQL Injection

```
SQL Injections
├── In-Band (output visible in response)
│   ├── Union-Based   — append a UNION SELECT to return data in the normal response
│   └── Error-Based   — trigger SQL errors that leak data in the error message
├── Blind (no direct output)
│   ├── Boolean-Based — true/false conditions change page behavior (content present or not)
│   └── Time-Based    — true/false conditions trigger SLEEP() delays
└── Out-of-Band       — exfiltrate data via DNS/HTTP requests to attacker-controlled server
```

> **This module focuses on Union-Based injection.** Blind and OOB are covered in later modules.

---

## Exam Notes

- The injection point is wherever user input enters a SQL query — form fields, URL params, cookies, headers
- `'` is the primary escape character for string context; `"` works too depending on the query
- Stacked queries (`;`) work in MSSQL/PostgreSQL but **not MySQL** — MySQL requires UNION or subquery techniques
- Always close syntax properly — a trailing orphan quote causes errors that may reveal DB type and query structure (useful for recon)
- Error messages are intelligence: they often expose the DB type, query fragment, and column names
