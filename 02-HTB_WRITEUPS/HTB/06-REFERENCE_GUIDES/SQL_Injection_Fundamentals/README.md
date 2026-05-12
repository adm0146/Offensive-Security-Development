# SQL Injection Fundamentals

Reference guides from the HTB Academy SQL Injection Fundamentals module. UNION-based extraction, auth bypass, file read/write, web shell deployment via MySQL.

---

## Reference Guides

- [00-EXAM_CHEATSHEET.md](00-EXAM_CHEATSHEET.md) — Complete SQLi payload reference: discovery, auth bypass, UNION enumeration, file ops, web shell, all lab answers.

- [01-Introduction.md](01-Introduction.md) — What SQLi is, impact, vulnerability classes.

- [02-Intro_to_Databases.md](02-Intro_to_Databases.md) — Relational DB fundamentals, tables, queries, why SQLi works.

- [03-Types_of_Databases.md](03-Types_of_Databases.md) — MySQL, PostgreSQL, MSSQL, Oracle, NoSQL — syntax differences that affect payloads.

- [04-Intro_to_MySQL.md](04-Intro_to_MySQL.md) — MySQL CLI basics, connection strings, system databases.

- [05-SQL_Statements.md](05-SQL_Statements.md) — SELECT, INSERT, UPDATE, DELETE, JOIN — what an SQLi attacker manipulates.

- [06-Query_Results.md](06-Query_Results.md) — ORDER BY, LIMIT, WHERE, LIKE; lab: finding `Mitchem`.

- [07-SQL_Operators.md](07-SQL_Operators.md) — AND/OR/NOT, operator precedence; lab: `654` titles.

- [08-Intro_to_SQL_Injections.md](08-Intro_to_SQL_Injections.md) — Injection types tree: in-band, blind, out-of-band.

- [09-Subverting_Query_Logic.md](09-Subverting_Query_Logic.md) — OR-based auth bypass; payload `tom' or '1'='1`; flag.

- [10-Using_Comments.md](10-Using_Comments.md) — `-- -` and `#` comments, parenthesis-aware bypass for nested WHERE clauses.

- [11-Union_Clause.md](11-Union_Clause.md) — UNION rules, column count padding with NULL, type compatibility.

- [12-Union_Injection.md](12-Union_Injection.md) — ORDER BY column count probe, visible column detection, extracting DB version/user/database.

- [13-Database_Enumeration.md](13-Database_Enumeration.md) — INFORMATION_SCHEMA enumeration: schemata → tables → columns → data with dot notation.

- [14-Reading_Files.md](14-Reading_Files.md) — FILE privilege check, `LOAD_FILE()`, reading source code and config files.

- [15-Writing_Files.md](15-Writing_Files.md) — `secure_file_priv` check, `INTO OUTFILE`, writing a PHP web shell for RCE.

- [16-Mitigating_SQL_Injection.md](16-Mitigating_SQL_Injection.md) — Defenses: parameterized queries, sanitization, validation, least privilege, WAF.

- [17-Skills_Assessment.md](17-Skills_Assessment.md) — chattr.htb HTTPS app: invitation code bypass → UNION injection on `q=` → admin Argon2i hash → webroot via `LOAD_FILE` → PHP shell via `INTO OUTFILE` → flag.
