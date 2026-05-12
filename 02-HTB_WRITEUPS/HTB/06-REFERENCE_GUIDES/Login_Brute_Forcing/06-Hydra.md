# Section 6 — Hydra

> Reference + command examples. No lab.

---

## What Is Hydra?

Fast, parallel network login cracker. Supports 50+ protocols. Pre-installed on Kali.

```bash
hydra -h        # verify installed
```

---

## Syntax

```bash
hydra [login_options] [password_options] [attack_options] service://target
```

---

## Key Flags

| Flag | Purpose | Example |
|------|---------|---------|
| `-l LOGIN` | Single username | `-l admin` |
| `-L FILE` | Username wordlist | `-L usernames.txt` |
| `-p PASS` | Single password | `-p password123` |
| `-P FILE` | Password wordlist | `-P /usr/share/wordlists/rockyou.txt` |
| `-t TASKS` | Parallel threads (default 16) | `-t 64` |
| `-f` | Stop after first valid login found | `-f` |
| `-s PORT` | Non-default port | `-s 2222` |
| `-V` | Verbose — show every attempt | `-V` |
| `-v` | Show successful logins only | `-v` |
| `-M FILE` | Target list (multiple hosts) | `-M targets.txt` |
| `-x MIN:MAX:CHARSET` | Generate passwords on the fly (brute force mode) | `-x 6:8:aA1` |

---

## Supported Services

| Service | Protocol | Command |
|---------|----------|---------|
| `ssh` | SSH | `hydra -l root -P pass.txt ssh://TARGET` |
| `ftp` | FTP | `hydra -l admin -P pass.txt ftp://TARGET` |
| `rdp` | RDP | `hydra -l admin -P pass.txt rdp://TARGET` |
| `smb` | SMB | `hydra -l admin -P pass.txt smb://TARGET` |
| `smtp` | SMTP | `hydra -l user@domain -P pass.txt smtp://TARGET` |
| `pop3` | POP3 | `hydra -l user@domain -P pass.txt pop3://TARGET` |
| `imap` | IMAP | `hydra -l user@domain -P pass.txt imap://TARGET` |
| `mysql` | MySQL | `hydra -l root -P pass.txt mysql://TARGET` |
| `mssql` | MSSQL | `hydra -l sa -P pass.txt mssql://TARGET` |
| `vnc` | VNC (no username) | `hydra -P pass.txt vnc://TARGET` |
| `http-get` | HTTP Basic Auth (GET) | `hydra -L users.txt -P pass.txt TARGET http-get` |
| `http-post-form` | Web login form (POST) | see below |

---

## Command Examples

### HTTP Basic Auth
```bash
hydra -L usernames.txt -P passwords.txt www.example.com http-get
```

### SSH (single cred)
```bash
hydra -l root -p toor ssh://TARGET
```

### SSH (multiple targets)
```bash
hydra -l root -p toor -M targets.txt ssh
```

### FTP on non-standard port
```bash
hydra -L usernames.txt -P passwords.txt -s 2121 -V ftp://ftp.example.com
```

### Web login form (POST) — success on HTTP 302 redirect
```bash
hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```

### Web login form (POST) — fail on error string
```bash
hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"
```

### RDP with generated passwords (brute force mode)
```bash
hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 rdp://192.168.1.100
```

---

## http-post-form Syntax Breakdown

```
"/path:param1=^USER^&param2=^PASS^:F=failure_string"
  ^      ^                              ^
  |      |                              |
  |      Form body — ^USER^ and         Failure condition:
  |      ^PASS^ are replaced each       F=string  → fail if response contains this
  URL    attempt                        S=string  → succeed if response contains this
  path                                  S=302     → succeed on HTTP 302 redirect
```

> **Getting the form params:** Open Burp, submit a bad login, capture the POST request — copy the body and replace the credential values with `^USER^` and `^PASS^`.

---

## Exam Notes

- `-f` is important — stops after the first hit, saves time and avoids lockouts
- `-t 64` is a safe thread count for remote targets; go higher on local/lab targets
- For web forms: always check whether success is a redirect (`S=302`) or a keyword (`S=Welcome`) — using the wrong condition gets false negatives
- `-V` is noisy but useful when debugging — switch to `-v` once confirmed working
- VNC has no username — omit `-l`/`-L` entirely
- `-x` generates passwords on the fly — use only when you know the password constraints (slow for large ranges)
