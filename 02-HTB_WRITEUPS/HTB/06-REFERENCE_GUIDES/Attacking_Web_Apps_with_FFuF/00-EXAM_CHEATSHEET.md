# FFuF — Exam Cheatsheet

## Full Attack Workflow

```
1. Vhost fuzz → find subdomains
2. Extension fuzz → find what file types each vhost uses
3. Recursive page fuzz (common.txt) → find pages with content
4. Parameter fuzz (GET + POST) → find hidden params
5. Value fuzz → find valid values, get flag
```

---

## 1. Vhost Fuzzing

```bash
# Probe default size
curl -s -o /dev/null -w "%{size_download}" -H 'Host: fake.domain.htb' http://TARGET_IP:PORT/

ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u "http://TARGET_IP:PORT/" -H 'Host: FUZZ.domain.htb' \
  -fs DEFAULT_SIZE -t 100 -s
```

## 2. Extension Fuzzing

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ \
  -u "http://TARGET_IP:PORT/indexFUZZ" \
  -H "Host: vhost.domain.htb" -mc 200,301,302,403 -t 100 -s
# web-extensions.txt includes the dot — write indexFUZZ not index.FUZZ
```

## 3. Recursive Page Fuzzing

```bash
# Probe all extension default sizes first
curl -s -o /dev/null -w "%{size_download}" -H "Host: vhost.domain.htb" "http://TARGET_IP:PORT/fake.php"

ffuf -w ~/SecLists/Discovery/Web-Content/common.txt:FUZZ \
  -u "http://TARGET_IP:PORT/FUZZ" -H "Host: vhost.domain.htb" \
  -recursion -recursion-depth 1 \
  -e .php,.phps,.php7 \
  -fs 0,NOT_FOUND_SIZE \
  -v -ic -t 100
# Use common.txt — large lists × extensions × recursion = hours
```

## 4. Parameter Fuzzing

```bash
# GET
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u "http://TARGET_IP:PORT/page.php?FUZZ=test" \
  -H "Host: vhost.domain.htb" -fs DEFAULT_SIZE -t 100 -s

# POST (PHP requires Content-Type header)
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u "http://TARGET_IP:PORT/page.php" \
  -H "Host: vhost.domain.htb" \
  -X POST -d 'FUZZ=test' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -fs DEFAULT_SIZE -t 100 -s
```

## 5. Value Fuzzing

```bash
# Numeric IDs
seq 1 1000 > /tmp/ids.txt

# Names (for user/username params)
~/SecLists/Usernames/Names/names.txt

# Fuzz
ffuf -w WORDLIST:FUZZ \
  -u "http://TARGET_IP:PORT/page.php" \
  -H "Host: vhost.domain.htb" \
  -X POST -d 'param=FUZZ' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -fs DEFAULT_SIZE,INVALID_SIZE -t 100 -s

# Retrieve content
curl -s -H "Host: vhost.domain.htb" \
  -X POST -d 'param=VALUE' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  "http://TARGET_IP:PORT/page.php"
```

---

## Key Flags Reference

| Flag | Purpose |
|------|---------|
| `-w WORDLIST:FUZZ` | Wordlist with keyword assignment |
| `-H 'Host: FUZZ.domain.htb'` | Vhost fuzzing |
| `-u "...?FUZZ=val"` | GET param fuzzing |
| `-X POST -d 'FUZZ=val'` | POST param fuzzing |
| `-e .php,.php7` | Append extensions to each wordlist entry |
| `-recursion -recursion-depth 1` | Auto-scan discovered directories (1 level) |
| `-fs SIZE1,SIZE2` | Filter by response size (comma-separated) |
| `-fw WORDS` | Filter by word count |
| `-fc CODE` | Filter by status code |
| `-ac` | Auto-calibrate filtering (alternative to manual -fs) |
| `-v` | Show full URL in results (required with recursion) |
| `-ic` | Ignore wordlist comment lines |
| `-t 100` | Threads (safe for remote; up to 200 for local) |
| `-s` | Silent — results only, no banner/progress |

---

## Wordlists Quick Reference

| Task | Wordlist |
|------|----------|
| Vhost/subdomain | `~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` |
| Extensions | `~/SecLists/Discovery/Web-Content/web-extensions.txt` |
| Pages (fast) | `~/SecLists/Discovery/Web-Content/common.txt` |
| Pages (thorough) | `~/SecLists/Discovery/Web-Content/raft-medium-directories.txt` |
| Parameters | `~/SecLists/Discovery/Web-Content/burp-parameter-names.txt` |
| Numeric values | `seq 1 1000 > /tmp/ids.txt` |
| Username values | `~/SecLists/Usernames/Names/names.txt` |

---

## /etc/hosts

```bash
sudo sh -c 'echo "TARGET_IP  domain.htb vhost1.domain.htb vhost2.domain.htb" >> /etc/hosts'
```
