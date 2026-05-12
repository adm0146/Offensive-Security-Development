# Section 13 — Skills Assessment

> Given only an IP, enumerate all vhosts, extensions, pages, parameters, and values to retrieve a flag.

---

## Answers

| Question | Answer |
|----------|--------|
| Q1 — Vhosts on *.academy.htb | `archive`, `test`, `faculty` |
| Q2 — Extensions accepted | `.php`, `.phps`, `.php7` |
| Q3 — "You don't have access!" page | `http://faculty.academy.htb:PORT/courses/linux-security.php7` |
| Q4 — Parameters on that page | `user`, `username` |
| Q5 — Flag | `HTB{w3b_fuzz1n6_m4573r}` |

---

## Full Methodology

### Step 1 — Vhost Fuzzing

```bash
# Find default response size
curl -s -o /dev/null -w "%{size_download}" \
  -H 'Host: fake.academy.htb' http://TARGET_IP:PORT/
# Returns: 985

ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u "http://TARGET_IP:PORT/" \
  -H 'Host: FUZZ.academy.htb' \
  -fs 985 -t 100 -s
# Found: archive, test, faculty
```

### Step 2 — Extension Fuzzing (on each vhost)

```bash
for vhost in archive test faculty; do
  echo "=== $vhost ==="
  ffuf -w ~/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ \
    -u "http://TARGET_IP:PORT/indexFUZZ" \
    -H "Host: $vhost.academy.htb" \
    -mc 200,301,302,403 -t 100 -s
done
# archive/test: .php, .phps
# faculty:      .php, .phps, .php7
```

### Step 3 — Recursive Page Fuzzing

**Key:** Get default size per vhost/extension first, filter both the 0-byte empty files and the not-found size.

```bash
# Check default sizes
for vhost in archive test faculty; do
  for ext in php phps php7; do
    sz=$(curl -s -o /dev/null -w "%{size_download}" \
      -H "Host: $vhost.academy.htb" "http://TARGET_IP:PORT/fakepage.$ext")
    echo "$vhost .$ext = $sz"
  done
done

# Recursive scan with common.txt (fast) — filters out 0-byte empty pages and not-found sizes
ffuf -w ~/SecLists/Discovery/Web-Content/common.txt:FUZZ \
  -u "http://TARGET_IP:PORT/FUZZ" \
  -H "Host: faculty.academy.htb" \
  -recursion -recursion-depth 1 \
  -e .php,.phps,.php7 \
  -fs 0,281,284 \
  -v -ic -t 100
# Found: /courses/ directory → /courses/linux-security.php7
```

**Use `common.txt` not `directory-list-2.3-small.txt`** — the small list × 4 extensions × recursion = hours of scanning. common.txt finishes in minutes.

### Step 4 — Parameter Fuzzing (POST)

```bash
# Get default response size
curl -s -o /dev/null -w "%{size_download}" \
  -H "Host: faculty.academy.htb" \
  -X POST -d "foo=bar" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  "http://TARGET_IP:PORT/courses/linux-security.php7"
# Returns: 774

ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u "http://TARGET_IP:PORT/courses/linux-security.php7" \
  -H "Host: faculty.academy.htb" \
  -X POST -d "FUZZ=1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fs 774 -t 100 -s
# Found: user, username
```

### Step 5 — Value Fuzzing

**Critical lesson:** Don't assume numeric IDs. Check what the parameter name implies — `username` = try a names wordlist.

```bash
# Check what size "invalid" values return
curl -s -o /dev/null -w "%{size_download}" \
  -H "Host: faculty.academy.htb" \
  -X POST -d "username=invalidddd" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  "http://TARGET_IP:PORT/courses/linux-security.php7"
# Returns: 781

# Fuzz with names wordlist
ffuf -w ~/SecLists/Usernames/Names/names.txt:FUZZ \
  -u "http://TARGET_IP:PORT/courses/linux-security.php7" \
  -H "Host: faculty.academy.htb" \
  -X POST -d "username=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fs 774,781 -t 100 -s
# Found: harry

# Get the flag
curl -s \
  -H "Host: faculty.academy.htb" \
  -X POST -d "username=harry" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  "http://TARGET_IP:PORT/courses/linux-security.php7"
# HTB{w3b_fuzz1n6_m4573r}
```

---

## Lessons Learned

- **Vhost fuzzing** requires filtering the default response size — probe a fake vhost with curl first
- **Extension fuzzing** goes before page fuzzing — don't scan for `.php` pages on a `.php7` site
- **Use `common.txt`** for recursive scans, not big lists — the extension multiplier makes large lists impractical
- **Filter both noise sizes**: the 0-byte empty pages AND the not-found page size
- **Value type matters**: `username` param → names wordlist, not `seq 1 1000`
- **Two-step value fuzzing**: find the "invalid input" response size first, then filter it out alongside the default
