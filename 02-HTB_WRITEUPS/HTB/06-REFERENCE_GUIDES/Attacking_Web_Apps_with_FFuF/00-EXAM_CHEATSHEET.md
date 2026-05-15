# Attacking Web Applications with FFuF — Exam Cheatsheet

---

## Full Attack Workflow

```
1. /etc/hosts entry → TARGET DOMAIN
2. Vhost fuzz       → discover internal-facing subdomains
3. Extension fuzz   → find what file types are valid (.php / .asp / .phtml)
4. Page fuzz        → enumerate endpoints
5. Recursive dir    → expand on directories
6. Parameter fuzz   → find hidden GET/POST params
7. Value fuzz       → enumerate IDs / usernames / valid values
```
> A step-by-step attack order to keep you from skipping steps. Always do extension fuzzing before page fuzzing — scanning for `.php` pages on a `.php7` server wastes every request.

---

## The FUZZ Keyword

`FUZZ` is the placeholder — wherever it appears in the URL, headers, body, or cookies, ffuf substitutes wordlist entries.

```bash
ffuf -u "http://TARGET/FUZZ" -w wordlist.txt              # URL path
ffuf -u "http://TARGET/" -H "Host: FUZZ.target.htb" -w sub.txt  # header
ffuf -u "http://TARGET/api?id=FUZZ" -w ids.txt            # GET param
ffuf -u "http://TARGET/login" -X POST -d "user=admin&pass=FUZZ" -w pw.txt  # POST body
```
> `FUZZ` is replaced with each wordlist entry. The four lines show the four places you can inject it: URL path, HTTP header, GET param, POST body.

Multiple FUZZ keywords (clusterbomb / pitchfork):
```bash
# Cluster bomb (every combination — default with multiple wordlists)
ffuf -u "http://TARGET/FUZZ.FUZ2Z" -w dirs.txt:FUZZ -w ext.txt:FUZ2Z

# Pitchfork (line-pairs — wordlist1[0] with wordlist2[0], etc.)
ffuf -u "http://TARGET/?user=FUZZ&pass=FUZ2Z" -w users.txt:FUZZ -w pws.txt:FUZ2Z -mode pitchfork
```
> Cluster bomb tests every combination of both wordlists. Pitchfork pairs them line-by-line — use pitchfork when one wordlist is usernames and the other is matching passwords.

---

## 1. Vhost Fuzzing

```bash
# Add /etc/hosts entry first
echo "10.10.10.10 inlanefreight.htb" | sudo tee -a /etc/hosts

# Fuzz the Host header — finds subdomains served by the same IP
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://inlanefreight.htb -H "Host: FUZZ.inlanefreight.htb" -fs 985

# -fs 985 filters out the default "size 985" response (default site fallback)
# Once you find a vhost (e.g. "archive"), add it to /etc/hosts:
echo "10.10.10.10 archive.inlanefreight.htb" | sudo tee -a /etc/hosts
```
> Each `echo` appends an IP-to-hostname mapping so your browser resolves the domain locally. The ffuf command fuzzes the `Host:` header, not the URL — this finds virtual hosts that aren't in public DNS. `-fs 985` hides the "default site" response so only real vhosts show up.

> **Why vhost fuzzing > DNS subdomain enum:** vhost discovers servers that aren't in public DNS — common for staging/internal apps.

---

## 2. Extension Fuzzing

Find what file extensions the server processes before brute-forcing names:

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ \
     -u http://target.htb/indexFUZZ -fs 0
# Tests: index.php index.asp index.aspx index.jsp ...
# Whichever returns 200 is your live extension
```
> `indexFUZZ` (not `index.FUZZ`) because `web-extensions.txt` already includes the dot. `-fs 0` removes empty responses. Use the result before page fuzzing so you scan for the right extension.

---

## 3. Page Fuzzing

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/raft-medium-words.txt:FUZZ \
     -u "http://target.htb/FUZZ.php"

# Faster with quickhits:
ffuf -w ~/SecLists/Discovery/Web-Content/quickhits.txt:FUZZ \
     -u "http://target.htb/FUZZ"
```
> Appending `.php` to every wordlist entry limits results to PHP files. Swap `.php` for the extension you found during extension fuzzing. `quickhits.txt` is a small curated list for fast initial checks.

---

## 4. Recursive Page Fuzzing

```bash
ffuf -w ~/SecLists/Discovery/Web-Content/raft-medium-directories.txt:FUZZ \
     -u "http://target.htb/FUZZ" \
     -recursion -recursion-depth 1 -e .php
# -recursion         = enter discovered dirs and fuzz them too
# -recursion-depth 1 = stop at one level deep (avoid endless loops)
# -e .php            = also try .php-extension variants
```
> `-recursion` tells ffuf to automatically fuzz any directory it finds. `-recursion-depth 1` limits it to one level down so the scan doesn't run forever. `-e .php` doubles the request count by also trying each word with `.php` appended.

---

## 5. Parameter Fuzzing

### GET parameters
```bash
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u "http://target.htb/page.php?FUZZ=key" -fs SIZE
# Find a hidden GET param that changes the response size
```
> Places `FUZZ` as the parameter name in the query string. Replace `SIZE` with the byte count of the default response (find it with a test curl first). A different size means the server recognized that parameter.

### POST parameters
```bash
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u "http://target.htb/page.php" -X POST \
     -d 'FUZZ=key' \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -fs SIZE
```
> Same idea as GET fuzzing but sends the parameter in the request body. `-X POST` switches the HTTP method. The `Content-Type` header is required so PHP parses the body correctly.

### JSON POST
```bash
ffuf -w params.txt:FUZZ \
     -u "http://target.htb/api/login" -X POST \
     -d '{"FUZZ":"key"}' \
     -H "Content-Type: application/json"
```
> Fuzzes parameter names inside a JSON body. The `Content-Type: application/json` header is required for the server to parse the JSON. Swap `"key"` for a test value relevant to the API.

---

## 6. Value Fuzzing

After finding a param name, fuzz its **value**:

```bash
# IDs
ffuf -w ~/SecLists/Fuzzing/numbers.txt:FUZZ -u "http://target.htb/user?id=FUZZ"

# Usernames
ffuf -w ~/SecLists/Usernames/Names/names.txt:FUZZ \
     -u "http://target.htb/login.php?username=FUZZ" -mc 200,302
```
> `FUZZ` is now in the value position instead of the parameter name position. For numeric IDs use a number list; for usernames use a names wordlist. `-mc 200,302` keeps only successful or redirect responses.

---

## Filters & Matchers (Reading Output)

ffuf shows everything by default — use filters to remove noise, matchers to whitelist hits.

### Filters (REMOVE matching responses)

| Flag | What it filters | When to use |
|------|-----------------|-------------|
| `-fc 404,403` | response codes | hide common "not found" responses |
| `-fs 985` | response size (bytes) | hide default page responses |
| `-fl 12` | response line count | when sizes vary slightly |
| `-fw 50` | response word count | for variable-size pages |
| `-ft 100` | response time (ms) | hide hangs/timeouts |
| `-fr 'regex'` | regex on body | filter by content pattern |
| `-fmode and` | combine filters with AND (default OR) | strict filtering |

### Matchers (KEEP only matching responses)

| Flag | Keeps responses where |
|------|----------------------|
| `-mc 200,302` | status codes match (default: 200,204,301,302,307,401,403,405,500) |
| `-ms 5000` | size matches |
| `-ml 50` | lines match |
| `-mw 100` | words match |
| `-mr 'regex'` | regex matches body |
| `-mc all` | match ALL codes (when default whitelist hides too much) |

### Examples

```bash
# Hide 404s and default pages, keep only 200/301/302
ffuf -u http://target.htb/FUZZ -w list.txt -fc 404 -fs 985

# Find anything with "admin" in the response
ffuf -u http://target.htb/FUZZ -w list.txt -mr 'admin'

# Login brute — only count 302 redirects (successful login)
ffuf -u http://target.htb/login -X POST -d "user=admin&pass=FUZZ" -w pw.txt -mc 302
```
> First command hides 404s and the default page size — leaves only real hits. `-mr 'admin'` keeps responses whose body contains "admin". The login brute uses `-mc 302` because a successful login usually redirects; failed logins stay on the same page with a 200.

---

## Auto-Calibration

When the server returns "200 OK page not found" pages instead of real 404s:

```bash
ffuf -u "http://target.htb/FUZZ" -w list.txt -ac
# -ac = auto-calibrate: ffuf sends a known-bad request first, learns the "false positive" response size, then filters it
# -acc = include custom seed words (e.g. -acc "ZZZZZZ")
```
> `-ac` probes a known-bad path first, measures the response size and word count, then filters out anything matching that baseline automatically. Use this instead of manually finding `-fs` values on soft-404 servers.

---

## Headers & Cookies Fuzzing

```bash
# Fuzz a header value (e.g. find rate-limit bypass by spoofed IP)
ffuf -u "http://target.htb/api/login" -X POST -d "u=admin&p=test" \
     -H "X-Forwarded-For: FUZZ" -w ips.txt -mc 200

# Fuzz auth cookies
ffuf -u "http://target.htb/admin" -b "session=FUZZ" -w sessions.txt -mc 200

# Fuzz API key in header
ffuf -u "http://target.htb/api" -H "X-API-Key: FUZZ" -w keys.txt -mc 200
```
> `-H` injects `FUZZ` into any HTTP header value. `-b` sets the cookie header. These are useful for finding IP-bypass headers, valid session tokens, or API keys. Replace the header name with whatever the app uses.

---

## Performance & Output

```bash
-t 100                  # 100 threads (default 40; tune up for fast targets)
-p 0.1                  # delay between requests (avoid rate limits)
-rate 50                # cap to 50 req/sec
-timeout 5              # per-request timeout
-maxtime 600            # stop scan after 10 minutes
-s                      # silent mode (no banner / less noise — pipe-friendly)

# Output formats
-o results.json -of json
-o results.csv  -of csv
-o results.md   -of md
-of all                 # write to all formats

# Resume an interrupted scan
ffuf ... -input-cmd 'cat resume_state' ...    # advanced
```
> `-t` and `-rate` together control throughput. Use `-p` to add a delay if the target rate-limits you. `-o` and `-of` save results to a file so you can review them later without re-running the scan.

---

## Proxy Through Burp

```bash
# Send all requests through Burp (lots of traffic):
ffuf -u http://target.htb/FUZZ -w list.txt -x http://127.0.0.1:8080

# Send only MATCHED responses to Burp (cleaner):
ffuf -u http://target.htb/FUZZ -w list.txt -replay-proxy http://127.0.0.1:8080
```
> `-x` routes every request through Burp — useful for debugging but generates a lot of traffic. `-replay-proxy` sends only the matched (interesting) responses to Burp so you can inspect them without the noise of thousands of 404s.

---

## Wordlists Quick Reference

| Wordlist | Path | Use |
|----------|------|-----|
| Common dirs | `~/SecLists/Discovery/Web-Content/common.txt` | Quick directory probe |
| Raft medium dirs | `~/SecLists/Discovery/Web-Content/raft-medium-directories.txt` | Standard dir brute |
| Raft medium words | `~/SecLists/Discovery/Web-Content/raft-medium-words.txt` | Page/word probe |
| Web extensions | `~/SecLists/Discovery/Web-Content/web-extensions.txt` | Extension fuzz |
| Subdomains 5k | `~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` | Fast vhost/sub probe |
| Subdomains 110k | `~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt` | Thorough sub enum |
| Burp param names | `~/SecLists/Discovery/Web-Content/burp-parameter-names.txt` | Param brute |
| API endpoints | `~/SecLists/Discovery/Web-Content/api/api-endpoints.txt` | API recon |
| Names (10k) | `~/SecLists/Usernames/Names/names.txt` | Value fuzz / username harvest |

---

## /etc/hosts Cheatsheet

Always set up `/etc/hosts` for HTB targets — vhosts and many redirects depend on hostname resolution.

```bash
echo "10.10.10.10 target.htb admin.target.htb dev.target.htb" | sudo tee -a /etc/hosts

# Verify:
cat /etc/hosts | grep target
```
> You can list multiple hostnames on one line — they all resolve to the same IP. Run the grep to confirm the entry was added before you try to browse the domain.

---

## STUCK? Triage

| Symptom | Fix |
|---------|-----|
| Every request returns 200 | Use `-ac` (auto-calibrate) or `-fs` to filter the false-positive size |
| Too many hits to read | Tighten with `-fc 404 -fs 985 -fl 12` |
| Hits 401/403 | Try `-H "Cookie: session=..."` or `-H "Authorization: Bearer ..."` |
| Vhost fuzz shows no results | Did you add `Host: FUZZ.domain.htb` header? `-u http://IP -H "Host: FUZZ.target.htb"` |
| Rate-limited / 429s | `-rate 10 -p 0.5` (cap rate, add delay) |
| Page redirects to login | `-mc 302` to find auth pages; `-mc 200,302` for general |
| Need to filter regex content | `-fr 'access denied'` |
| Param fuzz no different sizes | App might process params silently — try `-fr 'error'` or `-mr 'invalid'` |

---

## Skills Assessment Answers (memorize the chain)

```
Vhosts:        archive, test, faculty   (filtered default 985-byte response)
Extensions:    .php and .phps on all; .php7 additionally on faculty
Page:          http://faculty.academy.htb:PORT/courses/linux-security.php7
Parameters:    user and username (POST, burp-parameter-names.txt)
Flag:          HTB{w3b_fuzz1n6_m4573r}   (username=harry, names.txt wordlist)
```
