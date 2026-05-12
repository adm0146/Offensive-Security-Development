# Section 3 — Directory Fuzzing

> Find hidden directories on a web server by sending requests for every word in a wordlist.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Other directory besides /blog | `forum` |

---

## Basic Directory Fuzzing

```bash
ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt \
  -u http://TARGET_IP:PORT/FUZZ \
  -ic

# -w  = wordlist path (FUZZ keyword is default if not specified with :FUZZ)
# -u  = target URL with FUZZ where the directory name goes
# -ic = ignore comment lines in wordlist (lines starting with #)
#       Always use this with directory-list-2.3 — it starts with copyright comments
```

**With explicit keyword assignment:**
```bash
ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt:FUZZ \
  -u http://TARGET_IP:PORT/FUZZ \
  -ic
# :FUZZ after the wordlist path assigns the keyword name
# This matters when using multiple wordlists with different keywords
```

---

## Common ffuf Flags for Directory Scanning

```bash
ffuf -w WORDLIST -u http://TARGET/FUZZ \
  -ic              # ignore wordlist comments
  -t 100           # threads (default 40, max ~200 — don't go too high on remote targets)
  -mc 200,301,302  # only show these status codes (default: 200,204,301,302,307,401,403)
  -fc 404          # filter OUT this status code
  -fs 0            # filter OUT responses with size 0 (empty pages)
  -fw 20           # filter OUT responses with exactly 20 words (common for error pages)
  -c               # colorize output
  -v               # verbose — shows full URL in results
  -o output.json   # save results to file
  -of json         # output format (json, csv, html, md)
```

---

## Wordlist Paths on Kali

```bash
# dirbuster wordlists (built-in):
/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt    # ~87k entries, fast
/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt   # ~220k entries, thorough

# SecLists (if installed at ~/SecLists/):
~/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
~/SecLists/Discovery/Web-Content/common.txt                    # ~4.7k, very fast
~/SecLists/Discovery/Web-Content/raft-medium-directories.txt   # good balance
```

---

## Reading the Results

```
blog    [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 202ms]
forum   [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 434ms]
```

| Status | Meaning |
|--------|---------|
| 200 | Page exists and is accessible |
| 301/302 | Redirect — directory exists, server redirecting to /dir/ with trailing slash |
| 403 | Forbidden — exists but you can't access it (still a finding) |
| 404 | Not found — default for misses (filtered out automatically) |

**301 is a hit** — the directory exists, server just redirects to the trailing-slash version.

---

## Speed vs Safety

```bash
# Default (safe for remote targets):
ffuf -w wordlist -u http://TARGET/FUZZ -ic

# Faster (okay for lab/local):
ffuf -w wordlist -u http://TARGET/FUZZ -ic -t 200

# Don't go over ~200 threads on remote targets — risks DoS or connection drops
```

---

## Exam Notes

- `-ic` is mandatory for directory-list-2.3 files — the copyright comments at the top will appear as fake entries without it
- 301 = redirect = directory found — add trailing slash and visit `/dir/` in the browser
- Default match codes include 403 — forbidden dirs are still worth noting as findings
- On PwnBox wordlists are at `/opt/useful/seclists/` | On Kali: `/usr/share/dirbuster/wordlists/` or `~/SecLists/`
- `-t 100` is a safe speed boost; `-t 200` only when you need speed and target allows it
