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
> Basic directory brute-force. Replace `TARGET_IP:PORT` with your target. `-ic` is required for this wordlist family because it starts with comment lines. The 87k-entry small list runs in under a minute at default thread count.

**With explicit keyword assignment:**
```bash
ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt:FUZZ \
  -u http://TARGET_IP:PORT/FUZZ \
  -ic
# :FUZZ after the wordlist path assigns the keyword name
# This matters when using multiple wordlists with different keywords
```
> The `:FUZZ` suffix names the wordlist. You need unique names when using two or more wordlists so ffuf knows which one fills which placeholder.

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
> A reference block of the most-used flags. `-mc` and `-fc` are opposites — one keeps, one removes. Use `-v` whenever recursion is on so you can see the full path of each hit.

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
> Start with `common.txt` for quick checks, then `raft-medium-directories.txt` for thorough scans. The `directory-list-2.3` family is larger but needs `-ic` to skip the copyright header lines.

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

**301 is a hit.** The directory exists. The server is just redirecting you to the version with a trailing slash.

---

## Speed vs Safety

```bash
# Default (safe for remote targets):
ffuf -w wordlist -u http://TARGET/FUZZ -ic

# Faster (okay for lab/local):
ffuf -w wordlist -u http://TARGET/FUZZ -ic -t 200

# Don't go over ~200 threads on remote targets — risks DoS or connection drops
```
> Default threads (40) is safe for remote targets. `-t 200` is only for local or lab targets where you own the server. Too many threads can knock over a fragile HTB lab box.

---

## Exam Notes

- `-ic` is mandatory for directory-list-2.3 files — the copyright comments at the top will appear as fake entries without it
- 301 = redirect = directory found — add trailing slash and visit `/dir/` in the browser
- Default match codes include 403 — forbidden dirs are still worth noting as findings
- On PwnBox wordlists are at `/opt/useful/seclists/` | On Kali: `/usr/share/dirbuster/wordlists/` or `~/SecLists/`
- `-t 100` is a safe speed boost; `-t 200` only when you need speed and target allows it
