# Section 4 — Page Fuzzing

> Two-step process: (1) find what file extension the server uses, (2) fuzz for files with that extension.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Find all pages in /blog, get the flag | `HTB{bru73_f0r_c0mm0n_p455w0rd5}` |

Flag was at `/blog/home.php`.

---

## Step 1 — Extension Fuzzing

Find out what file type the server uses before you fuzz for page names. Scanning for `.php` pages on a `.jsp` server wastes every request.

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt \
  -u http://TARGET/blog/indexFUZZ \
  -mc 200,301,302,403

# The wordlist already includes the dot (.), so write indexFUZZ not index.FUZZ
# Test against index because every site has some form of index file
# Result: .php = 200 OK → site uses PHP
```
> Tests `index.php`, `index.asp`, `index.aspx`, and many more in one run. The wordlist includes the dot, so place `FUZZ` right after `index`. Run this before any page fuzzing so you know which extension to search for.

**Common extension → server mapping:**
| Extension | Server Type |
|-----------|------------|
| `.php` | Apache/PHP |
| `.aspx` / `.asp` | IIS (Windows) |
| `.jsp` | Java/Tomcat |
| `.html` / `.htm` | Static / any server |

---

## Step 2 — Page Fuzzing with Known Extension

```bash
ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt \
  -u http://TARGET/blog/FUZZ.php \
  -ic -mc 200,301,302,403 -fs 0

# FUZZ.php = append .php to every wordlist entry
# -fs 0 = filter out responses with size 0 (empty pages like index.php)
#         size 0 = page exists but has no content → skip it
# Result: home.php → 200, size > 0 → has content → visit it
```
> `FUZZ.php` appends `.php` to every wordlist word. Swap `.php` for whatever extension the server uses. `-fs 0` removes blank pages that exist but return empty bodies.

---

## Full Two-Step Workflow

```bash
# Step 1: What extension?
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt \
  -u http://TARGET/DIRECTORY/indexFUZZ -mc 200,403

# Step 2: What pages exist with that extension?
ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt \
  -u http://TARGET/DIRECTORY/FUZZ.EXTENSION \
  -ic -mc 200,403 -fs 0
```
> The two-step pattern for any directory: first find the server's file extension, then brute-force page names with that extension. Replace `DIRECTORY` with the path you're targeting and `EXTENSION` with your step-1 result.

---

## Key Filtering Flags

```bash
-fs SIZE   # filter by response SIZE (bytes) — use to remove identical "not found" pages
-fw WORDS  # filter by word count — useful when all misses have the same word count
-fl LINES  # filter by line count
-fc CODE   # filter by status code (e.g., -fc 404 to hide 404s)
```
> Use one of these flags to eliminate noise. Run a test request first to find the size/word-count of a known-bad response, then filter on that value.

**When to use `-fs`:** Run a quick scan first. Look at what size the "not found" responses are. If all misses return 983 bytes, add `-fs 983` to hide them. Only real hits will show up.

---

## Exam Notes

- Always do extension fuzzing first — fuzzing with the wrong extension wastes time and finds nothing
- The `web-extensions.txt` wordlist already includes the dot — write `indexFUZZ` not `index.FUZZ`
- `-fs 0` removes empty pages (exist but no content) — cleaner results
- 403 = forbidden but EXISTS — still a finding worth noting even if you can't read the content
- After finding pages, check each for interesting content — the flag/login/data is on the page itself
