# 15 — Creepy Crawlies (Crawling Tools)

> Automated crawlers that spider a target and dump emails, links, files, JS, comments, and more into structured output.

---

## Web Crawling Tools Overview

| Tool | Type | Best For |
|---|---|---|
| **Scrapy** | Python framework | Custom recon spiders, structured data extraction |
| **ReconSpider** | Scrapy-based script | Quick recon crawl — emails, links, files, JS, comments |
| **Burp Suite Spider** | Built into Burp | Active crawling during web app testing |
| **OWASP ZAP Spider** | Built into ZAP | Free alternative to Burp, automated + manual modes |
| **Apache Nutch** | Java-based | Massive-scale crawls, enterprise recon |

---

## Scrapy + ReconSpider — Quick Setup

### Install Scrapy

```bash
pip3 install scrapy
```
> Installs the Scrapy web crawling framework via pip3. ReconSpider depends on it. If you get a PEP 668 error on Kali, add `--break-system-packages` to override.

### Download and Run ReconSpider

```bash
# Download the custom recon spider
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip

# Run against target
python3 ReconSpider.py http://TARGET
```
> Downloads and extracts ReconSpider from HTB Academy, then runs it against the target URL. Replace `http://TARGET` with your target. Output is written to `results.json` in the current directory. Parse that file with `jq` to extract emails, comments, links, and more.

Output is saved to `results.json` in the current directory.

---

## results.json — What It Extracts

```json
{
    "emails": ["lily.floid@inlanefreight.com", "cvs@inlanefreight.com"],
    "links": ["https://www.inlanefreight.com/index.php/offices/"],
    "external_files": ["https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf"],
    "js_files": ["https://www.inlanefreight.com/wp-includes/js/jquery/jquery-migrate.min.js"],
    "form_fields": [],
    "images": ["https://www.inlanefreight.com/wp-content/uploads/2021/03/AboutUs_01.png"],
    "videos": [],
    "audio": [],
    "comments": ["<!-- #masthead -->"]
}
```

### What Each Key Reveals

| Key | What It Contains | Recon Value |
|---|---|---|
| `emails` | Email addresses found on the domain | Phishing targets, username enumeration, org chart mapping |
| `links` | Internal and external URLs | Site structure, hidden pages, partner/vendor relationships |
| `external_files` | PDFs, docs, spreadsheets | Metadata (author names, software versions), sensitive content |
| `js_files` | JavaScript file URLs | Client-side logic, API endpoints, hardcoded secrets |
| `form_fields` | Input fields from forms | Login forms, search fields, hidden parameters |
| `images` | Image URLs | Directory structure clues, metadata (EXIF data) |
| `videos` / `audio` | Media file URLs | Hosted content, CDN identification |
| `comments` | HTML comments in source | Dev notes, debug info, TODO items, removed features |

---

## Parsing results.json with jq

```bash
# Extract all emails
jq -r '.emails[]' results.json

# Extract all links
jq -r '.links[]' results.json

# Extract external files (PDFs, docs)
jq -r '.external_files[]' results.json

# Extract JS files (check for API endpoints)
jq -r '.js_files[]' results.json

# Extract HTML comments
jq -r '.comments[]' results.json

# Count findings per category
jq 'to_entries[] | {key: .key, count: (.value | length)}' results.json
```
> Each `jq -r '.KEY[]'` command extracts all values from one array in `results.json`. `-r` strips the surrounding quotes from string output. The last command counts how many items were found in each category — useful for quickly spotting where the data is dense. Start with `.comments[]` and `.emails[]` first.

---

## What To Do With Each Finding

| Finding | Next Step |
|---|---|
| **Emails** | Build target list for phishing, check for credential leaks on breach databases |
| **External files (PDFs)** | Run `exiftool` for metadata — author names, software, timestamps |
| **JS files** | Search for API keys, endpoints, hardcoded credentials with `grep` |
| **HTML comments** | Look for debug info, internal IPs, dev notes, disabled features |
| **Links to `/admin/`, `/backup/`** | Browse directly, check for auth bypass |
| **Form fields** | Map input vectors for injection testing |

---

## Key Takeaways

- ReconSpider produces structured JSON output from a single command.
- Emails are immediate value — they are phishing targets and reveal username patterns.
- JavaScript (JS) files often contain hardcoded API endpoints and secrets.
- HTML comments are developer leftovers. Check them for debug info, internal paths, and TODO notes.
- External files have metadata — run `exiftool` on every PDF you find.
- Always get permission before crawling. Respect server resources and stay within scope.

---

## Walkthrough — ReconSpider Exercise

### Problem: PEP 668 Blocking pip Install

Kali's newer Python (3.13+) enforces PEP 668 and blocks system-wide `pip install`:

```bash
pip3 install scrapy
# ERROR: externally-managed-environment
```

On a pentesting VM, the override is safe:

```bash
pip3 install scrapy --break-system-packages
```
> Overrides the PEP 668 externally-managed-environment restriction on newer Kali Python installations. This is safe to use on a dedicated pentesting VM.

### Running ReconSpider

```bash
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip
/usr/bin/python3 ReconSpider.py http://inlanefreight.com
```
> Uses the full path `/usr/bin/python3` to avoid virtual environment conflicts. Run this from the directory where you extracted ReconSpider.

### Parsing the Output

```bash
sudo apt install jq -y
cat results.json | jq .
```
> Installs `jq` if missing, then pretty-prints the entire `results.json` file. Use this to see all extracted data at once before drilling into specific keys.

### Key Findings

16 emails were discovered — including the CEO email (`jeremy-ceo@inlanefreight.com`), support addresses, and individual employees.

HTML comments leaked critical information:

```
<!-- TO-DO: change the location of future reports to inlanefreight-comp133.s3.amazonaws.htb -->
<!-- change Jeremy's email to jeremy-ceo@inlanefreight.com -->
```

- S3 bucket name exposed: `inlanefreight-comp133.s3.amazonaws.htb`
- Developer notes left in production code — internal email changes visible to anyone who reads the source

**Answer:** `inlanefreight-comp133.s3.amazonaws.htb`

### Lesson Learned

- HTML comments are dev leftovers — always check `jq -r '.comments[]' results.json`
- S3 bucket names in comments = check for public access
- Dev TODO notes reveal internal processes and future infrastructure plans

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
