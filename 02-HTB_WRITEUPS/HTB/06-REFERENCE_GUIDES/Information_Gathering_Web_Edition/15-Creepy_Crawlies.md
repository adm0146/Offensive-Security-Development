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

### Download and Run ReconSpider

```bash
# Download the custom recon spider
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip

# Run against target
python3 ReconSpider.py http://TARGET
```

Output saves to `results.json`.

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

- **ReconSpider** gives you structured JSON output from a single command
- **Emails** are immediate value — phishing targets and username patterns
- **JS files** often contain hardcoded API endpoints and secrets
- **HTML comments** are dev leftovers — debug info, internal paths, TODO notes
- **External files** have metadata — run `exiftool` on every PDF you find
- **Always get permission** before crawling — respect server resources and scope

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
