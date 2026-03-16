# 17 — Web Archives (Wayback Machine)

> The internet never forgets — archived snapshots reveal old pages, removed content, and historical vulnerabilities.

---

## What Is the Wayback Machine?

The **Internet Archive's Wayback Machine** ([web.archive.org](https://web.archive.org)) has been archiving websites since 1996. It stores full snapshots (HTML, CSS, JS, images) of websites at various points in time.

```
https://web.archive.org/web/*/TARGET.com
```

---

## How It Works

| Step | What Happens |
|---|---|
| **Crawling** | Automated bots browse the web, downloading full copies of pages |
| **Archiving** | Pages + resources stored with a timestamp (date/time snapshot) |
| **Accessing** | Users browse snapshots by entering a URL and selecting a date |

- Archive frequency varies — popular sites may be captured daily, others monthly or less
- Not every page is captured — prioritizes cultural, historical, and research value
- Site owners can request exclusion (but not guaranteed)

---

## Why It Matters for Recon

| Use Case | What You Find |
|---|---|
| **Hidden assets** | Old pages, directories, files, subdomains no longer live |
| **Removed content** | Deleted pages that contained sensitive info |
| **Technology changes** | What CMS/framework they used before — old tech may still be running |
| **Employee info** | Old team pages, contact info, org structure |
| **Vulnerability patterns** | Old versions of software listed in headers or source |
| **Marketing/strategy intel** | Past campaigns, partnerships, business direction |

---

## Quick Workflow

```bash
# 1. Check available snapshots for a target
# Visit: https://web.archive.org/web/*/target.com

# 2. Use the Wayback Machine CDX API for programmatic access
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com&output=text&fl=timestamp,original&collapse=urlkey" | head -20

# 3. Get the earliest snapshot
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com&output=text&fl=timestamp,original&limit=1"

# 4. View a specific snapshot (replace TIMESTAMP)
# https://web.archive.org/web/TIMESTAMP/target.com

# 5. Download an archived page
curl -s "https://web.archive.org/web/20170610042301/https://www.hackthebox.eu/" -o archived_page.html
```

---

## What To Look For in Archives

| Finding | Recon Value |
|---|---|
| Old `/admin/` or `/login/` pages | May still exist but be unlinked |
| Staff directories / team pages | Employee names for phishing, LinkedIn correlation |
| Old subdomains in links | May still resolve and be forgotten |
| Technology references (WordPress 4.x, PHP 5.x) | Check if old versions are still running |
| Removed files (PDFs, docs) | May contain metadata, internal info |
| Old robots.txt | Previously disallowed paths that may still exist |
| JavaScript files | Old API endpoints, hardcoded keys |

---

## Key Takeaways

- **Completely passive** — no packets touch the target, just browsing an archive
- **Old pages may still exist** — just because they're unlinked doesn't mean they're deleted
- **Check old robots.txt** — previously hidden paths might still be accessible
- **Employee turnover** — old team pages reveal past staff, username patterns
- **CDX API** enables programmatic queries — script it for large-scale recon
- **Compare snapshots** — diff old vs current to find what changed and what was removed

---

## Walkthrough — Wayback Machine Exercise

### Method

1. Go to [web.archive.org](https://web.archive.org)
2. Enter the target URL in the search bar
3. Use the **calendar view** to navigate to the specified date
4. Click the timestamp to view the archived snapshot
5. Browse the page for the answer — stats, counters, text, footers, etc.

No lab spawn needed — this is purely passive recon using the real Wayback Machine.

### Answers

| # | Question | Date | Answer |
|---|---|---|---|
| 1 | How many Pen Testing Labs did HTB have? | Aug 8, 2018 | **74** |
| 2 | How many members did HTB have? | Jun 10, 2017 | **3054** |
| 3 | What did facebook.com redirect to? | Mar 2002 | **http://site.aboutface.com/** |
| 4 | What could you use to "beam money to anyone" on PayPal? | Oct 1999 | **Palm 0rganizer** |
| 5 | Where was the Google Search Engine Prototype hosted? | Nov 1998 | **http://google.stanford.edu/** |
| 6 | When was iana.org last updated? | Mar 2000 | **17-December-99** |
| 7 | How many English articles was Wikipedia working on? | Feb 9, 2003 | **104155** |

### Lessons Learned

- **No tools needed** — just a browser and the Wayback Machine
- **Check footers** — "last updated" dates and copyright info live there
- **Stat counters on homepages** change over time — archives freeze them
- **Domain history** reveals surprising redirects (facebook.com was a different company)
- **Completely passive** — zero interaction with the target
