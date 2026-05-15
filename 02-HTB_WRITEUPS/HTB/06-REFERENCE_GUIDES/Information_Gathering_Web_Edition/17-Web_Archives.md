# 17 — Web Archives (Wayback Machine)

> The internet never forgets — archived snapshots reveal old pages, removed content, and historical vulnerabilities.

---

## What Is the Wayback Machine?

The Internet Archive's Wayback Machine (web.archive.org) has been archiving websites since 1996. It stores full snapshots — Hypertext Markup Language (HTML), CSS, JavaScript, and images — of websites at different points in time.

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

- Archive frequency varies. Popular sites may be captured daily; others monthly or less.
- Not every page is captured. The archive prioritizes cultural, historical, and research value.
- Site owners can request exclusion, but it is not guaranteed.

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
> The CDX API returns a list of all archived URLs and timestamps — no browser needed. `fl=timestamp,original` selects which fields to return. `collapse=urlkey` deduplicates URLs with different timestamps so you see each unique URL once. `limit=1` returns only the first result (useful for the earliest snapshot). Step 5 downloads a specific archived page by its timestamp — swap the timestamp and domain for your target.

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

- This technique is completely passive. No packets touch the target — you are browsing an archive.
- Old pages may still exist on the live site. Unlinked does not mean deleted.
- Check old robots.txt from archived snapshots. Previously hidden paths might still be accessible.
- Old team pages reveal past employees, username patterns, and org structure.
- The CDX API enables programmatic queries. Script it for large-scale recon across many targets.
- Compare old and current snapshots to find what changed, what was added, and what was removed.

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
