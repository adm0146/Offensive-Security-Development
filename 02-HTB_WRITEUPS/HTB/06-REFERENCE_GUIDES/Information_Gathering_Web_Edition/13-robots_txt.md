# 13 — robots.txt

> A website's own map of what it's hiding — disallowed paths often point straight to the interesting stuff.

---

## What Is robots.txt?

robots.txt is a plain text file at the root of a website (for example, `https://example.com/robots.txt`). It tells web crawlers which paths they are allowed or not allowed to access. It follows the Robots Exclusion Standard.

```bash
# Always check this first on any target
curl https://example.com/robots.txt
```
> Fetches the robots.txt file from the root of the target website. Swap the domain for your target. Scan the output for `Disallow:` lines — those paths are what the site owner does not want you to find.

> **Key insight:** robots.txt is a suggestion, not enforcement. Bots can ignore it. But for recon, the disallowed paths are a **goldmine** — they tell you exactly what the site owner wants hidden.

---

## robots.txt Structure

Each block has a `User-agent` line followed by directives, separated by blank lines:

```
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/

User-agent: Googlebot
Crawl-delay: 10

Sitemap: https://www.example.com/sitemap.xml
```

---

## Directives Reference

| Directive | What It Does | Example |
|---|---|---|
| `User-agent` | Which bot the rules apply to (`*` = all) | `User-agent: Googlebot` |
| `Disallow` | Paths the bot should NOT crawl | `Disallow: /admin/` |
| `Allow` | Override a broader Disallow rule | `Allow: /admin/public/` |
| `Crawl-delay` | Seconds to wait between requests | `Crawl-delay: 10` |
| `Sitemap` | URL to XML sitemap for efficient crawling | `Sitemap: https://example.com/sitemap.xml` |

---

## Reading robots.txt for Recon

### Example File

```
User-agent: *
Disallow: /admin/
Disallow: /private/
Disallow: /backup/
Disallow: /cgi-bin/
Allow: /public/

User-agent: Googlebot
Crawl-delay: 10

Sitemap: https://www.example.com/sitemap.xml
```

### What This Tells Us

| Finding | Recon Value |
|---|---|
| `Disallow: /admin/` | Admin panel exists at `/admin/` -- check for login page |
| `Disallow: /private/` | Private content -- could contain sensitive docs |
| `Disallow: /backup/` | Backup directory -- may have `.bak`, `.sql`, `.zip` files |
| `Disallow: /cgi-bin/` | CGI scripts -- legacy tech, often vulnerable |
| `Crawl-delay: 10` | Server may be resource-limited -- note for scan tuning |
| `Sitemap` URL | Full site structure in XML -- parse for all URLs |

---

## Recon Value of Disallowed Paths

| What You Find | What To Do |
|---|---|
| **Hidden directories** (`/admin/`, `/backup/`, `/staging/`) | Browse directly, check for directory listing |
| **Sensitive file paths** | Try accessing them -- may not have auth |
| **API endpoints** (`/api/v1/`, `/internal/`) | Test for unauthenticated access |
| **Sitemap URL** | Parse it for every URL on the site |
| **Crawler traps / honeypots** | Recognize decoy paths -- indicates security awareness |

---

## Quick Workflow

```bash
# 1. Grab robots.txt
curl -s https://TARGET/robots.txt

# 2. Extract all disallowed paths
curl -s https://TARGET/robots.txt | grep -i "disallow" | awk '{print $2}'

# 3. Check if sitemap exists
curl -s https://TARGET/robots.txt | grep -i "sitemap"

# 4. Try browsing disallowed paths directly
curl -s https://TARGET/admin/
curl -s https://TARGET/private/
```
> Step 1 fetches the file. Step 2 pipes it through `grep` and `awk` to extract only the path from each `Disallow:` line. Step 3 finds the sitemap URL if present — parse it for the full site structure. Steps 4+ attempt direct access to disallowed paths — robots.txt is advisory only and does not enforce access control. Swap TARGET for your IP or hostname.

---

## Key Takeaways

- Always check `robots.txt` first. It is free intelligence the site gives you.
- Disallowed paths are interesting paths. They often point to admin panels, backups, and private content.
- The `Sitemap:` URL reveals the full site structure in one request.
- `Crawl-delay` hints at server capacity. Use it to tune your scan speed so you do not overwhelm the target.
- Honeypot directories may exist. If you see unusual decoy paths, the site has active defenses.
- robots.txt is not access control. Disallowed paths may still be accessible — always try them directly.

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
