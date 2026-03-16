# 13 — robots.txt

> A website's own map of what it's hiding — disallowed paths often point straight to the interesting stuff.

---

## What Is robots.txt?

A plain text file at the **root directory** of a website (e.g., `https://example.com/robots.txt`) that tells crawlers which paths they can and cannot access. It follows the **Robots Exclusion Standard**.

```bash
# Always check this first on any target
curl https://example.com/robots.txt
```

> **Key insight:** robots.txt is a suggestion, not enforcement. Bots can ignore it. But for recon, the disallowed paths are a **goldmine** — they tell you exactly what the site owner wants hidden.

---

## robots.txt Structure

Each block (record) has a **User-agent** line followed by **directives**, separated by blank lines:

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

---

## Key Takeaways

- **Always check `robots.txt` first** -- it's free intel the site gives you
- **Disallowed paths = interesting paths** -- admin panels, backups, private content
- **Sitemap URLs** reveal the full site structure in one request
- **Crawl-delay** hints at server capacity -- useful for tuning scan speed
- **Honeypot directories** may exist -- indicates active defense
- **robots.txt is not access control** -- disallowed paths may still be accessible

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
