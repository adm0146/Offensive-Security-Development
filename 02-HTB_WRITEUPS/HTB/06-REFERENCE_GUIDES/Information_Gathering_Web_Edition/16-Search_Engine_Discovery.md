# 16 — Search Engine Discovery

> Google is a hacking tool — search operators and dorking techniques turn public indexes into a recon goldmine.

---

## Why Search Engine Discovery Matters

- Public and legal — all indexed data is openly accessible.
- Massive coverage — search engines index billions of pages.
- Free — no tools to install and no accounts needed.
- No direct interaction with the target — completely passive recon.

---

## Search Operators — Quick Reference

| Operator | What It Does | Example |
|---|---|---|
| `site:` | Limit results to a specific domain | `site:example.com` |
| `inurl:` | Find pages with a term in the URL | `inurl:login` |
| `filetype:` | Search for specific file types | `filetype:pdf` |
| `intitle:` | Find pages with a term in the title | `intitle:"confidential report"` |
| `intext:` | Search within page body text | `intext:"password reset"` |
| `cache:` | View cached version of a page | `cache:example.com` |
| `link:` | Find pages linking to a URL | `link:example.com` |
| `related:` | Find similar websites | `related:example.com` |
| `info:` | Get summary info about a page | `info:example.com` |
| `define:` | Get definitions | `define:phishing` |

---

## Advanced Operators

| Operator | What It Does | Example |
|---|---|---|
| `allintext:` | All specified words must be in body text | `allintext:admin password reset` |
| `allinurl:` | All specified words must be in URL | `allinurl:admin panel` |
| `allintitle:` | All specified words must be in title | `allintitle:confidential report 2023` |
| `numrange:` | Numbers within a range | `site:example.com numrange:1000-2000` |
| `..` (range) | Numerical range shorthand | `"price" 100..500` |

---

## Boolean & Modifiers

| Operator | What It Does | Example |
|---|---|---|
| `AND` | Both terms required | `site:example.com AND inurl:admin` |
| `OR` | Either term matches | `"linux" OR "ubuntu" OR "debian"` |
| `NOT` or `-` | Exclude results | `site:bank.com NOT inurl:login` |
| `" "` | Exact phrase match | `"information security policy"` |
| `*` | Wildcard (any word) | `site:example.com filetype:pdf user* manual` |

---

## Google Dorking — Recon Recipes

### Finding Login Pages

```
site:example.com inurl:login
site:example.com (inurl:login OR inurl:admin)
```

### Identifying Exposed Files

```
site:example.com filetype:pdf
site:example.com (filetype:xls OR filetype:docx)
```

### Uncovering Configuration Files

```
site:example.com inurl:config.php
site:example.com (ext:conf OR ext:cnf)
```

### Locating Database Backups

```
site:example.com inurl:backup
site:example.com filetype:sql
```

### Finding Sensitive Directories

```
site:example.com intitle:"index of" "backup"
site:example.com intitle:"index of" "admin"
```

### Credential Hunting

```
site:example.com filetype:env
site:example.com filetype:log "password"
site:example.com inurl:wp-config.php
```

---

## Dorking Workflow

```
1. Start broad:           site:target.com
2. Find login pages:      site:target.com inurl:login OR inurl:admin
3. Find exposed files:    site:target.com filetype:pdf OR filetype:xls OR filetype:docx
4. Find config files:     site:target.com ext:conf OR ext:cnf OR ext:env
5. Find backups:          site:target.com filetype:sql OR inurl:backup
6. Check directory listing: site:target.com intitle:"index of"
7. Credential hunting:    site:target.com filetype:log "password"
```

---

## Resources

- **Google Hacking Database (GHDB):** [exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database) — thousands of pre-built dorks
- **DorkSearch:** [dorksearch.com](https://dorksearch.com) — interactive dork builder

---

## Key Takeaways

- Google dorking is passive recon — no packets touch the target.
- `site:` combined with `filetype:` and `inurl:` is the core combination for most dorks.
- Exposed config files such as `config.php` and `.env` often contain credentials.
- Directory listings found with `intitle:"index of"` expose file structures.
- The Google Hacking Database (GHDB) at exploit-db.com has thousands of pre-built dorks — do not reinvent the wheel.
- Always combine operators. Broad searches waste time; specific dorks find the gold.

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
