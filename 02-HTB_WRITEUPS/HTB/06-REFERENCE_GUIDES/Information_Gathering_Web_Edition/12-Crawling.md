# 12 — Crawling

> Automated link-following to map a website's structure, discover hidden pages, and extract intel.

---

## What Is Crawling?

Crawling (spidering) = a bot starts at a **seed URL**, fetches the page, extracts all links, adds them to a queue, and repeats. Unlike fuzzing (guessing URLs), crawling **follows what the site itself reveals**.

```
Seed URL (Homepage)
+-- link1 --> link4, link5
+-- link2
+-- link3
```

The crawler visits link1, finds link4 and link5, queues them, and keeps going until it runs out of new links or hits a configured limit.

---

## Crawling Strategies

| Strategy | How It Works | Best For |
|---|---|---|
| **Breadth-First** | Crawl ALL links on the current page before going deeper | Broad site mapping, discovering all top-level sections |
| **Depth-First** | Follow one link chain as deep as possible, then backtrack | Finding deeply nested pages, specific content |

### Breadth-First (BFS)

```
Seed --> Page 1
           +-- Page 2 --> Page 4, Page 5
           +-- Page 3 --> Page 6, Page 7
```

Visits: Page 1 -> Page 2 -> Page 3 -> Page 4 -> Page 5 -> Page 6 -> Page 7

### Depth-First (DFS)

```
Seed --> Page 1 --> Page 2 --> Page 3 --> Page 4 --> Page 5 (backtrack to Page 2)
```

Follows each branch to its end before backtracking.

---

## What Crawlers Extract

| Data Type | What It Is | Why It Matters |
|---|---|---|
| **Internal Links** | Links within the same domain | Map site structure, find hidden pages |
| **External Links** | Links to other domains | Identify partners, third-party services, CDNs |
| **Comments** | User/dev comments in HTML or forums | Leak internal info, software versions, credentials |
| **Metadata** | Page titles, descriptions, author names, dates | Context about purpose, technology, ownership |
| **Sensitive Files** | Backups, configs, logs | DB creds, API keys, source code, encryption keys |

---

## Sensitive File Extensions to Watch For

| Extension | What It Usually Is |
|---|---|
| `.bak`, `.old` | Backup files -- may contain source code or configs |
| `.config`, `.conf` | Configuration files -- DB strings, API keys |
| `.log` | Log files -- error messages, paths, usernames |
| `.sql` | Database dumps -- full table data |
| `.env` | Environment variables -- secrets, tokens |
| `.swp`, `.swo` | Vim swap files -- partial source code |

---

## Context Is Everything

A single finding means nothing alone. **Connect the dots:**

| Finding Alone | Combined With | Becomes |
|---|---|---|
| Comment mentions "file server" | `/files/` directory found by crawler | Publicly accessible file server -- check for sensitive docs |
| Outdated software version in metadata | Known CVE for that version | Confirmed exploitable vulnerability |
| Several URLs point to `/files/` | Directory browsing is enabled | Exposed backup archives, internal documents |

**The recon value is in correlation, not isolation.**

---

## Key Takeaways

- **Crawling follows links the site reveals** -- fuzzing guesses them
- **Breadth-first** = wide site map; **depth-first** = deep specific paths
- **Always check extracted files** -- backups, configs, env files can contain credentials
- **Comments and metadata** leak more than people think
- **Correlate findings** -- a comment + a directory + a version = actionable intel
- **Context turns noise into signal** -- analyze data holistically

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
