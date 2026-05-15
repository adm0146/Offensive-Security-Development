````markdown
# 19 — Skills Assessment

> Final challenge combining WHOIS, robots.txt, subdomain brute-forcing, vhost fuzzing, nested subdomain discovery, and web crawling.

---

## Assessment Overview

| Skill Tested | Where It Applied |
|---|---|
| **WHOIS** | Q1 — Finding registrar IANA ID for `inlanefreight.com` |
| **Fingerprinting** | Q2 — Identifying web server software on the target |
| **robots.txt / Directory Discovery** | Q3 — Finding hidden admin directory and API key |
| **Subdomain Brute-Forcing (Nested)** | Q4/Q5 — Discovering `dev.web1337.inlanefreight.htb` |
| **Crawling with ReconSpider** | Q4/Q5 — Extracting email and API key from crawled pages |

---

## Target Setup

```bash
# Add target to /etc/hosts (do this FIRST — .htb domains don't resolve publicly)
echo "<TARGET_IP>  inlanefreight.htb web1337.inlanefreight.htb" | sudo tee -a /etc/hosts
```
> Adds both known hostnames to your local DNS override file so they resolve to the lab IP. Replace `<TARGET_IP>` with the actual IP. Do this before running any tool against the target.

---

## Q1 — WHOIS Registrar IANA ID

**Question:** What is the IANA ID of the registrar of the inlanefreight.com domain?

```bash
whois inlanefreight.com | grep -i "registrar iana"
```
> Runs WHOIS against the public domain and pipes the output through `grep` to find the Registrar IANA ID line directly. The IANA ID is a number assigned to accredited domain registrars.

**Answer:** `468`

---

## Q2 — Web Server Fingerprinting

**Question:** What HTTP server software is powering the inlanefreight.htb site on the target system?

```bash
curl -I http://inlanefreight.htb:<PORT>
```
> Sends a HEAD request to get only response headers. The `Server:` header reveals the web server software and version. Replace `<PORT>` with the actual port from the lab.

```
HTTP/1.1 200 OK
Server: nginx/1.26.1
```

**Answer:** `nginx`

---

## Q3 — Hidden Admin Directory + API Key

**Question:** What is the API key in the hidden admin directory that you have discovered on the target system?

### Step 1: Crawl with gospider to discover robots.txt entries

```bash
gospider -s http://web1337.inlanefreight.htb:<PORT> -d 3 -t 10
```
> Crawls the target to depth 3 using 10 threads. The `-d` flag sets crawl depth and `-t` sets thread count. gospider automatically reads and reports `robots.txt` entries — that is how the `/admin_h1dd3n` path is discovered here.

Output reveals `robots.txt` entries:

```
[robots] - http://web1337.inlanefreight.htb:<PORT>/index.html
[robots] - http://web1337.inlanefreight.htb:<PORT>/index-2.html
[robots] - http://web1337.inlanefreight.htb:<PORT>/index-3.html
[robots] - http://web1337.inlanefreight.htb:<PORT>/admin_h1dd3n
```

### Step 2: Check robots.txt directly

```bash
curl -s http://web1337.inlanefreight.htb:<PORT>/robots.txt
```
> Reads the robots.txt file directly. The `Disallow: /admin_h1dd3n` line confirms the hidden admin directory path.

```
User-agent: *
Allow: /index.html
Allow: /index-2.html
Allow: /index-3.html
Disallow: /admin_h1dd3n
```

### Step 3: Access the hidden directory

```bash
curl -s http://web1337.inlanefreight.htb:<PORT>/admin_h1dd3n/
```
> Directly accesses the disallowed path from robots.txt. robots.txt is advisory only — the server does not enforce it. The response contains the API key in the page body.

```html
<h1>Welcome to web1337 admin site</h1>
<h2>The admin panel is currently under maintenance, but the API is still accessible with the key e963d863ee0e82ba7080fbf558ca0d3f</h2>
```

**Answer:** `e963d863ee0e82ba7080fbf558ca0d3f`

---

## Q4 — Email Discovery via Crawling (4 Points)

**Question:** After crawling the inlanefreight.htb domain on the target system, what is the email address you have found?

### This Was the Hard One — Here's Why

The main pages on `inlanefreight.htb` and `web1337.inlanefreight.htb` are bare HTML with no links, no emails, and no JavaScript. Crawlers have nothing to extract from them. The email is hidden on a nested subdomain that you must discover through VHost brute-forcing.

### Step 1: Brute-force subdomains of `web1337.inlanefreight.htb`

The critical insight here is that you need to fuzz for subdomains of the subdomain, not just of `inlanefreight.htb`.

First, check the default response size to filter false positives:

```bash
curl -s -o /dev/null -w "%{size_download}" -H "Host: nonexistent.web1337.inlanefreight.htb" http://web1337.inlanefreight.htb:<PORT>/
# Returns: 120
```
> Gets the baseline response size for a non-existent VHost. `-o /dev/null` discards the body; `-w "%{size_download}"` prints only the byte count. Use the returned number as your `-fs` filter value in ffuf so wildcard (fake positive) responses are filtered out.

Then fuzz with ffuf:

```bash
ffuf -u http://web1337.inlanefreight.htb:<PORT> \
     -H "Host: FUZZ.web1337.inlanefreight.htb" \
     -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fs 120 -t 100
```
> Fuzzes for nested subdomains under `web1337.inlanefreight.htb` by injecting wordlist entries into the `Host:` header. `-fs 120` filters out the 120-byte wildcard response established in the previous step. `-t 100` sets 100 threads for speed. Any result with a different size is a real VHost.

**Result:**

```
dev     [Status: 200, Size: 123, Words: 5, Lines: 1, Duration: 187ms]
```

### Step 2: Add the nested subdomain to /etc/hosts

```bash
echo "<TARGET_IP>  dev.web1337.inlanefreight.htb" | sudo tee -a /etc/hosts
```
> Adds the newly discovered nested VHost to `/etc/hosts`. Replace `<TARGET_IP>` with the lab IP. Do this before the next step or curl will fail to resolve the hostname.

### Step 3: Verify the new vhost has content

```bash
curl -s http://dev.web1337.inlanefreight.htb:<PORT>/
```
> Verifies the VHost is serving real content. The response shows a page with actual links — crawlers need links to follow in order to discover more pages.

```html
<h1>Page 1</h1><a href="index-334.html">Next</a>
```

This page has links — meaning crawlers can now follow them and extract data.

### Step 4: Crawl with ReconSpider

```bash
python3 ReconSpider.py http://dev.web1337.inlanefreight.htb:<PORT>
```
> Runs ReconSpider against the nested VHost. It follows the chain of `index-XXX.html` links across 100 pages and saves all extracted data (emails, links, comments) to `results.json`.

ReconSpider crawls 100 pages by following the chain of `index-XXX.html` links and saves the output to `results.json`.

### Step 5: Extract the email

```bash
cat results.json | jq -r '.emails[]'
```
> Extracts all email addresses found during the crawl from `results.json`. `-r` prints raw strings without surrounding quotes.

```
1337testing@inlanefreight.htb
```

**Answer:** `1337testing@inlanefreight.htb`

---

## Q5 — Future API Key

**Question:** What is the API key the inlanefreight.htb developers will be changing to?

This answer was also in the ReconSpider output from Q4. It was hidden in an HTML comment on one of the 100 crawled pages:

```bash
cat results.json | jq -r '.comments[]'
```
> Extracts all HTML comments found during the crawl. Developer notes left in production code often appear here — including future API keys, internal server paths, and TODO items.

```html
<!-- Remember to change the API key to ba988b835be4aa97d068941dc852ff33 -->
```

**Answer:** `ba988b835be4aa97d068941dc852ff33`

---

## Key Takeaways

### 1. Nested Subdomains Are Real

Do not stop at first-level subdomains. If you find `sub.domain.htb`, fuzz for `FUZZ.sub.domain.htb` too. Hidden development and staging environments are often nested one level deeper.

### 2. The Assessment Is Sequential

Each question builds on the previous one:
- Q1-Q2: Basic recon (WHOIS, fingerprinting)
- Q3: robots.txt reveals hidden directory → API key
- Q4-Q5: Nested subdomain brute-forcing → crawling → email + future API key

### 3. Response Size Filtering Is Critical

When fuzzing VHosts, the default catch-all response floods you with false positives. Always do two things:
1. Check the default response size first with `curl -s -o /dev/null -w "%{size_download}"`.
2. Filter that size out with `-fs` in ffuf or `--exclude-length` in gobuster.

### 4. Crawlers Need Links to Follow

ReconSpider, gospider, and Scrapy all follow links to discover content. If a page has no links — like the bare `web1337` and `inlanefreight.htb` pages — crawlers find nothing. The `dev` subdomain was the only VHost with actual link chains for the crawler to follow.

### 5. HTML Comments Leak Secrets

The future API key was found in an HTML comment — a dev note left in production code. Always check:

```bash
cat results.json | jq -r '.comments[]'
```
> Extracts HTML comments from the ReconSpider output file. This is where developers accidentally leave API keys, internal URLs, and credential notes. Run this on every crawl result.

### 6. Don't Forget /etc/hosts

Every new subdomain you discover must be added to `/etc/hosts` before you can access it. Make this a habit:

```
Discover subdomain → Add to /etc/hosts → Verify with curl → Crawl/enumerate
```

---

## Complete Workflow Summary

```
1. Add target to /etc/hosts
2. Fingerprint: curl -I http://target:<PORT>
3. Check robots.txt on all known vhosts
4. Access disallowed paths (admin directories)
5. Brute-force subdomains: ffuf -H "Host: FUZZ.domain.htb" -fs <default_size>
6. Brute-force NESTED subdomains: ffuf -H "Host: FUZZ.sub.domain.htb" -fs <default_size>
7. Add ALL discovered subdomains to /etc/hosts
8. Crawl each vhost: python3 ReconSpider.py http://sub.domain.htb:<PORT>
9. Parse results: cat results.json | jq .
10. Extract emails: jq -r '.emails[]' results.json
11. Check comments: jq -r '.comments[]' results.json
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| `whois` | Domain registration info (IANA ID) |
| `curl -I` | HTTP header fingerprinting (server software) |
| `gospider` | Initial crawl + robots.txt discovery |
| `ffuf` | VHost and nested subdomain brute-forcing |
| `gobuster vhost` | Alternative vhost brute-forcing |
| `ReconSpider` | Deep web crawling — emails, links, comments, files |
| `jq` | JSON parsing of ReconSpider output |

````
