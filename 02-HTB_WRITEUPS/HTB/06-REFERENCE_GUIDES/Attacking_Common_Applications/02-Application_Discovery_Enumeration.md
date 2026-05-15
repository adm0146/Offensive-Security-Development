# Section 2 — Application Discovery & Enumeration

Getting from "scope CIDR" to a prioritized list of attackable apps. Two tools dominate: **EyeWitness** and **aquatone**.

---

## The Discovery Funnel

```
1. Ping sweep             → live hosts
2. Targeted port scan     → web ports common across the scope
3. Service scan (-sV)     → app fingerprints
4. Screenshot tool        → visual triage of every webapp
5. Categorized report     → high-value targets float to the top
```

In a 500-host scope, you can't manually browse to every port:80. Screenshot tools collapse hours of triage into 10 minutes of report scrolling.

---

## Initial Port Scan

Common starter command — targets the ports almost every webapp lives on:
```bash
sudo nmap -p 80,443,8000,8080,8180,8888,10000 --open \
  -oA web_discovery -iL scope_list
```

Why these ports:
| Port | Common service |
|------|----------------|
| 80, 443 | Standard HTTP/HTTPS |
| 8000 | Splunk, dev servers |
| 8080 | Tomcat, PRTG, Jenkins, dev proxies |
| 8180 | Tomcat alternate |
| 8443 | Tomcat HTTPS, admin panels |
| 8888 | Jupyter, dashboards |
| 10000 | Webmin |

Follow up with `--top-ports 10000` or `-p-` on smaller scopes for full coverage.

### Hostname hints
| Pattern | Tells you |
|---------|-----------|
| `*-dev.*`, `*-qa.*`, `*-acc.*` | Lower environments — often unpatched, debug enabled |
| `gitlab*`, `jenkins*` | Code/CI — check for self-signup, public repos, default creds |
| `support*`, `help*` | Ticketing systems — osTicket, Zendesk, JIRA |
| `app*`, `web*`, `portal*` | Generic — needs further enum |
| `inlanefreight.local` (root) | Often the primary product site |

Add interesting hostnames to a "dig deeper" list before screenshotting.

---

## EyeWitness

Selenium-based screenshotter that consumes Nmap XML and produces a categorized HTML report.

### Install
```bash
sudo apt install eyewitness
# OR
git clone https://github.com/RedSiege/EyeWitness && cd EyeWitness/Python/setup && sudo ./setup.sh
```

### Run from Nmap XML
```bash
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```

### What it produces
```
inlanefreight_eyewitness/
├── ew.db                  ← SQLite session file (for --resume)
├── report.html            ← the main artifact
├── screens/               ← PNG screenshots
├── source/                ← HTML source dumps
└── headers/               ← raw HTTP headers per host
```

### `ew.db` — resume file
EyeWitness writes a SQLite database called **`ew.db`** in the output directory. If the run is interrupted, resume with:
```bash
eyewitness --resume ./inlanefreight_eyewitness/ew.db
```
Source ref: `manager = db_manager.DB_Manager(cli_parsed.d + '/ew.db')` in `EyeWitness.py`.

### Report categorization
EyeWitness sorts hosts into:
- **High Value Targets** — Tomcat, Jenkins, ManageEngine, etc.
- **CMS** — WordPress, Drupal, Joomla
- **401/403 Unauthorized** — protected admin panels
- **Splash Pages**
- **Uncategorized**

It also suggests default credentials per fingerprint — huge time saver.

### Useful flags
| Flag | Purpose |
|------|---------|
| `-f file.txt` | Line-separated URL list instead of XML |
| `-x file.xml` | Nmap or .nessus XML |
| `--single URL` | One-off URL |
| `--resume ew.db` | Continue an interrupted run |
| `--prepend-https` | Try HTTPS variants too |
| `--no-prompt` | Skip the "open report?" question |
| `--proxy-ip / --proxy-port` | Route through Burp |
| `--threads N` | Parallelism |

---

## Aquatone

Go-based alternative. Faster on large scopes (no Selenium overhead). Better at clustering similar pages.

### Install
```bash
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
sudo mv aquatone /usr/local/bin/
```

### Run from Nmap XML
```bash
cat web_discovery.xml | aquatone -nmap
```

Or from a URL list via stdin:
```bash
echo "http://target.com" | aquatone -out /tmp/aq_run
```

### Default ports scanned
`80, 443, 8000, 8080, 8443` — narrower than EyeWitness; override with `-ports xlarge` or a custom list.

### Output
```
aquatone_report.html       ← Vue-based interactive report
aquatone_session.json      ← raw data
aquatone_urls.txt          ← list of all scanned URLs
screenshots/               ← PNGs
html/                      ← page source
headers/                   ← HTTP headers
```

### The HTML report

Opens at `/` which aliases to `/pages/by-similarity` — clusters of visually similar pages. The H2 header reads **"Pages by Similarity"**.

Other report tabs:
| Route | Header |
|-------|--------|
| `/` (default) | **Pages by Similarity** |
| `/pages/by-hosts` | Pages by Hosts |
| `/pages/single` | Pages |
| `/pages/graph` | (interactive graph) |
| `/pages/stats` | (statistics) |

Navbar brand: `AQUATONE`. Page title: `Aquatone Report`.

### Useful flags
| Flag | Purpose |
|------|---------|
| `-nmap` | Read Nmap XML from stdin |
| `-out DIR` | Output directory |
| `-ports xlarge` | Wider port range (5,381 ports) |
| `-ports small,medium,large,xlarge` | Preset port sets |
| `-threads N` | Parallelism |
| `-proxy URL` | Route through Burp |

### EyeWitness vs aquatone
| Aspect | EyeWitness | aquatone |
|--------|-----------|----------|
| Engine | Selenium (Firefox) | headless Chrome via DevTools |
| Speed | Slower | Faster on large scopes |
| Categorization | Built-in (HVT/CMS/401/etc.) | Clusters by visual similarity |
| Default creds suggestions | Yes | No |
| Input formats | Nmap XML, Nessus XML, URL list | Nmap XML, URL list |
| Active maintenance | Yes (RedSiege fork) | Original abandoned; community forks exist |

Run **both** on larger engagements — they have different categorization heuristics and catch different things.

---

## Service Identification (`-sV`)

Once screenshots highlight the interesting hosts, deeper service scans tell you exactly what's running:
```bash
sudo nmap --open -sV -p- 10.129.201.50
```

Typical findings on a mixed Windows host:
```
80/tcp    IIS 10.0
135/tcp   msrpc
139/tcp   netbios-ssn
445/tcp   microsoft-ds
3389/tcp  ms-wbt-server
5357/tcp  HTTPAPI (SSDP/UPnP)
8000/tcp  Splunkd httpd
8080/tcp  PRTG Network Monitor (Indy httpd)
8089/tcp  Splunkd (free license)
```

→ Splunk + PRTG on the same box = two strong attack candidates (both have well-documented RCE paths covered later in the module).

### Splunk fingerprint
```
8000/tcp  Splunkd httpd
8089/tcp  Splunkd httpd (free license; remote login disabled)
```
"Free license" is a tell — older Splunk free licenses **disabled authentication entirely** (CVE territory).

### PRTG fingerprint
```
Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
```
Version number visible → cross-reference public CVEs.

---

## Notetaking Skeleton

```
External Penetration Test - <Client>
├── Scope (IPs, URLs, fragile hosts, timeframes)
├── Client POCs
├── Credentials
├── Discovery/Enumeration
│   ├── Scans (Nmap, Nessus, Masscan with timestamps)
│   └── Live hosts
├── Application Discovery
│   ├── Scans (eyewitness/aquatone outputs with timestamps)
│   └── Interesting/Notable Hosts (URL + app + version)
├── Exploitation
│   └── <Hostname or IP>
└── Post-Exploitation
    └── <Hostname or IP>
```

Always timestamp scans and record exact command syntax — clients sometimes ask "what was that traffic at 14:33?" months after the engagement.

---

## /etc/hosts Setup for vhost Labs

This module uses vhosts to simulate multi-app environments. After spawning a target:
```bash
sudo sed -i '/inlanefreight.local/d' /etc/hosts
IP=<spawned target IP>
echo "$IP   app.inlanefreight.local dev.inlanefreight.local drupal-dev.inlanefreight.local drupal-qa.inlanefreight.local drupal-acc.inlanefreight.local drupal.inlanefreight.local blog.inlanefreight.local" | sudo tee -a /etc/hosts
```

Without the hosts entries, Apache's vhost router returns the wrong (or 404) page when you hit the bare IP.

---

## Lab Answers

**Q1 — EyeWitness `.db` filename:** `ew.db`

Confirmed in `EyeWitness.py`:
```python
manager = db_manager.DB_Manager(cli_parsed.d + '/ew.db')
```
Used by `--resume` to restart interrupted runs.

**Q2 — aquatone_report.html title page header:** `Pages by Similarity`

The default route `/` aliases to `/pages/by-similarity`, which renders:
```html
<h2 class="display-4 text-center border-bottom pb-3">Pages by Similarity</h2>
```

This is the first visible H2 on the home page. Confirmed by running aquatone locally and grepping the generated HTML.

---

## Exam Notes

- `-p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list` is the go-to starter scan
- **Always run a screenshot tool** — at scope > ~20 hosts, manual browsing is unworkable
- EyeWitness DB file = `ew.db` (resume target)
- Aquatone default page = "Pages by Similarity" (visual cluster view)
- Hostnames containing `dev`, `qa`, `acc` deserve extra attention — often unpatched
- "Free license" on Splunkd in the `-sV` output is a CVE indicator
- Save Nmap XML — both screenshot tools consume it directly
- Build the notebook BEFORE attacking — saves rework when scope grows
- Watch for non-standard ports running juicy apps — Jenkins on 8081, Tomcat on 8180, etc.
