# Section 3 — External Information Gathering

> First technical phase of the engagement. No credentials, no insider knowledge — just the target IP and scope. Goal: map the attack surface before touching anything.

---

## Methodology — How the Pieces Fit Together

This section chains together skills from three modules:
- **Network Enumeration with Nmap** — port scanning, service detection, script scanning
- **Information Gathering Web Edition** — DNS zone transfers, subdomain enumeration, vhost fuzzing
- **Footprinting** — service fingerprinting (FTP, SSH, SMTP, DNS, etc.)

The thought process: scan first to see what's listening, then use what you find to expand the scope (DNS → subdomains → more attack surface).

---

## Step 1 — Quick Top-1000 TCP Scan

```bash
sudo nmap --open -oA inlanefreight_ept_tcp_1k -iL scope
```
> Fast initial scan of the top 1,000 TCP ports. `--open` filters to only show open ports. `-oA` saves output in all three formats (normal, grepable, XML). `-iL scope` reads target IPs from a file. This gives you a quick lay of the land while your full scan runs in the background.

**Results — 11 ports open:**

| Port | Service | Module Connection |
|------|---------|-------------------|
| 21 | FTP | Footprinting — check anonymous login, version → CVE |
| 22 | SSH | Footprinting — version check, brute force later if you get usernames |
| 25 | SMTP | Footprinting — user enumeration via VRFY/EXPN/RCPT TO |
| 53 | DNS | Info Gathering Web — zone transfer, subdomain enum |
| 80 | HTTP | Info Gathering Web / Web attacks — main web app |
| 110 | POP3 | Footprinting — email retrieval, cred testing |
| 111 | RPCbind | Footprinting — check for NFS exports |
| 143 | IMAP | Footprinting — email retrieval, cred testing |
| 993 | IMAPS | Encrypted IMAP |
| 995 | POP3S | Encrypted POP3 |
| 8080 | HTTP proxy | Second web app — different attack surface |

## Step 2 — Full Port Scan with Aggressive Detection (Background)

```bash
sudo nmap --open -p- -A -oA inlanefreight_ept_tcp_all_svc -iL scope
```
> Full 65535-port scan with `-A` (OS detection + version scanning + script scanning + traceroute). This is slow but thorough. Run it in the background while you start working with the top-1000 results. `-A` is more intrusive than `-sV` alone — the NSE scripts may interact with services.

**Key findings from the full scan:**

| Service | Version | Notable |
|---------|---------|---------|
| FTP | vsftpd 3.0.3 | **Anonymous login allowed**, `flag.txt` visible |
| SSH | OpenSSH 8.2p1 Ubuntu | Version fingerprint confirms Ubuntu |
| SMTP | Postfix | VRFY command available (user enumeration) |
| DNS | Unknown version | Zone transfer possible |
| HTTP :80 | Apache 2.4.41 (Ubuntu) | Main Inlanefreight site |
| HTTP :8080 | Apache 2.4.41 (Ubuntu) | "Support Center" — potential open proxy |
| POP3/IMAP | Dovecot | Email services |

### Extracting Service Summary from Grepable Output

```bash
egrep -v "^#|Status: Up" inlanefreight_ept_tcp_all_svc.gnmap | cut -d ' ' -f4- | tr ',' '\n' | \
sed -e 's/^[ \t]*//' | awk -F '/' '{print $7}' | grep -v "^$" | sort | uniq -c | sort -k 1 -nr
```
> Parses the `.gnmap` file to extract and count unique service versions. Useful on multi-host scans to quickly see what you're dealing with across the network. On a single host like this it just gives a clean summary.

---

## Step 3 — DNS Zone Transfer

**Why DNS first:** port 53 is open, and a successful zone transfer expands your attack surface for free — every subdomain is a potential separate web app with its own vulnerabilities.

```bash
dig axfr inlanefreight.local @10.129.203.101
```
> `axfr` = full zone transfer request. If the DNS server allows zone transfers to any IP (misconfiguration), it dumps every DNS record in the zone. This is a finding in itself (DNS zone transfer should be restricted to authorized secondary DNS servers).

**Subdomains discovered (9):**

| Subdomain | Notes |
|-----------|-------|
| blog.inlanefreight.local | Blog — CMS? WordPress? |
| careers.inlanefreight.local | Careers portal — file upload for resumes? |
| dev.inlanefreight.local | Dev site — often has debug info, default creds |
| gitlab.inlanefreight.local | GitLab — source code, credentials in repos |
| ir.inlanefreight.local | Investor relations |
| status.inlanefreight.local | Status page |
| support.inlanefreight.local | Support center — matches port 8080? |
| tracking.inlanefreight.local | Tracking system |
| vpn.inlanefreight.local | VPN portal — login page, possible cred spray |

---

## Step 4 — VHost Fuzzing (Catch What DNS Missed)

Zone transfers only return records the admin configured. VHost fuzzing finds hosts that respond to different `Host:` headers but may not have DNS records.

### Step 4.1 — Baseline the invalid response

```bash
curl -s -I http://10.129.203.101 -H "HOST: defnotvalid.inlanefreight.local" | grep "Content-Length:"
```
> Send a request with a fake hostname. The response size (15157 bytes) is the baseline for "not a real vhost." Any response with a different size is a real vhost.

### Step 4.2 — Fuzz with ffuf

```bash
ffuf -w /path/to/namelist.txt:FUZZ -u http://10.129.203.101/ -H 'Host:FUZZ.inlanefreight.local' -fs 15157
```
> `-fs 15157` filters out the baseline response size. Everything that passes the filter is a real vhost. Use `~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` or similar on your box.

**Result:** ffuf found the same 9 subdomains from the zone transfer plus **one additional vhost** that wasn't in DNS (redacted — this is a flag question).

**Lesson:** always run both techniques. Zone transfer gives you the configured records; vhost fuzzing catches unregistered hosts that still respond.

---

## Step 5 — Update /etc/hosts

```bash
sudo tee -a /etc/hosts > /dev/null <<EOT

## inlanefreight hosts
10.129.x.x inlanefreight.local blog.inlanefreight.local careers.inlanefreight.local dev.inlanefreight.local gitlab.inlanefreight.local ir.inlanefreight.local status.inlanefreight.local support.inlanefreight.local tracking.inlanefreight.local vpn.inlanefreight.local
EOT
```
> Add all discovered subdomains to `/etc/hosts` so your browser and tools resolve them to the target IP. Replace `10.129.x.x` with your actual target. Add the redacted vhost here too once you find it.

---

## Decision Tree — What to Hit Next

At this point you have a massive attack surface. The thought process for prioritization:

```
FTP anonymous login → free flag, check for sensitive files
DNS zone transfer → already done, found subdomains
Each subdomain → fingerprint the web app (whatweb, browse it)
SMTP VRFY → enumerate valid usernames for later spraying
Port 8080 → different web app, separate attack surface
GitLab → source code = credentials, API keys, config files
dev.* → dev sites often have debug mode, default creds, exposed endpoints
careers.* → file upload = potential web shell
vpn.* → login page = potential brute force target
```

The key skill here is **breadth-first enumeration** — touch everything lightly before going deep on any one thing. Map the full surface, then attack the weakest point.

---

## Exam Relevance

- Always run both a quick scan AND a full port scan — services on non-standard ports are common on the CPTS exam
- DNS zone transfer is a freebie when port 53 is open — always try it
- VHost fuzzing catches what DNS misses — always do both
- Save all scan output (`-oA`) — you'll reference it throughout the engagement and need it for the report
- The grepable output parsing one-liner is worth memorizing for multi-host engagements
