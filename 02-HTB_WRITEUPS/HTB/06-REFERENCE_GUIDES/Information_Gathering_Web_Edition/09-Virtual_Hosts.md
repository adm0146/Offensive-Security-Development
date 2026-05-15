# 🖥️ Virtual Hosts

## Overview

Virtual hosting lets a single web server host multiple websites on one IP address. The server reads the `Host` header in each HTTP request to decide which site to serve.

This matters for recon because virtual hosts can expose internal subdomains, development environments, admin panels, and staging sites that never appear in public Domain Name System (DNS) records. These hidden VHosts are prime targets.

---

## ⚠️ Before You Start — /etc/hosts Setup

`.htb` domains do not exist in public DNS. Your machine cannot resolve them unless you manually add the target to `/etc/hosts`. Do this every time you spawn a target — before running any tools.

```bash
echo "<TARGET_IP>  <domain>.htb" | sudo tee -a /etc/hosts
```
> Appends the target IP and hostname to your local DNS override file. Replace `<TARGET_IP>` and `<domain>` with the actual values. Do this for every `.htb` domain before running any tools against it.

### Example

```bash
echo "154.57.164.78  inlanefreight.htb" | sudo tee -a /etc/hosts
```
> Adds the HTB lab target to `/etc/hosts` so the `.htb` domain resolves locally. Swap the IP and domain name for your specific target.

### Verify

```bash
grep inlanefreight /etc/hosts
```
> Checks that the entry was added correctly by searching `/etc/hosts` for the target domain name. If you see the line you just added, the resolution will work.

Without this step, gobuster, ffuf, curl, and your browser will all time out or fail. Make it muscle memory:

```
1. Spawn target → get IP
2. Add to /etc/hosts
3. Then start working
```

---

## VHosts vs Subdomains

| Concept | Description | DNS Record? |
|---|---|---|
| **Subdomain** | Extension of a main domain (e.g., `blog.example.com`) | ✅ Yes — publicly resolvable |
| **Virtual Host** | Server-side config serving different content based on Host header | ❌ Not always — can be internal only |

A VHost without a DNS record is still accessible if you manually set the `Host` header or add the domain to `/etc/hosts`. This is exactly what VHost fuzzing exploits.

---

## How VHost Lookup Works

```
Browser → HTTP Request (Host: www.inlanefreight.com)
    ↓
WebServer examines Host header
    ↓
Matches against VirtualHost config
    ↓
Retrieves files from matching DocumentRoot
    ↓
Returns HTTP Response to Browser
```

---

## Types of Virtual Hosting

| Type | How It Works | Pros | Cons |
|---|---|---|---|
| **Name-Based** | Uses HTTP `Host` header to differentiate sites | Most common, no extra IPs needed, easy setup | SSL/TLS limitations |
| **IP-Based** | Each site gets its own IP address | Works with any protocol, better isolation | Expensive, not scalable |
| **Port-Based** | Different sites on different ports (80, 8080) | Useful when IPs are limited | Not user-friendly, requires port in URL |

Name-based hosting is the most common type and the most relevant for VHost fuzzing.

---

## Apache VHost Config Example

```apache
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>
```

All three domains share one IP address. The server reads the `Host:` header from each request and serves the matching DocumentRoot directory.

---

## VHost Discovery — Manual vs Automated

### Manual Approach
- Analyze HTTP response headers
- Reverse DNS lookups
- Check `/etc/hosts` entries

### Automated Tools

| Tool | Language | Best For |
|---|---|---|
| **gobuster** | Go | Fast VHost brute-forcing, custom wordlists |
| **ffuf** | Go | Fuzzing Host header, flexible filtering |
| **feroxbuster** | Rust | Recursive brute-forcing, wildcard detection |

---

## gobuster — VHost Brute-Forcing

### Core Command

```bash
gobuster vhost -u http://<TARGET_IP> -w <WORDLIST> --append-domain
```
> Brute-forces virtual host names by sending requests with different `Host:` headers to the same IP. `--append-domain` is required in newer gobuster versions — it appends the base domain so each wordlist entry becomes a full hostname (e.g., `dev` becomes `dev.inlanefreight.htb`). Replace the URL and wordlist path for your target.

### Full Example

```bash
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```
> Full example targeting port 81 with the 110K subdomain wordlist. Watch the output for `Status: 200` responses — those are live virtual hosts. If everything returns the same size, add `--exclude-length <SIZE>` to filter out the wildcard response.

### Important Flags

| Flag | Purpose |
|---|---|
| `-u` | Target URL (use IP or known domain) |
| `-w` | Wordlist path |
| `--append-domain` | **Required in newer versions** — appends base domain to each word (e.g., `dev` → `dev.inlanefreight.htb`) |
| `-t` | Number of threads (increase for faster scanning, e.g., `-t 50`) |
| `-k` | Ignore SSL/TLS certificate errors |
| `-o` | Save output to file (`-o results.txt`) |

> **Note:** Older versions of gobuster appended the domain automatically. Newer versions **require** `--append-domain` or results will be wrong.

---

## What to Look For in gobuster Output

```
Found: forum.inlanefreight.htb:81 Status: 200 [Size: 100]
```

| Field | What It Means |
|---|---|
| `Found:` | A valid VHost was discovered |
| `forum.inlanefreight.htb:81` | The full virtual hostname and port |
| `Status: 200` | Server returned content — **this is a live VHost** |
| `Size: 100` | Response body size — useful for filtering false positives |

### Filtering Results

| Status Code | Meaning |
|---|---|
| `200` | Live VHost — investigate further |
| `301/302` | Redirect — follow it |
| `403` | Forbidden — exists but access denied (still interesting) |
| `404` | Not found — likely not a valid VHost |
| `400` | Bad request — filter these out (wildcard responses) |

Watch for consistent response sizes. If every word returns `Size: 1234`, the server is returning a wildcard response. Use `--exclude-length 1234` to filter that noise.

---

## Accessing a Discovered VHost

If a VHost has no DNS record, add it to `/etc/hosts` to access it. Then browse to it or run further tools against it:

```bash
echo "10.129.17.237  forum.inlanefreight.htb" | sudo tee -a /etc/hosts
```
> Adds the newly discovered VHost to your local hosts file so you can browse to it. Swap the IP and hostname. Do this for every VHost you find before running further tools against it.

Then browse to `http://forum.inlanefreight.htb` or run further tools against it.

---

## VHost Fuzzing with ffuf

ffuf is an alternative to gobuster. It fuzzes the `Host` header directly using the `FUZZ` keyword:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     -u http://<TARGET_IP> \
     -H "Host: FUZZ.inlanefreight.htb" \
     -fs <FILTER_SIZE>
```
> ffuf VHost fuzzing — same idea as gobuster but injects wordlist entries directly into the `Host:` header via the `FUZZ` keyword. `-fs` filters responses by size to remove wildcard noise. Get the default size first with `curl -s http://<TARGET_IP> | wc -c` and use that value for `-fs`.

| Flag | Purpose |
|---|---|
| `-w` | Wordlist |
| `-u` | Target URL (use IP directly) |
| `-H` | Set custom header — `FUZZ` is the placeholder |
| `-fs` | Filter by response size (remove wildcard noise) |
| `-mc all` | Match ALL status codes (catches 400, 403 that default filters miss) |

---

## When Standard Wordlists Miss — Build a Custom Wordlist

If a single wordlist does not find what you need, combine all DNS wordlists and filter by a prefix pattern.

### Step 1: Find the default response size

```bash
curl -s http://<TARGET_IP>:<PORT> | wc -c
```
> Fetches the default page and counts the number of bytes in the response body. Use this number as your `-fs` filter value so ffuf ignores wildcard responses that match the default page size.

This gives you the default page size in bytes (for example, `116`). Use this number as your `-fs` filter value to remove wildcard responses.

### Step 2: Run the standard scan first

```bash
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
     -u http://target.htb:<PORT> \
     -H "Host: FUZZ.target.htb" \
     -fs 116
```
> Standard ffuf VHost scan using the 110K wordlist. `-fs 116` filters out the default 116-byte response. Adjust the filter value to match your baseline. Swap the domain and port for your target.

### Step 3: If you need more — build a targeted wordlist from ALL DNS lists

```bash
grep -h ^<PREFIX> ~/SecLists/Discovery/DNS/* > /tmp/custom_wordlist.txt
```
> Searches every wordlist in the DNS directory for lines starting with your chosen prefix. `-h` suppresses filenames from the output. Replace `<PREFIX>` with a pattern like `web`, `dev`, or `admin`. The result is saved to a temp file for deduplication in the next step.

| Part | What It Does |
|---|---|
| `grep -h` | Search without printing filenames |
| `^<PREFIX>` | Only lines starting with your prefix (e.g., `^web`, `^dev`, `^admin`) |
| `~/SecLists/Discovery/DNS/*` | Search across **every** wordlist in the DNS directory |
| `> /tmp/custom_wordlist.txt` | Save to a temp file |

### Step 4: Deduplicate and fuzz

```bash
sort -u /tmp/custom_wordlist.txt | ffuf -w - -u http://target.htb:<PORT> \
     -H "Host: FUZZ.target.htb" \
     -fs 116
```
> Deduplicates the custom wordlist with `sort -u` and pipes it directly into ffuf via `-w -` (stdin as wordlist). This runs the VHost scan with your combined, deduplicated list without writing a second file.

| Part | What It Does |
|---|---|
| `sort -u` | Remove duplicate entries |
| `ffuf -w -` | Read wordlist from stdin (piped input) |
| `-fs 116` | Filter out default page responses |

> **Why this works:** The top 110K wordlist only had 216 `web*` entries. But combining ALL DNS wordlists in SecLists gives you thousands more — entries from `bitquark`, `dns-Jhaddix`, `deepmagic`, `shubs-subdomains`, etc. that aren't in the standard list.

---

## Key Takeaways

- VHosts let one IP serve many domains. Not all of them are in public DNS.
- The server uses the `Host` header to route each request to the right site.
- gobuster vhost with SecLists is the standard VHost enumeration approach.
- `--append-domain` is required in modern versions of gobuster.
- Filter results by `Status: 200` and watch response sizes to identify valid hits.
- Add every discovered VHost to `/etc/hosts` before running further tools against it.
- If standard wordlists miss the target, build a custom one: `grep -h ^<prefix> ~/SecLists/Discovery/DNS/*` pulls entries from every DNS wordlist.
- VHost fuzzing generates a lot of traffic. Only run it on authorized targets.
