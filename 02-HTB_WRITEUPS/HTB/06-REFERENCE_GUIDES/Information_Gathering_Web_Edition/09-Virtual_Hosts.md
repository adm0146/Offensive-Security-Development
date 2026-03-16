# 🖥️ Virtual Hosts

## Overview

**Virtual hosting** allows a single web server to host multiple websites or applications on one IP address. The web server uses the HTTP `Host` header from each request to determine which site to serve.

**Why it matters for recon:** Virtual hosts can expose internal subdomains, dev environments, admin panels, and staging sites that don't appear in public DNS records. These hidden VHosts are prime targets.

---

## ⚠️ Before You Start — /etc/hosts Setup

`.htb` domains don't exist in public DNS. Your machine won't resolve them unless you manually add the target to `/etc/hosts`. **Do this every time you spawn a target — before running any tools.**

```bash
echo "<TARGET_IP>  <domain>.htb" | sudo tee -a /etc/hosts
```

### Example

```bash
echo "154.57.164.78  inlanefreight.htb" | sudo tee -a /etc/hosts
```

### Verify

```bash
grep inlanefreight /etc/hosts
```

Without this step, gobuster, ffuf, curl, and your browser will all timeout or fail when trying to reach the domain. **Make it muscle memory:**

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

**Key insight:** A VHost without a DNS record is still accessible if you manually set the Host header or add the domain to `/etc/hosts`. This is exactly what VHost fuzzing exploits.

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

**Name-based is the most common** — and the most relevant for VHost fuzzing.

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

All three domains share one IP. The server reads `Host:` header → serves the right DocumentRoot.

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

### Full Example

```bash
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

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

**Watch for consistent response sizes** — if every word returns `Size: 1234`, the server is returning a wildcard response. Use `--exclude-length 1234` to filter noise.

---

## Accessing a Discovered VHost

If a VHost has no DNS record, add it to `/etc/hosts` to access it:

```bash
echo "10.129.17.237  forum.inlanefreight.htb" | sudo tee -a /etc/hosts
```

Then browse to `http://forum.inlanefreight.htb` or run further tools against it.

---

## VHost Fuzzing with ffuf

Alternative to gobuster — fuzzes the `Host` header directly:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     -u http://<TARGET_IP> \
     -H "Host: FUZZ.inlanefreight.htb" \
     -fs <FILTER_SIZE>
```

| Flag | Purpose |
|---|---|
| `-w` | Wordlist |
| `-u` | Target URL (use IP directly) |
| `-H` | Set custom header — `FUZZ` is the placeholder |
| `-fs` | Filter by response size (remove wildcard noise) |

---

## Key Takeaways

- VHosts let one IP serve many domains — not all are in public DNS
- The `Host` header is what the server uses to route requests
- **gobuster vhost** + SecLists = standard VHost enumeration approach
- `--append-domain` is required in modern gobuster
- Filter by `Status: 200` and watch response sizes for valid hits
- Add discovered VHosts to `/etc/hosts` to access them
- VHost fuzzing generates lots of traffic — use on authorized targets only
