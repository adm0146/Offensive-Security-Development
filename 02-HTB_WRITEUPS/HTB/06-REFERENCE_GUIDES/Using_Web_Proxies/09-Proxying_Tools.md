# Section 9 — Proxying Tools

> Route command-line tools and Metasploit through Burp/ZAP to intercept and inspect their requests.
> Why: see exactly what tools are sending, debug them, or modify their requests on the fly.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Last line in http_put module request | `msf test file` |

The `http_put` module sends a PUT request to upload a test file. The request body (last line) is the file content, which defaults to `msf test file` (set by the `FILEDATA` option).

---

## Method 1 — Proxychains (Route ANY Linux Tool)

**When:** You want to send any CLI tool's traffic through Burp without changing the tool's config.
**Why:** Proxychains intercepts all TCP connections from a process and routes them through a proxy — works with anything.

```bash
# Step 1: Configure proxychains to use Burp
sudo nano /etc/proxychains.conf
# Comment out the default socks4 line:
# socks4  127.0.0.1 9050
# Add Burp at the bottom:
http    127.0.0.1   8080

# Step 2: Prefix any command with proxychains:
proxychains -q curl http://TARGET_IP:PORT
proxychains -q nmap -sT -p 80,443 TARGET_IP
proxychains -q sqlmap -u "http://TARGET/page?id=1"
# -q = quiet mode (suppress proxychains connection info)
```

All traffic from the command now appears in Burp's HTTP History — you can see every request, forward/drop them, and modify them.

---

## Method 2 — Metasploit PROXIES Option

**When:** Running an MSF module and you want to see exactly what it sends.
**Why:** Debug module behavior, verify the request format, or intercept and modify during exploitation.

```bash
msfconsole

use auxiliary/scanner/http/http_put
set PROXIES HTTP:127.0.0.1:8080   # route through Burp
set RHOSTS TARGET_IP
set RPORT TARGET_PORT
run
```

**The PROXIES format:** `PROTOCOL:IP:PORT`
- `HTTP:127.0.0.1:8080` = Burp HTTP proxy
- `SOCKS5:127.0.0.1:1080` = SOCKS5 proxy (Chisel, SSH)

After running, check Burp's HTTP History to see all requests the module sent.

---

## What http_put Sends

The `auxiliary/scanner/http/http_put` module tests whether a web server allows arbitrary file uploads via PUT requests (a common misconfiguration on old Apache/IIS servers).

```http
PUT /random_filename.txt HTTP/1.1
Host: TARGET_IP:PORT
Content-Type: text/plain
Content-Length: 13

msf test file
```

Key options:
```
FILEDATA   = "msf test file"   ← the body content (last line of request)
FILENAME   = random .txt file  ← what to upload
ACTION     = PUT               ← PUT (upload) or DELETE
```

---

## Other Tools — Setting the Proxy

Most tools have their own way to set a proxy:

```bash
# curl:
curl -x http://127.0.0.1:8080 http://TARGET

# wget:
wget -e use_proxy=yes -e http_proxy=127.0.0.1:8080 http://TARGET

# Python requests (in scripts):
import requests
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.get("http://TARGET", proxies=proxies)

# Environment variables (works for many tools):
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
# Then run any tool normally — many tools respect these env vars
```

---

## Exam Notes

- Proxychains = universal proxy wrapper for Linux — route any tool through Burp with `proxychains -q COMMAND`
- MSF PROXIES format: `HTTP:127.0.0.1:8080` (not just an IP:port)
- Proxying slows tools down — only enable when you need to inspect requests, not during normal use
- Once proxied, the requests appear in Burp HTTP History — you can right-click → Send to Repeater to replay/modify them
- For HTTPS traffic through proxychains, the CA cert must be installed (same as browser)
- `set PROXIES` works in MSF for most scanner/exploit modules that make HTTP requests
