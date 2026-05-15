# Section 10 — Preventing File Upload Vulnerabilities

> Theory only. No lab.

---

## Defense Layers (deploy all, not pick one)

```
1. Extension validation  → whitelist + blacklist (belt-and-suspenders)
2. Content validation    → magic bytes + Content-Type
3. Storage isolation     → randomized names, separate dir/server, no direct access
4. Server hardening      → disable_functions, no PHP exec in upload dir
5. Operational           → file size limits, AV scan, WAF, logging
```

---

## 1 — Extension Validation (Both Lists)

Use **both** whitelist (allowed) AND blacklist (dangerous) — if one is bypassed, the other catches it:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

// Blacklist — anywhere in filename (catches double-extension)
if (preg_match('/\.ph(p|ps|ar|tml)/i', $fileName)) {
    echo "Disallowed extension"; die();
}

// Whitelist — must END with allowed extension
if (!preg_match('/\.(jpg|jpeg|png|gif)$/i', $fileName)) {
    echo "Only images allowed"; die();
}
```
> Uses both a blacklist and a whitelist together. The blacklist catches PHP extensions anywhere in the filename (including double-extension tricks). The `$` anchor in the whitelist requires the filename to actually end with an image extension. The `/i` flag makes both checks case-insensitive.

Key points:
- Blacklist regex uses `\.ph(p|ps|ar|tml)` to catch `.php.jpg` (reverse-double)
- Whitelist regex uses `$` anchor — final extension must match
- `/i` flag handles case variants (`pHp`, `PHP`)
- Apply on BOTH client and server side (client = UX, server = security)

---

## 2 — Content Validation

Validate the file's actual content matches its claimed type:

```php
$contentType = $_FILES['uploadFile']['type'];                          // client header
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);     // server-detected from magic bytes

foreach ([$contentType, $MIMEtype] as $t) {
    if (!in_array($t, ['image/png', 'image/jpeg', 'image/gif'])) {
        echo "Invalid content type"; die();
    }
}
```
> Checks both the client-supplied Content-Type header and the server-detected MIME type from the file's actual bytes. Attackers can spoof the header but cannot easily fake both simultaneously.

**Stronger: re-encode the file server-side after upload.**
```php
// PHP — re-save as a clean image, stripping any embedded payloads
$img = imagecreatefromjpeg($_FILES['uploadFile']['tmp_name']);
imagejpeg($img, $target_path, 85);
imagedestroy($img);
```
> Re-encoding the image through PHP's GD library destroys any embedded PHP code or JavaScript. Only valid pixel data survives the round-trip. This kills the polyglot file technique entirely.
Re-encoding destroys polyglot files (PHP-in-image, JS-in-EXIF) because only valid image data survives the round-trip.

---

## 3 — Storage Isolation

### Don't reveal upload paths
- Serve files through a `download.php` proxy, not direct URLs
- Return 403 on any direct request to the uploads directory
- Hide the directory entirely from public listing

### Randomize filenames at storage
Store the original (sanitized) name in DB; use random hex/UUID on disk:
```php
$randomName = bin2hex(random_bytes(16)) . '.' . $allowed_ext;
$db->insert('uploads', ['display_name' => $sanitized, 'disk_name' => $randomName, 'owner_id' => $uid]);
```
> Stores the original display name in the database but saves the file with a random hex name on disk. This defeats filename injection, path traversal, and predictable-path attacks.

Defeats:
- Filename injection (randomized → no user-controlled chars in path)
- Predictable upload paths (no hash-based guessing like Section 11 of LFI module)
- Path traversal (no `../` chance)

### Separate server / container
Host uploads on a different server or in a Docker volume. Even if RCE achieved, the foothold is on the upload host, not the main app server.

```php
// In php.ini
open_basedir = /var/www/uploads/   # restrict PHP file access to this dir
```
> `open_basedir` restricts PHP so it can only open files within the specified directory tree. Even if an attacker achieves code execution, they cannot read files outside the uploads directory.

### Download proxy with security headers
```php
// download.php
$file = $db->getUserFile($_GET['id'], $userId);   // IDOR-safe lookup
if (!$file) http_response_code(403);

header('Content-Type: ' . $file['mime']);
header('Content-Disposition: attachment; filename="' . $file['display_name'] . '"');
header('X-Content-Type-Options: nosniff');   // no MIME sniffing
header('Content-Security-Policy: default-src \'none\'');
readfile('/storage/' . $file['disk_name']);
```
> Serves files through a proxy script instead of exposing the storage directory directly. `Content-Disposition: attachment` forces download instead of inline rendering, which kills stored XSS via SVG or HTML uploads. `X-Content-Type-Options: nosniff` prevents browser MIME type guessing.

Critical headers:
- `Content-Disposition: attachment` — forces download instead of inline render (kills stored XSS via SVG/HTML)
- `X-Content-Type-Options: nosniff` — disables browser MIME sniffing
- `Content-Security-Policy: default-src 'none'` — blocks JS/CSS even if served inline

---

## 4 — Server Hardening

### PHP — `php.ini`
```ini
disable_functions = system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec
open_basedir = /var/www/html/
allow_url_include = Off
allow_url_fopen = Off
expose_php = Off
```
> Disables PHP functions that execute OS commands, restricts file system access, and turns off remote file inclusion. Even if an attacker uploads a shell, `disable_functions` prevents them from running system commands.

### Apache — `/etc/apache2/mods-enabled/php*.conf`
```apache
# Fix loose regex (the misconfig exploited in Section 6):
<FilesMatch "\.ph(ar|p|tml)$">       # ← $ anchor required
    SetHandler application/x-httpd-php
</FilesMatch>

# Block PHP execution in uploads dir:
<Directory /var/www/html/uploads>
    php_flag engine off
</Directory>
```
> The `$` anchor prevents the reverse-double-extension attack. `php_flag engine off` blocks PHP execution in the uploads directory entirely — even if a PHP file is stored there, it will never execute.

### nginx
```nginx
location ~ ^/uploads/.*\.(php|phtml|phar)$ {
    deny all;   # extra safety
}

location ~ ^/uploads/ {
    try_files $uri =404;   # serve static only — never pass to PHP
}
```
> Blocks requests for PHP files in the uploads directory and serves all other content as static files. The second block ensures nginx never passes upload directory requests to the PHP-FPM handler.

### Error handling
- **Never display raw errors** (`display_errors = Off` in PHP)
- Return generic "Upload failed" messages
- Log details to a non-public file for debugging

---

## 5 — Operational Controls

| Control | Stops |
|---------|-------|
| File size limit | DoS via huge file, pixel-flood |
| Decompression limit | Zip bombs |
| ClamAV / similar scan | Known malware signatures |
| ModSecurity / WAF | Generic upload payload signatures |
| Library version pinning | CVEs in ImageMagick / ExifTool / ffmpeg |
| Audit logging | Forensic trail for incident response |
| Rate limiting | Brute-force upload abuse |

### File size in PHP
```ini
upload_max_filesize = 5M
post_max_size = 6M
```
> Sets the maximum upload and POST sizes in `php.ini`. Files larger than `upload_max_filesize` are rejected by PHP before your code even runs.

### Code-level size check
```php
if ($_FILES['uploadFile']['size'] > 5 * 1024 * 1024) {
    echo "File too large"; die();
}
```
> Adds an explicit size check in application code as a second layer. This catches edge cases where `php.ini` limits might not apply (e.g., chunked uploads).

---

## Defense Priority Table

| Attack class | Best defense |
|--------------|--------------|
| Arbitrary upload (`.php`) | Whitelist extension + content validation |
| Double extension (`shell.jpg.php`) | Whitelist with `$` anchor + Apache regex with `$` |
| Reverse double (`shell.php.jpg`) | Blacklist regex catching `.php` anywhere |
| Magic-byte / polyglot | Server-side re-encode of image |
| SVG XXE / XSS | Block SVG entirely, or sanitize XML before serve |
| Filename injection (cmd/SQL/XSS) | Randomize filename at storage, use UUID |
| Path traversal in filename | `basename()` strips dir components |
| LFI + upload chain | Disable PHP exec in upload dir |
| ImageMagick RCE | Patch + restrict policy.xml |
| Phar deserialization | `allow_url_fopen=Off` + don't run file ops on user-supplied paths |

---

## Secure Upload Reference Implementation (PHP)

```php
<?php
// 1. Size limit
if ($_FILES['f']['size'] > 5 * 1024 * 1024) {
    http_response_code(413); exit('File too large');
}

// 2. Extension whitelist with $ anchor
$name = basename($_FILES['f']['name']);
if (!preg_match('/\.(jpg|jpeg|png|gif)$/i', $name)) {
    exit('Only images allowed');
}

// 3. Extension blacklist (defense-in-depth)
if (preg_match('/\.(ph[ps]?|phtml|phar|html?|svg)/i', $name)) {
    exit('Disallowed extension pattern');
}

// 4. MIME validation
$mime = mime_content_type($_FILES['f']['tmp_name']);
if (!in_array($mime, ['image/jpeg', 'image/png', 'image/gif'])) {
    exit('Invalid content');
}

// 5. Re-encode to destroy embedded payloads
$img = @imagecreatefromstring(file_get_contents($_FILES['f']['tmp_name']));
if (!$img) exit('Corrupt image');

// 6. Random storage name + sanitized display name in DB
$diskName = bin2hex(random_bytes(16)) . '.jpg';
$displayName = preg_replace('/[^a-zA-Z0-9._-]/', '', $name);

imagejpeg($img, "/var/www/uploads/$diskName", 85);
imagedestroy($img);

// 7. Track in DB (sanitized name + owner)
$db->prepare('INSERT INTO uploads(owner_id, disk_name, display_name, mime) VALUES (?, ?, ?, ?)')
   ->execute([$userId, $diskName, $displayName, $mime]);

echo "Upload OK";
?>
```
> Full secure upload implementation. The seven steps cover size, extension whitelist, extension blacklist, MIME content check, re-encoding (kills polyglots), random filename on disk, and parameterized database storage. Each step is a separate defense layer — defeating one still leaves six more.

---

## Exam Notes

- The CPTS exam will ask "which defense stops which attack" — memorize the priority table above
- Whitelist > blacklist; **both** > either alone
- Magic-byte/MIME check + server-side **re-encoding** is the only defense that kills polyglot files
- Random filenames on disk = the single most effective defense against filename injection + path-disclosure attacks
- `open_basedir` + `disable_functions` are the safety net when validation is bypassed — even RCE gets sandboxed
- Apache `FilesMatch` MUST have `$` anchor — the Section 6 misconfiguration was a real production bug pattern
- For real-world: re-encoding images is the recommended fix even at perf cost — kills the entire polyglot class
