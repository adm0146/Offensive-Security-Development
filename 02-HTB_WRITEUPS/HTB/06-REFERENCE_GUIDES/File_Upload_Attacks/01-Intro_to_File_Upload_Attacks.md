# Section 1 — Intro to File Upload Attacks

> Theory only. No lab.

---

## Why File Upload Is Such a Common Vuln

Almost every modern web app accepts user-uploaded files — avatars, documents, attachments, profile media. Each accepting endpoint is a potential foothold:

- File travels from the attacker to the server's filesystem
- Server stores it under a path the web server may serve back
- If the server **executes** the file (PHP, JSP, ASPX), the attacker gets RCE

The vulnerability is rarely in "uploading" itself — it's in **what's allowed and how it's validated**.

---

## Severity Spectrum

| Worst | → | Best |
|-------|---|------|
| **Unauthenticated arbitrary file upload** | Authenticated arbitrary upload | Filtered upload (bypassable) | Filtered upload (truly safe) |
| Anyone → instant RCE | Foothold → RCE after auth | Bypass needed → RCE | DoS / metadata leaks at most |

Unauthenticated arbitrary upload to a web-executable directory = one of the highest-severity web vulnerabilities possible (CVSS 9.0+).

---

## Attack Outcomes Beyond RCE

Even when arbitrary upload isn't possible, restricted upload can still lead to:

| Outcome | How |
|---------|-----|
| **RCE** | Upload web shell / reverse shell script — module's main focus |
| **Stored XSS** | Upload SVG/HTML with `<script>`, served back to other users |
| **XXE** | Upload SVG/DOCX/XLSX — anything XML-parsed by the backend |
| **DoS** | Zip bomb, decompression bomb, oversized files, malformed images crashing parsers |
| **Overwrite critical files** | Upload `.htaccess` to enable PHP exec in dir; upload `index.html` to deface; overwrite `web.config` |
| **SSRF** | Upload XML/SVG with external entity that pulls internal URLs |
| **Path traversal** | Filename = `../../../etc/cron.d/x` writes arbitrary location |
| **Phishing host** | Upload HTML page on the trusted domain to phish users |

---

## Where Vulnerabilities Come From

1. **Missing validation** — no checks at all
2. **Blacklist-based extension check** — denies `.php`, attacker uses `.phtml`/`.php5`/`.phar`
3. **Client-side-only validation** — JavaScript check bypassed with curl/Burp
4. **MIME-type check (Content-Type header)** — attacker spoofs the header
5. **Magic-byte check** — attacker prepends valid file signature to malicious file
6. **Filename sanitization bugs** — null bytes, double extensions, encoding tricks
7. **Vulnerable libraries** — ImageMagick, Apache Commons FileUpload, Spring MVC — historical CVEs
8. **Misconfigured web server** — PHP execution allowed in upload dir

---

## Why "Just" Filtered Upload Often Becomes RCE

Even with a tight whitelist (only `.jpg`, `.png`):
- Server might still execute embedded PHP inside an "image" (Section 7 LFI module covered this)
- Library bugs: ImageMagick `convert` command injection from crafted SVG (CVE-2016-3714 "ImageTragick")
- Polyglot files — valid GIF + valid PHP simultaneously
- Apache misconfiguration: `.jpg.php` interpreted as PHP

This module covers each angle individually.

---

## Module Roadmap

```
Section 2     Theory: how uploads work + types of validation
Sections 3-6  Bypassing each validation type (client, blacklist, whitelist, type/content)
Section 7     Limited upload attacks (XSS via SVG, XXE, etc.)
Section 8     Other attack patterns (zip bombs, overwrite, etc.)
Section 9     Real-world CVEs (vulnerable libraries)
Section 10    Prevention & secure defaults
Section 11    Skills assessment — full chain
```

---

## Exam Notes

- File upload is the **single most common** path to RCE on web pentests — appears in nearly every engagement report
- "Unauthenticated arbitrary file upload" is the worst-case finding — flag it as Critical/9.0+ CVSS
- Even restricted uploads have value — XSS via SVG and XXE via DOCX are real impact, not just "low severity"
- Library bugs (ImageMagick, ExifTool, ghostscript) are the wildcard — patch level matters as much as code review
- This module pairs directly with LFI (Section 7 of the LFI module) — upload + include = guaranteed RCE
