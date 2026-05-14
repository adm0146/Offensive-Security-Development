# File Upload Attacks

Reference guides from the HTB Academy File Upload Attacks module. Bypasses for client-side, blacklist, whitelist, content-type, and MIME-type filters; SVG XXE; phar polyglots; prevention.

---

## Reference Guides

- [00-EXAM_CHEATSHEET.md](00-EXAM_CHEATSHEET.md) — Full playbook: bypasses by filter type, web shells per language, magic bytes, PHP extension variants, SVG XXE, reverse shells, prevention table, decision tree.

- [01-Intro_to_File_Upload_Attacks.md](01-Intro_to_File_Upload_Attacks.md) — Why uploads are high-severity, types of attacks (RCE / XSS / XXE / DoS / overwrite), where vulnerabilities come from, module roadmap.

- [02-Absent_Validation.md](02-Absent_Validation.md) — Arbitrary file upload (no filter): fingerprint web framework, upload `.php`, find upload path, confirm execution.

- [03-Upload_Exploitation.md](03-Upload_Exploitation.md) — Web shells (one-liner per language), pre-built shells on Kali, reverse shell generation with msfvenom, PTY upgrade.

- [04-Client-Side_Validation.md](04-Client-Side_Validation.md) — Bypass JS-only filters via direct curl/Burp; DevTools disable of `onchange` validators.

- [05-Blacklist_Filters.md](05-Blacklist_Filters.md) — PHP extension fuzzing: `.phar`, `.phtml`, `.php5`–`.php7`, case variants, character injection.

- [06-Whitelist_Filters.md](06-Whitelist_Filters.md) — Double extension (`shell.jpg.php`), reverse double (`shell.php.jpg`), character injection, exploiting loose Apache `<FilesMatch>` regex.

- [07-Type_Filters.md](07-Type_Filters.md) — Content-Type header spoofing, magic byte injection (`GIF8`), polyglot files, combining all five filter bypasses.

- [08-Limited_File_Uploads.md](08-Limited_File_Uploads.md) — SVG XXE for read/RCE, exiftool XSS in EXIF, DOCX/XLSX XXE, decompression bombs, pixel flood DoS.

- [09-Other_Upload_Attacks.md](09-Other_Upload_Attacks.md) — Filename injection (cmd/SQL/XSS/path traversal), upload directory disclosure, Windows reserved names (CON/NUL), 8.3 filenames, library CVEs.

- [10-Preventing_File_Upload_Vulnerabilities.md](10-Preventing_File_Upload_Vulnerabilities.md) — Defense layers: whitelist+blacklist, MIME validation, server-side re-encode, random filenames, `disable_functions`, `open_basedir`, secure download proxy.

- [11-Skills_Assessment.md](11-Skills_Assessment.md) — Uploads Shop e-commerce assessment: SVG XXE for source disclosure → regex analysis → `.phar.jpg` polyglot at `user_feedback_submissions/YYMMDD_*` → RCE → flag.
