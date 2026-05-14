# File Inclusion

Reference guides from the HTB Academy File Inclusion module. LFI, RFI, PHP wrappers, log poisoning, file upload chains, and hardening.

---

## Reference Guides

- [00-EXAM_CHEATSHEET.md](00-EXAM_CHEATSHEET.md) — Full LFI/RFI playbook: sinks table, bypass matrix, critical files (Linux + Windows), PHP wrappers, log poisoning, automation, prevention, decision tree.

- [01-Intro_to_File_Inclusion.md](01-Intro_to_File_Inclusion.md) — What LFI/RFI is, read vs execute distinction by sink function, comparison with path traversal/RFI/SSRF.

- [02-Local_File_Inclusion.md](02-Local_File_Inclusion.md) — Basic LFI: absolute path, path traversal (`../`), inclusion patterns (prefix dir, prefix filename, appended extension), second-order LFI.

- [03-Basic_Bypasses.md](03-Basic_Bypasses.md) — Filter bypasses: non-recursive `../` strip (`....//`), URL encoding, double encoding, approved-path regex, path truncation, null byte (PHP < 5.3).

- [04-PHP_Filters.md](04-PHP_Filters.md) — `php://filter/read=convert.base64-encode/resource=FILE` for source code disclosure. Fuzzing for PHP files first with ffuf.

- [05-PHP_Wrappers.md](05-PHP_Wrappers.md) — `data://`, `php://input`, `expect://` for RCE. Check `allow_url_include` via php.ini first.

- [06-Remote_File_Inclusion.md](06-Remote_File_Inclusion.md) — RFI via HTTP/FTP/SMB. Hosting payloads with Python http.server, pyftpdlib, impacket-smbserver.

- [07-LFI_and_File_Uploads.md](07-LFI_and_File_Uploads.md) — LFI + upload chain: embed PHP in image (GIF8 magic byte), `zip://` wrapper, `phar://` wrapper.

- [08-Log_Poisoning.md](08-Log_Poisoning.md) — PHP session poisoning, Apache/nginx access.log poisoning via User-Agent, `/proc/self/environ` poisoning.

- [09-Automated_Scanning.md](09-Automated_Scanning.md) — ffuf for hidden parameters, LFI-Jhaddix wordlist for payloads, webroot enumeration, etc-files of all Linux packages.

- [10-File_Inclusion_Prevention.md](10-File_Inclusion_Prevention.md) — Whitelisting, `basename()`, `allow_url_include=Off`, `open_basedir`, `disable_functions`, ModSecurity.

- [11-Skills_Assessment.md](11-Skills_Assessment.md) — Sumace Consulting chain: read-only image.php LFI to disclose source, upload PHP shell with predictable md5 path, double-URL-encoded LFI in `contact.php?region=` for RCE → flag.
