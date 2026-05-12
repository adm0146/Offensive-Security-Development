# SQLMap Essentials

Reference guides from the HTB Academy SQLMap Essentials module. All injection types (BEUSTQ), request handling, attack tuning, WAF bypass, OS exploitation.

---

## Reference Guides

- [00-EXAM_CHEATSHEET.md](00-EXAM_CHEATSHEET.md) — All sqlmap flags by category: input, tuning, bypass, enumeration, OS exploitation. Includes a decision tree for "when sqlmap says not injectable."

- [01-SQLMap_Overview.md](01-SQLMap_Overview.md) — Tool overview, supported DBMSes, BEUSTQ injection types (Boolean/Error/Union/Stacked/Time/Inline-Query), speed ranking.

- [02-Getting_Started.md](02-Getting_Started.md) — Basic syntax: `-u`, `--data`, `-r`, `--cookie`, `--batch`. Key flags to memorize.

- [03-SQLMap_Output.md](03-SQLMap_Output.md) — Reading sqlmap log messages: stable URL, reflective values, `--string=` discrimination, session files in `~/.local/share/sqlmap/output/`.

- [04-Running_SQLMap_on_HTTP_Request.md](04-Running_SQLMap_on_HTTP_Request.md) — GET, POST, cookie, JSON, header injection points. `--data='{"id":1}'`, `--level=2` for cookies, `--no-cast` for JSON.

- [05-Handling_SQLMap_Errors.md](05-Handling_SQLMap_Errors.md) — Debug flags: `--parse-errors`, `-t traffic.txt`, `-v 6`, `--proxy=http://127.0.0.1:8080` for Burp.

- [06-Attack_Tuning.md](06-Attack_Tuning.md) — `--prefix`/`--suffix` for non-standard boundaries, `--level`/`--risk` payload count, UNION tuning (`--union-cols`, `--union-char`, `--union-from`).

- [07-Database_Enumeration.md](07-Database_Enumeration.md) — `--banner`, `--current-user`, `--current-db`, `--is-dba`, `--dbs`, `--tables`, `--columns`, `--dump`.

- [08-Advanced_Database_Enumeration.md](08-Advanced_Database_Enumeration.md) — `--schema`, `--search` (LIKE-based hunt for keywords like `pass`/`cc`), built-in hash cracking, `--passwords` for DB-user accounts.

- [09-Bypassing_Protections.md](09-Bypassing_Protections.md) — Bypasses: `--csrf-token`, `--randomize`, `--eval`, `--random-agent`, tamper scripts (`between`, `space2comment`, `randomcase`), `--chunked`, HPP, `--flush-session`.

- [10-OS_Exploitation.md](10-OS_Exploitation.md) — `--file-read`, `--file-write` + `--file-dest`, `--os-shell` (interactive) and `--os-cmd` (one-shot). Use `--technique=E` for reliable shell output.

- [11-Skills_Assessment.md](11-Skills_Assessment.md) — Minishop assessment: JSON `action.php` with `>` and `space` filtered → `--tamper=between` + `--random-agent` → dump `production.final_flag`.
