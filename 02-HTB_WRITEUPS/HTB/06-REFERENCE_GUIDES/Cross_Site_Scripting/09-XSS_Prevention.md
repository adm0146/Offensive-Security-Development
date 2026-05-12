# Section 9 — XSS Prevention

> Theory only. No lab.

---

## Defense Layers

Every XSS bug has a **source** (user input) and a **sink** (where it's rendered). Defense applies controls at both, on both ends of the stack.

```
Browser (Front-end)              Server (Back-end)
─────────────────                ─────────────────
Input validation (regex)         Input validation (regex / filter_var)
Input sanitization (DOMPurify)   Input sanitization (htmlspecialchars / DOMPurify)
Avoid dangerous sinks            Output encoding (htmlentities)
                                 Server headers (CSP, X-XSS-Protection)
                                 Cookie flags (HttpOnly, Secure, SameSite)
                                 WAF
```

> Front-end defenses can be bypassed by anyone crafting raw HTTP requests. They improve UX but are never sufficient on their own — back-end is the real boundary.

---

## Front-End

### Input Validation (regex)
```javascript
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}
```

### Input Sanitization with DOMPurify
```html
<script src="dist/purify.min.js"></script>
<script>
const clean = DOMPurify.sanitize(userInput);
</script>
```
DOMPurify strips/escapes anything that could execute — `<script>`, event handlers, `javascript:` URIs, etc. **Industry standard for client-side sanitization.**

### Never put user input into

| Context | Why dangerous |
|---------|---------------|
| `<script>...</script>` | JS execution |
| `<style>...</style>` | CSS injection → exfil, sometimes JS |
| HTML attribute values | Breakout via `"` or `'` |
| HTML comments `<!-- -->` | Comment escape |
| `eval()`, `setTimeout("...")`, `setInterval("...")` | Direct JS eval |

### Dangerous JS sinks (avoid for untrusted data)

**Native:**
- `innerHTML`, `outerHTML`
- `document.write()`, `document.writeln()`
- `document.domain`

**jQuery:**
- `html()`, `parseHTML()`
- `add()`, `append()`, `prepend()`, `after()`, `insertAfter()`, `before()`, `insertBefore()`
- `replaceAll()`, `replaceWith()`

**Safe alternatives:** `textContent`, `innerText`, jQuery `text()` — these treat input as plain text, never HTML.

---

## Back-End

### Input Validation
**PHP:**
```php
if (filter_var($_GET['email'], FILTER_VALIDATE_EMAIL)) {
    // proceed
} else {
    // reject
}
```

**Node.js:** Same regex pattern as front-end.

### Input Sanitization
**PHP:**
```php
$safe = addslashes($_GET['input']);   // escape special chars
```

**Node.js:**
```javascript
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(dirty);
```

### Output Encoding (the most reliable defense)

Encode special characters → HTML entities. The browser displays them as text, never parses them as HTML.

**PHP:**
```php
echo htmlspecialchars($_GET['input']);   // < → &lt;
echo htmlentities($_GET['input']);        // broader char set
```

**Node.js:**
```javascript
import { encode } from 'html-entities';
encode('<');   // '&lt;'
```

> **Encode at output, not at input** — encoded data in the DB causes problems if you ever need to use it elsewhere (CLI, mobile app). Sanitize on output, contextually.

---

## Server Configuration

### HTTP Response Headers
```
Content-Security-Policy: script-src 'self'           # only allow same-origin JS
X-Content-Type-Options: nosniff                       # prevent MIME-sniffing-based XSS
X-Frame-Options: DENY                                 # prevent clickjacking
Strict-Transport-Security: max-age=31536000           # force HTTPS
```

**CSP is the single highest-impact XSS hardening header.** A strict CSP (`script-src 'self'`, no `unsafe-inline`, no `unsafe-eval`) blocks ~all injected `<script>` payloads.

### Cookie Flags
```
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```
- `HttpOnly` — JS can't read it → defeats `document.cookie` exfil
- `Secure` — HTTPS-only transmission
- `SameSite=Strict` — not sent on cross-site requests → defeats CSRF + XSS-based CSRF

### Other Layers
- **HTTPS everywhere** — prevents MITM injection
- **WAF** (ModSecurity, Cloudflare, AWS WAF) — pattern-blocks common XSS payloads; bypassable but useful defense-in-depth
- **Framework defaults** — React JSX auto-escapes, Angular templates auto-escape, ASP.NET has built-in XSS protection. Don't fight them; use them.

---

## Defense Priority

| Layer | Stops what |
|-------|-----------|
| Output encoding (`htmlspecialchars`) | Most XSS at the rendering step — most effective |
| CSP `script-src 'self'` | Blocks injected `<script>` even if encoding fails |
| HttpOnly cookies | Prevents session theft even if XSS exists |
| DOMPurify (input sanitization) | Catches malicious HTML before it's stored |
| Input validation | Rejects malformed input early |
| WAF | Pattern-based blocking — last resort, bypassable |

---

## Exam Notes

- Output encoding (`htmlspecialchars` / `htmlentities`) is the canonical XSS fix on the back-end
- CSP `script-src 'self'` is the canonical defense-in-depth header — know what it does
- `HttpOnly` on session cookies stops the Section-8 cookie-theft pattern dead
- Never trust front-end validation alone — attacker can bypass with curl/Burp
- DOMPurify is the standard library for "I need to allow some HTML but not JS"
- The CPTS exam often asks "which defense stops which attack?" — memorize the priority table above
