# Section 9 — XSS Prevention

> Theory only. No lab.

---

## Defense Layers

Every XSS (Cross-Site Scripting) bug has a **source** (user input) and a **sink** (where it is rendered). Defense applies controls at both ends of the stack.

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
> A basic email format check. Returns `true` if the input matches the pattern, `false` otherwise. Always pair front-end validation with the same check on the server side.

### Input Sanitization with DOMPurify
```html
<script src="dist/purify.min.js"></script>
<script>
const clean = DOMPurify.sanitize(userInput);
</script>
```
> Loads DOMPurify and sanitizes a string before placing it in the DOM. DOMPurify strips anything that could execute — `<script>` tags, event handlers, `javascript:` URIs, and more. It is the industry standard for client-side sanitization.

DOMPurify is the industry standard for client-side sanitization.

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
> Uses PHP's built-in `filter_var` to validate email format. Returns `false` if the input does not match a valid email pattern. Swap the filter constant for `FILTER_VALIDATE_IP`, `FILTER_VALIDATE_URL`, etc. as needed.

**Node.js:** Same regex pattern as front-end.

### Input Sanitization
**PHP:**
```php
$safe = addslashes($_GET['input']);   // escape special chars
```
> Adds backslashes before special characters. Useful as a basic safety net, but not a complete defense on its own. Prefer `htmlspecialchars` or `htmlentities` for HTML output.

**Node.js:**
```javascript
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(dirty);
```
> Sanitizes a string using DOMPurify on the server side (via Node). Strips all executable HTML before storing or rendering.

### Output Encoding (the most reliable defense)

Encode special characters as HTML entities. The browser shows them as text and never parses them as HTML.

**PHP:**
```php
echo htmlspecialchars($_GET['input']);   // < → &lt;
echo htmlentities($_GET['input']);        // broader char set
```
> `htmlspecialchars` converts `<`, `>`, `"`, `'`, and `&` to their HTML entity equivalents. `htmlentities` covers a broader set of characters. Use these on every output that includes user data.

**Node.js:**
```javascript
import { encode } from 'html-entities';
encode('<');   // '&lt;'
```
> Encodes characters to HTML entities in Node.js. The browser renders `&lt;` as the less-than sign rather than treating it as a tag.

> **Encode at output, not at input.** Encoded data stored in the database causes problems when used in other contexts (CLI, mobile apps). Sanitize at the point of rendering instead.

---

## Server Configuration

### HTTP Response Headers
```
Content-Security-Policy: script-src 'self'           # only allow same-origin JS
X-Content-Type-Options: nosniff                       # prevent MIME-sniffing-based XSS
X-Frame-Options: DENY                                 # prevent clickjacking
Strict-Transport-Security: max-age=31536000           # force HTTPS
```
> These headers are set by the server on every response. The Content Security Policy (CSP) header is the most important. A strict CSP with `script-src 'self'` blocks nearly all injected `<script>` payloads even if the XSS exists.

**CSP is the single highest-impact XSS hardening header.** A strict CSP (`script-src 'self'`, no `unsafe-inline`, no `unsafe-eval`) blocks nearly all injected `<script>` payloads.

### Cookie Flags
```
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```
> Three critical flags on every session cookie. `HttpOnly` prevents JavaScript from reading the cookie, which stops `document.cookie` theft. `Secure` ensures the cookie only travels over HTTPS. `SameSite=Strict` prevents the browser from sending the cookie on cross-site requests, defeating Cross-Site Request Forgery (CSRF).

- `HttpOnly` — JavaScript cannot read it — defeats `document.cookie` exfiltration
- `Secure` — HTTPS-only transmission
- `SameSite=Strict` — not sent on cross-site requests — defeats CSRF and XSS-based CSRF

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
