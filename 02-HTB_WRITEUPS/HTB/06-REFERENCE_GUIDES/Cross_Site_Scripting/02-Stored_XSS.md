# Section 2 — Stored XSS

---

## What Makes It Stored

The server saves user input (in a database, file, or cache) and later serves it to other users without sanitizing it. Every viewer triggers the payload. No special link needs to be shared.

---

## Detection Payloads

```html
<script>alert(window.origin)</script>   <!-- shows current origin -->
<script>alert(document.cookie)</script> <!-- shows session cookies -->
<script>print()</script>                <!-- triggers browser print dialog -->
<plaintext>                             <!-- HTML rendering stops; useful when alert() blocked -->
```
> Use `window.origin` instead of a hardcoded value. If input is rendered inside a cross-origin iframe, the alert shows which document is executing — not just where the form lives.



---

## Verify a Hit

1. Submit payload
2. View page source (`Ctrl+U`) — confirm the payload is rendered as raw HTML/JS (not encoded as `&lt;script&gt;`)
3. Refresh — if the payload persists across reloads + sessions, it's **stored** (not reflected)
4. The alert fires every visit, for every viewer

---

## Modern Browser Quirks

- Chrome and Firefox suppress `alert()` in some sandboxed contexts, such as cross-origin iframes or certain Content Security Policy (CSP) states.
- `<plaintext>` is the most reliable detection payload. It visually breaks page rendering so you know the browser processed it.
- `<svg onload=...>` and `<img src=x onerror=...>` are backup payload styles when `<script>` is filtered.

---

## Lab — Stored XSS (To-Do List app)

**Target:** `154.57.164.76:32103`

### Q1 — Get the flag by showing cookies instead of URL

The base detection payload was `<script>alert(window.origin)</script>`. Modify the JS to display `document.cookie`:

```html
<script>alert(document.cookie)</script>
```

Submit via the form, then reload. The browser executes the stored script and the alert shows the session cookie containing the flag.

### Capturing without a browser

The flag is delivered in the server's `Set-Cookie` response header:

```bash
curl -sk "http://154.57.164.76:32103/" -i | grep -i set-cookie
# Set-Cookie: cookie=HTB{570r3d_f0r_3v3ry0n3_70_533}
```
> Fetches the page silently (`-sk`) and prints headers (`-i`). Then `grep` isolates the `Set-Cookie` line. Swap the IP:port for the current lab target.

> The lab sets a flag cookie on every request; the XSS payload demonstrates how an attacker would have exfiltrated it from a real victim.

**Flag:** `HTB{570r3d_f0r_3v3ry0n3_70_533}`

---

## Exam Notes

- Stored XSS is the highest-severity XSS type — it hits every visitor automatically
- Two-step verification: (1) source shows raw payload, (2) it persists across reload
- `document.cookie` only sees non-`HttpOnly` cookies — production apps should flag session cookies `HttpOnly` to mitigate
- The flag-in-cookie pattern is common in HTB labs; check `Set-Cookie` headers before reaching for a real browser
- Removal: stored XSS isn't fixed by patching the app alone — also need to scrub the database/cache
