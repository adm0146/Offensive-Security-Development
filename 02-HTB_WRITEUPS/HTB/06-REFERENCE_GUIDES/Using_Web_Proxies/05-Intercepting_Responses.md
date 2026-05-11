# Section 5 — Intercepting Responses

> Intercept the server's HTML response and edit it before the browser renders it.
> Use case: remove input restrictions, enable disabled fields, expose hidden elements.

---

## Why Intercept Responses

When the server sends HTML with restrictions baked in — like `type="number"`, `maxlength="3"`, `disabled`, or `hidden` — the browser enforces those restrictions. But you can intercept the response and change the HTML before the browser sees it. Then the browser renders your modified version with no restrictions.

This is cleaner than intercepting every request because you only need to modify the page once, then interact with it normally.

---

## Burp — Enable Response Interception

```
Proxy → Proxy Settings → Response Interception Rules
→ Check: "Intercept responses based on the following rules"
→ Ensure the default rule is enabled (intercepts all responses)
```

**Workflow:**
```
1. Turn request interception ON
2. Refresh the page (Ctrl+Shift+R for a full reload)
3. Forward the intercepted REQUEST (click Forward)
4. Burp now shows the intercepted RESPONSE
5. Edit the HTML before clicking Forward again
6. The browser renders your modified version
```

**Common edits to make in the response HTML:**

```html
<!-- Change number input to text (removes type=number restriction): -->
type="number"  →  type="text"

<!-- Increase max length: -->
maxlength="3"  →  maxlength="100"

<!-- Enable a disabled field: -->
<input disabled ...>  →  <input ...>

<!-- Show a hidden field: -->
<input type="hidden" ...>  →  <input type="text" ...>
```

**Auto-enable hidden/disabled fields without intercepting:**
```
Proxy → Proxy Settings → Response Modification Rules
→ Enable: "Unhide hidden form fields"
→ Enable: "Enable disabled form fields"
Burp applies these automatically to every response — no manual editing needed.
```

---

## ZAP — Intercept Responses

In ZAP, when you intercept a request and click **Step**, ZAP forwards the request AND automatically intercepts the response — you get both in sequence.

```
1. Enable interception (Ctrl+B)
2. Trigger the request (click Ping or refresh the page)
3. ZAP shows the intercepted REQUEST → click Step (not Continue)
4. ZAP now shows the intercepted RESPONSE
5. Edit the HTML the same way as in Burp
6. Click Continue
```

---

## ZAP HUD — Instant Field Enable (No Response Intercept Needed)

ZAP's HUD has a **Show/Enable** button (light bulb icon, third from top on left pane) that instantly enables any disabled or hidden form fields on the current page — no interception, no refresh needed.

```
1. Open ZAP's pre-configured browser with HUD enabled
2. Load the target page
3. Click the 💡 (Show/Enable) button in the HUD left pane
4. All disabled and hidden fields become visible and interactive immediately
```

**HUD also has a Comments button:**
- Adds visual indicators in the browser where HTML comments exist
- Hover over an indicator to read the comment — useful for finding developer notes, credentials, or hidden endpoints left in the source

---

## Exam Notes

- Response interception = modify HTML BEFORE browser renders it (removes client-side restrictions)
- Request interception = modify POST data BEFORE server receives it (bypasses validation)
- You need BOTH at different times — know which situation calls for which
- Burp response interception is OFF by default — you have to enable it in Proxy Settings
- ZAP's Step button automatically captures both the request AND response in sequence
- ZAP HUD Show/Enable button is the fastest way to enable disabled fields (no intercept needed)
- For persistent changes (auto-modify every response), use Burp's Response Modification Rules or ZAP's Auto-Repl feature — next section covers this
- Hidden fields often contain interesting values (tokens, IDs, flags, user roles) — always check them
