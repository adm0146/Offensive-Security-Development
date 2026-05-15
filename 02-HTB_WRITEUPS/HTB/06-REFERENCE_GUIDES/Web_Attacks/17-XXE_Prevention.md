# Section 17 — XXE Prevention

> Theory only. No lab.

XXE is unusual in that prevention is mostly **a library/config problem**, not a sanitization problem. Modern XML parsers default to safe behavior — bugs come from legacy code, explicit opt-ins, and forgotten upgrades.

---

## Defense Layers

```
1. Disable external entity resolution at the parser level   ← primary fix
2. Keep XML libraries patched and current
3. Disable verbose error output (kills error-based XXE)
4. Avoid XML where possible — prefer JSON/YAML
5. WAF + egress filtering                                   ← defense in depth
```

The single most effective control is disabling external entity loading in the parser configuration. Everything else is layered around that.

---

## 1 — Safe Parser Configuration (Per Language)

### PHP (libxml)
PHP 8+ defaults to safe (external entities disabled). Pre-8 code may have:
```php
libxml_disable_entity_loader(false);   // ENABLES external entities — DEPRECATED in PHP 8
```
This function is deprecated since PHP 8.0 specifically because it allowed unsafe enabling. Modern code should use:
```php
// PHP 8+: external entities disabled by default — do nothing
$dom = new DOMDocument();
$dom->loadXML($input);

// To be explicit:
$dom->loadXML($input, LIBXML_NONET | LIBXML_DTDLOAD ^ LIBXML_DTDLOAD);
```

**Avoid:** `LIBXML_NOENT` (resolves entities — enables XXE), `LIBXML_DTDLOAD` (loads external DTDs).

### Java
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```
For SAXParser, XMLReader, TransformerFactory, SchemaFactory, Validator — each has its own feature setter. OWASP cheat sheet covers all of them.

### .NET (XmlDocument / XmlReader)
.NET Framework 4.5.2+ defaults are safe. To force:
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;     // recommended
settings.XmlResolver = null;                          // no external resource fetching
```

### Python
```python
# defusedxml — safe drop-in replacement for stdlib xml
from defusedxml import ElementTree as ET
tree = ET.parse(file)
```
The stdlib `xml.etree.ElementTree` parser is mostly safe in Python 3.7.1+, but `defusedxml` is the recommended belt-and-suspenders solution.

### Node.js
Most Node XML libraries (`xml2js`, `fast-xml-parser`) don't process DTDs at all. If using `libxmljs`:
```javascript
const xml = libxmljs.parseXml(input, {
  noent: false,    // do NOT substitute entities
  dtdload: false,  // do NOT load external DTDs
  noblanks: true
});
```

### Ruby (Nokogiri)
```ruby
doc = Nokogiri::XML(input) do |config|
  config.strict.nonet.noent(false)
end
```

---

## 2 — Keep Libraries Patched

XXE bugs that survive into 2026 are usually:
- Apps stuck on legacy frameworks (PHP 5.x, .NET 3.5, Java 6)
- Internal apps that haven't been touched in years
- Library defaults changing between versions but the app pinning an old version
- Document processors (SVG renderers, PDF generators, DOCX parsers) shipping ancient XML stacks

Audit triggers:
- `composer.lock` / `package-lock.json` / `Gemfile.lock` with old major versions
- `<dependencyManagement>` pinning Apache Xerces < 2.12
- SOAP stacks (Apache CXF, Axis, JAX-WS old versions)
- Image processors (ImageMagick with SVG/MVG support, Inkscape headless)

---

## 3 — Disable Verbose Errors

Error-based XXE (Section 15) works because the server returns parser errors containing your smuggled file content. Production servers should never display raw stack traces:

```php
// PHP — production
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);
```

```java
// Java — Spring Boot
server.error.include-stacktrace=never
server.error.include-message=never
```

This isn't an XXE fix — it's a generic information disclosure fix that also closes error-based exfil. Pair with proper parser config.

---

## 4 — Lock Down Specific XML Features

When you must accept XML, disable these features individually:

| Feature | What it does | Should be |
|---------|--------------|-----------|
| External general entities | `<!ENTITY x SYSTEM "...">` resolved | Disabled |
| External parameter entities | `<!ENTITY % x SYSTEM "...">` resolved | Disabled |
| External DTD loading | `<!DOCTYPE x SYSTEM "...">` fetched | Disabled |
| Inline DTD declarations | `<!DOCTYPE x [...]>` | Disabled if not needed |
| XInclude | `<xi:include href="...">` | Disabled |
| Entity expansion | `&entity;` substitution | Disable, or set hard cap |

`disallow-doctype-decl=true` (Java/Xerces) is the nuclear option — if the app never needs DTDs, just forbid them entirely.

---

## 5 — Egress Filtering (Stops OOB)

Even with vulnerable XML parsing, a server that can't make outbound connections can't be exfiltrated from via OOB:
- Block all egress from web/app servers except specific allowlisted hosts
- Block DNS resolution from app tier to anything except internal resolvers
- Detect anomalous outbound traffic to unknown destinations

This won't stop direct file disclosure when the response reflects content — but it kills OOB and DNS exfil.

---

## 6 — Prefer JSON

The cleanest fix is to not accept XML at all. JSON parsers don't have entity expansion, external schemas, or DTDs. If the app architecture allows:
- Switch SOAP APIs to REST/JSON
- Convert XML config files to YAML or JSON
- Reject XML uploads in favor of plain JSON or typed forms

When XML is required (SAML, OAuth via XML, legacy clients), then strict parser config + library patching is the only path.

---

## 7 — WAF as Defense in Depth

WAF rules can match common XXE payload patterns:
```
<!DOCTYPE.*\[.*<!ENTITY
SYSTEM\s+["'](?:file|php|http|ftp|jar|expect|netdoc|data)://
%[a-zA-Z0-9_]+;
```

WAFs catch unsophisticated attacks but:
- Don't catch encoded variants (UTF-7, UTF-16BE)
- Don't catch when XML is wrapped in DOCX/SVG/SAML
- Can be bypassed by malformed-but-still-parseable variants
- Should never be the only defense

---

## Detection Signatures (Blue Team Side)

If you're hunting for XXE attempts in logs:

| Signal | Meaning |
|--------|---------|
| HTTP request body containing `<!DOCTYPE` + `<!ENTITY` | XXE attempt |
| HTTP request body containing `SYSTEM "file://` or `SYSTEM "php://` | File read attempt |
| Outbound HTTP from app tier to unusual IPs | Possible OOB exfil |
| DNS queries with long base64-looking labels from app tier | DNS exfil |
| Parser errors mentioning `parser error : Entity` in logs | Failed XXE attempt |
| Spike in 200 OK responses for `<email>` field containing newlines | Reflected file content |
| Application logs showing `php://filter/convert.base64-encode` | Source disclosure attempt |

---

## Common Anti-Patterns to Flag in Review

```php
// Bad — explicitly enables entities
libxml_disable_entity_loader(false);
$dom = new DOMDocument();
$dom->loadXML($_POST['xml']);

// Bad — LIBXML_NOENT substitutes entities (enables XXE)
$xml = simplexml_load_string($_POST['xml'], 'SimpleXMLElement', LIBXML_NOENT);

// Bad — DTDLOAD fetches external DTDs
$dom->loadXML($_POST['xml'], LIBXML_DTDLOAD);
```

```java
// Bad — default DocumentBuilderFactory on older JDKs
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xml)));
```

```python
# Bad — lxml with resolve_entities=True (default in older versions)
import lxml.etree as ET
parser = ET.XMLParser(resolve_entities=True, no_network=False)
```

---

## Audit Checklist

For an internal app review:
1. Identify all XML parsing surfaces (find: `loadXML`, `simplexml_load`, `parseXml`, `XmlReader.Create`, `DocumentBuilder`, `etree.parse`, `xml2js`)
2. Check each parser's configuration — entities resolved? DTDs allowed?
3. Identify all document processors (SVG, DOCX, XLSX, EPUB, SAML) — do they share a vulnerable XML stack?
4. Check error display in production
5. Check egress firewall rules
6. Look for hard-pinned legacy library versions in lockfiles
7. Confirm WAF rules but don't rely on them

---

## Exam Notes

- The fix is **parser configuration**, not input sanitization — XML libraries should disable external entities/DTDs by default
- `libxml_disable_entity_loader` is the PHP function to flag — deprecated in PHP 8.0 because its very existence implied unsafe configurations were possible
- Java has the longest list of feature flags to set — OWASP cheat sheet lists each parser type's required config
- `defusedxml` is the safe Python recommendation
- For high-stakes APIs: disable DTDs entirely (`disallow-doctype-decl=true` equivalent)
- Verbose error display enables error-based XXE — production must hide stack traces
- Egress filtering kills OOB exfiltration even if parser is vulnerable
- WAFs are layer 7 detection — not a replacement for proper parser config
- JSON has no equivalent vulnerability — switching format eliminates the class
- For real engagements: report XXE findings with BOTH the parser config fix AND the egress filter recommendation
