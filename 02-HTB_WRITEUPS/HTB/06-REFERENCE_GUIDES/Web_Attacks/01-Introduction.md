# Section 1 — Introduction to Web Attacks

> Theory only. No lab.

---

## Module Scope

Three high-value web attacks not covered in other CPTS modules:

```
1. HTTP Verb Tampering   → authZ bypass + security control bypass via unexpected methods
2. IDOR                  → access other users' data via predictable object references
3. XXE                   → file read + SSRF + RCE via malicious XML
```

Each appears in real-world apps regularly and each has clear, exploitable patterns once you know the signatures.

---

## HTTP Verb Tampering — Quick Concept

Web apps often enforce authorization on `GET`/`POST` but forget about `PUT`/`DELETE`/`PATCH`/`HEAD`/`OPTIONS`/`TRACE`. If the back-end handler treats all verbs the same but the auth check only inspects `GET`, an attacker can use a different verb to bypass auth entirely.

```http
GET /admin/users  →  302 redirect to login
HEAD /admin/users →  200 OK (handler runs, auth check skipped)
```

Most common patterns:
- Apache `<LimitExcept GET POST>` directives — denylist verbs
- Java J2EE `<http-method>` constraints
- API endpoints that handle one method explicitly but accept any verb implicitly

---

## IDOR — Quick Concept

App exposes a direct reference (ID, filename, hash) to a resource without checking the requester owns/can access that resource.

```
/profile?id=1234           → your profile
/profile?id=1235           → ANOTHER user's profile (IDOR if no authZ check)

/files/document_42.pdf     → your file
/files/document_43.pdf     → other user's file
```

Common in:
- Profile / settings pages
- File downloads
- Order history / invoice pages
- API endpoints `/api/v1/users/{id}`
- Password reset flows that take user_id

---

## XXE — Quick Concept

XML parser processes `<!ENTITY>` declarations from attacker-controlled XML. With external entities (`SYSTEM`), the parser fetches local files, internal URLs, or attacker-controlled DTDs.

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<root>&xxe;</root>
```

Where XML processing happens:
- SOAP APIs
- DOCX / XLSX / SVG uploads
- RSS / Atom feed importers
- SAML / federated auth flows
- Old-style web service endpoints

Modern XML libraries disable external entities by default — vulnerability mostly in legacy code or libs configured for backward compatibility.

---

## Why These Three Together

All three share a common root cause: **the back-end trusts client-controlled data that should have been validated server-side**.

| Attack | What's trusted | What should happen |
|--------|----------------|-------------------|
| HTTP Verb Tampering | The HTTP method as auth-relevant context | All methods routed through one centralized auth check |
| IDOR | The object reference as proof of authorization | Server verifies requester owns the resource |
| XXE | XML structure (entities, DTD) | Parser configured to reject external entities |

Auditor pattern for all three: **"What does the server check vs. what does it not check?"**

---

## Module Roadmap

```
Sections 2-5    HTTP Verb Tampering — detection, bypass, prevention
Sections 6-12   IDOR — discovery, mass enumeration, request tampering, prevention
Sections 13-17  XXE — local file read, blind XXE, OOB exfil, RCE, prevention
Section 18      Skills assessment
```

---

## Exam Notes

- Web Attacks module sits alongside SQLi, XSS, File Inclusion, File Upload, Command Injection — it's the "other three" exam will test
- IDOR is the highest-frequency real-world finding of the three — appears in nearly every bug bounty engagement
- XXE is the highest-impact (file read → source → RCE chain) but increasingly rare in modern stacks
- HTTP Verb Tampering is niche — most often appears in legacy enterprise apps with Apache/.htaccess auth
- Common signal: any time the app exposes a numeric ID, filename, or hash in the URL/body → IDOR test
- Common signal: any time the app accepts XML uploads → XXE test
- Common signal: any time the app uses Apache `<LimitExcept>` or J2EE `<http-method>` → Verb Tampering test
