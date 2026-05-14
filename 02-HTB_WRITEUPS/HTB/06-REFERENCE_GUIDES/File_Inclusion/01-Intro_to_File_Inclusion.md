# Section 1 — Intro to File Inclusions

> Theory only. No lab.

---

## What File Inclusion Is

Web apps that load resources dynamically based on user input (`?page=about`, `?language=en`) can be coerced into loading **other files** when the path isn't sanitized. The classic pattern: a templating engine builds a page by including a partial whose name comes from a URL parameter — change the parameter, change the file the server reads (or executes).

Two outcomes possible:
- **Read** → source code disclosure, config files, credentials, SSH keys
- **Execute** → remote code execution

Severity depends on which function the dev used.

---

## Vulnerable Code Patterns (by language)

### PHP
```php
if (isset($_GET['language'])) {
    include($_GET['language']);   // ← directly user-controlled
}
```
Also vulnerable: `include_once()`, `require()`, `require_once()`, `file_get_contents()`, `fopen()`, `file()`.

### Node.js
```javascript
// fs.readFile — read only
fs.readFile(path.join(__dirname, req.query.language), ...)

// Express render — executes templates
app.get("/about/:language", (req, res) => {
    res.render(`/${req.params.language}/about.html`);
});
```

### Java (JSP)
```jsp
<jsp:include file="<%= request.getParameter('language') %>" />
<c:import url="<%= request.getParameter('language') %>" />
```

### .NET
```cs
Response.WriteFile(HttpContext.Request.Query['language']);
@Html.Partial(HttpContext.Request.Query['language']);
```

---

## Read vs Execute — The Critical Distinction

| Function | Read | Execute | Remote URL |
|----------|:----:|:-------:|:----------:|
| **PHP** | | | |
| `include()` / `include_once()` | ✅ | ✅ | ✅ (if `allow_url_include=On`) |
| `require()` / `require_once()` | ✅ | ✅ | ❌ |
| `file_get_contents()` | ✅ | ❌ | ✅ |
| `fopen()` / `file()` | ✅ | ❌ | ❌ |
| **Node.js** | | | |
| `fs.readFile()` | ✅ | ❌ | ❌ |
| `fs.sendFile()` | ✅ | ❌ | ❌ |
| `res.render()` | ✅ | ✅ | ❌ |
| **Java** | | | |
| `<jsp:include>` | ✅ | ❌ | ❌ |
| `<c:import>` | ✅ | ✅ | ✅ |
| **.NET** | | | |
| `@Html.Partial()` | ✅ | ❌ | ❌ |
| `@Html.RemotePartial()` | ✅ | ❌ | ✅ |
| `Response.WriteFile()` | ✅ | ❌ | ❌ |
| `<!--#include file="..."-->` | ✅ | ✅ | ✅ |

**Why this matters:**
- **Read-only** sink → LFI gets you source code, but the only path to RCE is indirect (log poisoning, session poisoning, PHP wrappers).
- **Execute** sink → drop a PHP/JSP/etc. payload, get RCE directly.
- **Remote URL support** → escalates LFI to RFI (Remote File Inclusion) — host the malicious file on your own server.

---

## Why It's Critical Even Without RCE

Even "just" file reads can compromise the whole app:
- `/etc/passwd` — user enumeration
- App config files — DB credentials, API keys, AWS secrets
- `~/.ssh/id_rsa` — direct SSH access
- App source code — find other vulnerabilities (SQLi, auth bypass, hardcoded keys)
- `.git/config` or `.env` — secrets that should never have been web-readable
- Apache/nginx access logs — set up for log poisoning → RCE chain

---

## How LFI Relates to Other Bugs

| Compared to | Difference |
|-------------|-----------|
| **Path Traversal** | LFI = include + execute/render. Path Traversal = just read raw bytes (e.g., from a download endpoint). LFI is the strictly stronger primitive. |
| **RFI** | RFI = include a remote URL. LFI = include a local path. RFI requires `allow_url_include=On` in PHP (off by default since 5.2). |
| **SSRF** | SSRF makes the server connect to a URL. RFI makes the server **execute** content from a URL. SSRF is read-only; RFI is RCE. |
| **Arbitrary File Read** | Same outcome as LFI-read, different vector (e.g., XXE, broken auth). LFI specifically uses an include/render sink. |

---

## Exam Notes

- File Inclusion is **the** web-app pivot — LFI gets you to source code; source code gets you to other bugs; one of those bugs gets you RCE
- Always check the sink type — `include()` is RCE-able with the right payload; `file_get_contents()` is read-only without a wrapper trick
- PHP `allow_url_include` was on by default in PHP < 5.2; disabled since. On modern hosts, expect LFI not RFI
- Don't underestimate "just" file disclosure — `/var/www/html/config.php` or `.env` regularly contains DA-equivalent secrets
- This module focuses on PHP + Linux. Most techniques apply to other stacks; the wrappers/payloads differ
