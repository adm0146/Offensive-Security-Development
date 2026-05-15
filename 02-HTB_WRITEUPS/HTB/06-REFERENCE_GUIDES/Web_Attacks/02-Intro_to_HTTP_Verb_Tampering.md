# Section 2 — Intro to HTTP Verb Tampering

> Theory only. No lab.

---

## The HTTP Verb Set

| Verb | Purpose |
|------|---------|
| `GET` | Retrieve resource — most common |
| `POST` | Submit data, create resource |
| `HEAD` | Same as GET but only returns headers (no response body) |
| `PUT` | Write data to specified location (upload/replace) |
| `DELETE` | Remove resource at specified location |
| `OPTIONS` | Discover what methods the server accepts (`Allow:` header) |
| `PATCH` | Partial update to existing resource |
| `TRACE` | Echo received request back (debugging — usually disabled) |
| `CONNECT` | Tunnel connection through proxy |

---

## Two Distinct Vulnerability Classes

### 1. Misconfigured Authentication (Server-Side)
The auth rule covers SOME verbs but not all. Different verb → no auth.

```apache
# Apache .htaccess
<Limit GET POST>
    Require valid-user
</Limit>
```
> `<Limit>` is a denylist — it only enforces the rule on the listed methods. Any other verb bypasses the auth check entirely. The fix is `<LimitExcept GET POST>` which enforces auth on every method except those listed.

```xml
<!-- J2EE web.xml — same denylist bug -->
<security-constraint>
    <web-resource-collection>
        <http-method>GET</http-method>
        <http-method>POST</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```
> The J2EE `<http-method>` denylist has the same problem — it only restricts the listed verbs. Send `DELETE` or `PUT` and the auth constraint is never evaluated.

### 2. Inconsistent Input Source Handling (Code-Level)
Application filters input from ONE source (e.g., `$_GET`) but USES input from BOTH sources (e.g., `$_REQUEST` covers GET + POST).

```php
// Filter only inspects GET
if (preg_match('/^[A-Za-z\s]+$/', $_GET["code"])) {
    // SQL uses $_REQUEST (includes POST!)
    $query = "SELECT * FROM ports WHERE code LIKE '%" . $_REQUEST["code"] . "%'";
}
```
> The regex only checks `$_GET["code"]`. If the attacker sends a GET request with a safe value AND a POST body with a SQL payload, `$_REQUEST["code"]` resolves to the POST value — the filter never sees it. This is the `$_REQUEST` input-source mismatch vulnerability.

Attacker sends GET with safe value (passes filter) AND POST with malicious payload → `$_REQUEST` resolves to the POST value → SQLi triggered.

---

## Why It's More Common Than You'd Think

Both bugs share a root cause: **developer assumed all clients use only the verbs documented in the form**. Browsers send only `GET`/`POST` from `<form>` tags by default. Attackers can use any verb via curl/Postman/Burp.

| Defensive assumption | Attack reality |
|---------------------|----------------|
| "Users will only POST to login.php" | Attacker sends HEAD → 200 OK, auth never runs |
| "We filtered $_GET, so URL-based injection is dead" | Attacker sends POST with payload → still flows through |
| "Only GET/POST are listed in our routes" | Server accepts any verb by default and routes the same handler |

---

## Recognition Signatures

| Server / framework | What to look for |
|--------------------|------------------|
| Apache + `.htaccess` | `<Limit ...>` directives without `Except` — denylist style |
| Apache config | `<Files>` blocks with method restriction |
| nginx | Less common — usually method check in app code |
| J2EE / Tomcat | `<security-constraint>` with `<http-method>` (denylist) |
| ASP.NET | `<deny>` on specific verbs in `<authorization>` |
| Node/Express | Route registered for `app.post(...)` but handler accessible via other methods |
| PHP `$_REQUEST` | Mixes GET + POST + COOKIE — classic mismatch sink |

---

## Detection Workflow

1. Identify a protected page / sensitive action
2. Confirm normal verb (`GET` or `POST`) returns 302/401/403
3. Probe with `OPTIONS` to see what server claims it accepts
4. Try all verbs: `GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `OPTIONS`, `PATCH`, `TRACE`
5. Compare response codes + sizes — any verb returning 200 = bypass
6. For code-level: send POST while filtered param is also in URL (or vice-versa)

```bash
# Quick verb sweep
for V in GET HEAD POST PUT DELETE OPTIONS PATCH TRACE; do
  echo -n "$V: "
  curl -sk -o /dev/null -w "%{http_code} %{size_download}\n" -X "$V" "http://TARGET/protected/"
done
```
> Sweeps all common HTTP methods against the target path and prints the response code and body size for each. Any method that returns 200 when others return 401/403 is a potential bypass. Replace `http://TARGET/protected/` with the actual protected endpoint.

Anything other than `301/302/401/403` on an unauthenticated request → potential bypass.

---

## Exam Notes

- **Misconfig variant** (Apache `<Limit>`) bypasses authentication — sends `HEAD` instead of `GET`
- **Code variant** (`$_REQUEST` mismatch) bypasses input filters — sends POST when filter only checks GET
- The Apache `<Limit>` vs `<LimitExcept>` distinction is the canonical test point — `<Limit>` is a DENYLIST, `<LimitExcept>` is an ALLOWLIST. Denylist is almost always wrong.
- `$_REQUEST` in PHP is the most famous offender — covers GET, POST, AND COOKIE
- `OPTIONS` is your reconnaissance verb — shows `Allow:` header listing supported methods
- HEAD usually triggers the same code path as GET but suppresses output — perfect for bypass when you don't need the response body
- For modern frameworks (Spring Boot, Express, FastAPI), method-level routing makes this less common — but legacy enterprise apps with Apache/Tomcat still have it
