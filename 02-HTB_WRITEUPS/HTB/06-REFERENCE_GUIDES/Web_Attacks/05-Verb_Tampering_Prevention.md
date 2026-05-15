# Section 5 — Verb Tampering Prevention

> Theory only. No lab.

---

## The Two Sources of Verb Tampering

```
1. Server config limits auth to specific verbs       → use allowlist syntax (LimitExcept)
2. Code filters one source but uses a wider source   → consistent input handling
```

Both have framework-specific fixes.

---

## 1 — Server Configuration Fixes

### Apache — vulnerable
```apache
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>                       ← denylist: ONLY GET protected
        Require valid-user
    </Limit>
</Directory>
```

### Apache — fixed
```apache
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <LimitExcept POST>                ← allowlist: protect EVERYTHING except listed
        Require valid-user
    </LimitExcept>
</Directory>

# Or block everything without exceptions:
<Directory "/var/www/html/admin">
    Require valid-user                ← applies to ALL verbs
</Directory>
```

> `<Limit GET>` = "auth required for GET only" → vulnerable. `<LimitExcept GET>` = "auth required for everything except GET" → fixed.

### Tomcat / J2EE `web.xml` — vulnerable
```xml
<security-constraint>
  <web-resource-collection>
    <url-pattern>/admin/*</url-pattern>
    <http-method>GET</http-method>      <!-- ONLY GET constrained -->
  </web-resource-collection>
  <auth-constraint>
    <role-name>admin</role-name>
  </auth-constraint>
</security-constraint>
```

### Tomcat — fixed
```xml
<security-constraint>
  <web-resource-collection>
    <url-pattern>/admin/*</url-pattern>
    <!-- No http-method element = applies to ALL methods -->
  </web-resource-collection>
  <auth-constraint>
    <role-name>admin</role-name>
  </auth-constraint>
</security-constraint>

<!-- Or use <http-method-omission> for allowlist style -->
<security-constraint>
  <web-resource-collection>
    <url-pattern>/admin/*</url-pattern>
    <http-method-omission>GET</http-method-omission>
  </web-resource-collection>
  ...
</security-constraint>
```

### ASP.NET `web.config` — vulnerable
```xml
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin"/>
        <deny verbs="GET" users="*"/>
    </authorization>
</system.web>
```

### ASP.NET — fixed
```xml
<system.web>
    <authorization>
        <allow roles="admin"/>            <!-- No verbs attribute = all verbs -->
        <deny users="*"/>
    </authorization>
</system.web>
```

### nginx — usually safe by design
nginx doesn't have a per-method auth construct like Apache. Method restrictions happen in `location` blocks:
```nginx
location /admin/ {
    limit_except GET POST {
        deny all;                  # deny all verbs except GET/POST
    }
    auth_basic "Admin";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```
`limit_except` is allowlist by design — listed verbs are allowed, others denied.

### Disable HEAD when not needed
HEAD is the most common bypass verb because it runs the same handler as GET. If your app never needs HEAD:

```apache
# Apache
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^HEAD$
RewriteRule .* - [F]
```

```nginx
# nginx
if ($request_method = HEAD) {
    return 405;
}
```

---

## 2 — Code-Level Fixes

### PHP — vulnerable (filter on POST, action uses REQUEST)
```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9._-]/', $_POST['filename'])) {   // ← only POST
        system("touch " . $_REQUEST['filename']);                 // ← uses REQUEST
    }
}
```

### PHP — fixed (consistent source)
```php
$filename = $_REQUEST['filename'] ?? '';   // pick ONE source upfront
if ($filename === '') exit;

// Validate the value we'll actually use:
if (preg_match('/[^A-Za-z0-9._-]/', $filename)) {
    echo "Invalid filename"; exit;
}

// Use the validated value (argv array, not shell concatenation):
$out = [];
$ret = 0;
exec("touch " . escapeshellarg("/uploads/" . basename($filename)), $out, $ret);
```

### Python / Flask — vulnerable
```python
# Filter checks request.args (URL params)
if re.match(r'^[A-Za-z0-9._-]+$', request.args.get('filename', '')):
    os.system(f"touch {request.values.get('filename')}")    # request.values = args + form
```

### Python / Flask — fixed
```python
filename = request.values.get('filename', '')   # consistent source
if not re.match(r'^[A-Za-z0-9._-]+$', filename):
    abort(400)
subprocess.run(["touch", filename])    # argv array, no shell
```

### Node.js / Express — vulnerable
```javascript
if (/^[A-Za-z0-9._-]+$/.test(req.query.filename)) {   // checks URL
    exec(`touch ${req.body.filename}`);               // uses body
}
```

### Node.js — fixed
```javascript
const filename = req.query.filename || req.body.filename;   // consistent
if (!/^[A-Za-z0-9._-]+$/.test(filename)) {
    return res.status(400).send("Invalid");
}
execFile('touch', [filename]);   // argv array
```

---

## Where to Pull Input (Universal "Wide" Sources)

When you can't change the application logic, validate against the WIDEST possible source — better to over-validate than under-validate:

| Language | Wide source (covers GET + POST + others) |
|----------|------------------------------------------|
| PHP | `$_REQUEST['param']` |
| Java | `request.getParameter('param')` |
| ASP.NET | `Request['param']` (combined collection) |
| Express | `req.query.param \|\| req.body.param \|\| req.params.param` |
| Django | `request.GET.get('param') \|\| request.POST.get('param')` |
| Flask | `request.values.get('param')` |

Filter from these → action from these → no mismatch possible.

---

## Defense Priority Table

| Attack | Fix |
|--------|-----|
| Apache `<Limit GET>` auth bypass | `<LimitExcept>` or remove method restriction |
| Tomcat `<http-method>GET` auth bypass | Remove `<http-method>` (applies to all) |
| ASP.NET `verbs="GET"` auth bypass | Remove `verbs=` attribute |
| HEAD verb runs GET handler | Block HEAD globally OR use centralized middleware auth |
| `$_GET` filter / `$_REQUEST` sink mismatch | Validate from the SAME source the sink uses |
| Body filter / URL sink mismatch | Same principle — consistent source |

---

## Audit Heuristics

When reading code, flag every line that:
1. Uses `$_GET`, `$_POST`, `request.args`, `request.body` (specific source)
2. Uses `$_REQUEST`, `request.values`, `request.params` (combined source)
3. Where filter and sink use different ones from above

Combine with:
```bash
# Find inconsistent source usage in PHP
grep -rn '$_GET\|$_POST\|$_REQUEST' src/

# Find HTML5 forms with method= attribute — those are the assumed verbs
grep -rE 'method="(get|post|put|delete)"' templates/
```

If the audit finds `$_POST` filter + `$_REQUEST` action in the same function → fix it.

---

## Exam Notes

- `<LimitExcept>` is the canonical Apache fix — knows by name on CPTS exam
- `$_REQUEST` is the canonical wide-source — when in doubt, validate from it
- Disable HEAD if unused — kills the most common bypass verb
- Method-level routing in modern frameworks (Spring `@GetMapping` vs `@PostMapping`) prevents the vuln by design — if the app uses these decorators, the bug is much less likely
- Centralized auth middleware (e.g., Express `app.use(authMiddleware)`) runs on EVERY request regardless of verb — beats per-route or per-method auth checks
- Real-world fix priority: (1) centralize auth, (2) use allowlist syntax in config, (3) validate from consistent source in code
