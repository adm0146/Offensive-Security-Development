# Section 12 — IDOR Prevention

> Theory only. No lab.

---

## Defense Hierarchy

```
1. Object-level access control (RBAC)  ← the only real fix
2. Strong, unguessable references      ← reduces enumeration ease
3. Server-side identity binding        ← session tied to authZ context
4. Never trust client-side state       ← role/permission must come from server
```

Reference obfuscation alone is **not** a defense. It just slows discovery. The fix is server-side checks on every resource access.

---

## 1 — Object-Level Access Control

Every request that fetches a resource should verify:
- **Authentication**: requester has valid session
- **Authorization**: requester is allowed to access THIS specific resource

```javascript
// Firebase-style rule — the resource ID must match the user's identity
match /api/profile/{userId} {
    allow read, write: if user.isAuth == true
        && (user.uid == userId || user.roles == 'admin');
}
```

The check has two parts:
- `user.uid == userId` — owner can access their own data
- `user.roles == 'admin'` — admin role bypass

Both pieces happen **server-side using session-derived identity**, NOT from the request body.

### SQL equivalent
```sql
-- Bad — fetches ANY profile by id
SELECT * FROM profiles WHERE id = :id;

-- Good — owner-bound check baked into the query
SELECT * FROM profiles
WHERE id = :id
  AND (owner_id = :session_user_id OR :session_user_role = 'admin');
```

### PHP equivalent
```php
$row = $db->fetch("SELECT * FROM profiles WHERE id = ? AND owner_id = ?",
                   [$_GET['id'], $_SESSION['uid']]);
if (!$row) {
    http_response_code(404);   // or 403
    exit;
}
```

The KEY change: `owner_id = ?` filter using `$_SESSION['uid']` (server-derived) — NOT `$_REQUEST['user_id']` (client-controllable).

---

## 2 — RBAC (Role-Based Access Control)

RBAC is the framework that scales authZ across an application. Three concepts:

- **Users** — individual accounts
- **Roles** — sets of permissions (e.g., `viewer`, `editor`, `admin`)
- **Permissions** — fine-grained actions (e.g., `read:profile`, `write:billing`)

Users get assigned roles; roles map to permissions; resources check permissions.

```python
# Pseudo-Python
class Permission(Enum):
    READ_PROFILE = "read:profile"
    WRITE_PROFILE = "write:profile"
    DELETE_USER = "delete:user"

ROLE_PERMISSIONS = {
    "user":  {READ_PROFILE, WRITE_PROFILE},
    "admin": {READ_PROFILE, WRITE_PROFILE, DELETE_USER},
}

def authorize(user, action, resource):
    if action == Permission.WRITE_PROFILE:
        return resource.owner_id == user.id or user.role == "admin"
    return Permission(action) in ROLE_PERMISSIONS[user.role]
```

### Centralize the check
Don't sprinkle authZ logic across every controller. Use middleware:

```javascript
// Express middleware
app.put('/api/profile/:id', requireAuth, authorize('profile', 'write'), (req, res) => {
    // by here, authorization has been verified
});
```

Centralization means:
- One place to audit
- Hard to forget on new endpoints (failing to add middleware = endpoint won't work, not "endpoint works without auth")
- Logging happens automatically

---

## 3 — Server-Derived Identity

Never trust client-supplied identity claims:

```
✗ Bad:  PUT /api/profile/42 + body has {"uid": 42}
        — server uses body uid to determine owner

✓ Good: PUT /api/profile/42
        — server compares path :id against $_SESSION['uid']
        — body is just the new values
```

The session ID (or JWT) is the only thing tying a request to an identity. Validate that ALL operations on `/api/profile/42` are by the user whose session has uid=42 (or by an admin).

### JWT pitfalls
```
✗ Bad: JWT contains role; server trusts the role claim directly
✓ Good: JWT only identifies the user; server looks up role from DB on every request
```

Why: stolen tokens can be modified if signing is weak. Server-side role lookup is the source of truth.

---

## 4 — Strong Object References

Even with proper authZ, predictable references make enumeration easier and leak information:
- "User ID 1024" tells you there are at least 1023 other users
- "Invoice ID 100" tells you the company billed 99 customers before you

Use **UUID v4** (random) for primary references:

```
?id=89c9b29b-d19f-4515-b2dd-abb6e693eb20   # UUIDv4 — unguessable

vs.

?id=42                                       # sequential — leaks scale
```

```php
// Generate UUID v4 in PHP
$uuid = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
    mt_rand(0, 0xffff), mt_rand(0, 0xffff),
    mt_rand(0, 0xffff),
    mt_rand(0, 0x0fff) | 0x4000,
    mt_rand(0, 0x3fff) | 0x8000,
    mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
);
```

Or use the database's native UUID type (PostgreSQL `uuid_generate_v4()`, MySQL `UUID()`).

### UUIDs Don't Replace AuthZ
A UUID is hard to guess but not secret. It leaks via:
- Share URLs
- Referer headers
- Browser history
- Cache logs
- Error messages

**UUIDs + missing authZ = still IDOR.** UUIDs reduce *automated enumeration* but don't fix *broken access control*.

---

## 5 — Indirect References (Defense in Depth)

Instead of exposing the raw ID, map it through a per-session table:

```
Session table:
  session_id=abc | client_ref=1 → real_id=789 (user's invoice)
  session_id=abc | client_ref=2 → real_id=1004 (user's other invoice)
```

The client only sees `client_ref=1` and `client_ref=2` (which are session-scoped). They can't enumerate to access invoice 790 because that ID is never exposed to them.

Requires session storage but eliminates direct reference enumeration entirely.

---

## What NOT to Do

| Bad practice | Why it fails |
|--------------|--------------|
| Trust `role` from cookie/JSON body | Client can modify it |
| Hash IDs on the front-end | Hash function visible in JS |
| Use UUIDs WITHOUT server-side authZ | UUID leaks → IDOR still works |
| Check authZ only on GET (not PUT/DELETE) | Verb tampering / direct write attacks |
| Compare path ID to body ID only | Both are client-controlled |
| Use sequential IDs for "internal" admin pages | Admin pages get scraped by ex-employees, contractors |

---

## Defense Priority Table

| Attack | Fix |
|--------|-----|
| Mass enumeration via sequential IDs | UUID v4 + server-side authZ |
| GET IDOR leaking data | `WHERE id = ? AND owner_id = session_uid` |
| PUT IDOR overwriting other users | Same authZ check on every method |
| Role escalation via cookie/body | Server lookup of role from DB on every request |
| Encoded reference bypass | Always pair with authZ — encoding ≠ access control |
| API verb tampering on resources | Centralized middleware on all routes |

---

## Audit Heuristics

For every endpoint that accepts an ID:
1. Trace where the ID comes from (path, body, query, cookie)
2. Find where the ID is used (DB query, file lookup)
3. Is there a server-side check `id_belongs_to_session_user OR session_user_is_admin`?
4. If not — IDOR.

Quick search:
```bash
# PHP audit — find endpoints that fetch by user-controlled ID
grep -rE 'WHERE.*id.*\$_(GET|POST|REQUEST)' --include='*.php' src/
grep -rE 'fetch.*\$_(GET|POST|REQUEST)\[.id' --include='*.php' src/
```

---

## Exam Notes

- **AuthZ is the only real fix** — encoding, hashing, UUIDs are obfuscation
- The RBAC fragment from the section (`user.uid == userId || user.roles == 'admin'`) is the **canonical** authZ pattern — memorize the shape
- Server-side identity (`$_SESSION['uid']`) vs client-supplied identity (`$_REQUEST['uid']`) — the difference determines whether IDOR exists
- Centralized middleware > per-endpoint checks — saves you from forgetting one
- For exam: "How would you fix this IDOR?" → "Add a server-side check that the resource owner matches the authenticated session user, OR the user has the required role"
- UUIDs prevent **automated** enumeration but not **targeted** exploitation when references leak
- The role in a JWT claim is fine for performance — but on sensitive operations, look up the role fresh from the database
