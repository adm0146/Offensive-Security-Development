# Section 6 — Intro to IDOR

> Theory only. No lab.

---

## What IDOR Is

Insecure Direct Object Reference = the app exposes a direct reference (ID, filename, hash, GUID) to a resource, and the back-end **fails to verify** the requester is authorized to access that resource.

```
/download.php?file_id=123      → your file
/download.php?file_id=124      → ANOTHER user's file (IDOR if no authZ check)
/api/users/456/profile          → another user's profile
/orders/INV-2024-00789.pdf      → another user's invoice
```

The direct reference alone isn't the bug — the missing authorization check is.

---

## The Real Vulnerability: Missing Access Control

Many apps "implement" access control by:
- Hiding admin pages from non-admin users in the UI
- Only listing files that belong to the current user
- Returning specific IDs in API responses based on user context

But the back-end accepts ANY value the client sends. If the user manually changes the ID in the URL/body/JSON, the back-end happily returns the requested resource — because there's no server-side check that "user X owns resource Y."

```
✗ Front-end only:  UI hides resources you don't own → bypass with curl
✗ ID obfuscation:  using GUIDs instead of integers → still leaks via shares, ref headers
✓ Server-side:     SELECT * FROM files WHERE id = ? AND owner = ?
```

The correct check ALWAYS happens server-side and ALWAYS verifies the relationship between requester and resource.

---

## Two Categories of IDOR

### IDOR Information Disclosure
Read another user's resource:
- Personal data (PII, addresses, phone, email)
- Financial data (CC numbers, bank info, orders)
- Files (uploads, exports, invoices)
- Private messages
- Account settings

### IDOR Insecure Function Calls
Perform an action on another user's resource OR call admin-only function:
- Change another user's password
- Delete another user's content
- Modify another user's profile
- Promote yourself to admin (via parameter tampering)
- Invoke admin-only API endpoints from a regular user account

---

## What Makes IDORs So Common

1. **Hard to detect automatically** — scanners can't determine "should user A see resource B?"
2. **Hard to build correctly** — every endpoint needs a per-resource authZ check
3. **Devs trust the front-end** — "the UI only shows the user's own ID" feels secure but isn't
4. **Microservices split responsibility** — service A trusts the user ID from service B without re-checking
5. **Legacy code** — old endpoints predate the auth framework

Even Facebook, Twitter, Instagram, GitHub have had public IDOR bugs in production.

---

## Direct Reference Patterns to Look For

| Pattern | Test |
|---------|------|
| Sequential integer IDs | `?id=1` → `?id=2`, `?id=3`, ... |
| GUIDs in URL | Try other GUIDs (leaks via referer, share links) |
| Filename patterns (`user_42.pdf`) | Try other user IDs |
| Hash-based references | Look up the algorithm — often reversible |
| Email/username in URL | `?email=other@example.com` |
| JSON body fields | `{"user_id": 1234}` — change to other IDs |
| Hidden form fields | `<input type="hidden" name="user_id" value="42">` |
| API endpoints `/users/{id}` | Path-based ID = trivially modifiable |
| Cookies with user data | `userid=42` cookie — replay with `userid=43` |
| JWT claims | Sub claim might be only authZ → spoof if signed with weak key |

---

## Auth vs AuthZ — The Critical Distinction

- **Authentication (authN)**: Are you who you say you are? (Login, session, JWT validation)
- **Authorization (authZ)**: Can you access THIS resource? (Per-resource permission check)

IDOR is an authZ failure. You're properly authenticated (you have a valid session), but the server doesn't check whether you're authorized to access the specific resource you requested.

---

## Why Hidden References Don't Help

Some devs try to "fix" IDOR by:
- Using GUIDs instead of integers — still guessable if shared via referer, share links, leaked logs
- Encrypting/encoding IDs in URL — encoding is not security; the encoded form is still a direct reference
- Hashing IDs client-side — server validates the hash but not the relationship
- Splitting IDs across multiple parameters — still controllable client-side

**The only fix is server-side authZ on every request.**

---

## Exam Notes

- IDOR is OWASP Top 10 — currently #1 under "Broken Access Control"
- Look for **any** numeric/predictable ID in URLs, bodies, cookies, JWT claims
- Two attack categories: **read** (info disclosure) and **write/invoke** (function call)
- "Information disclosure" + "function call" = the two question types CPTS exam asks about
- The fix is `WHERE resource_id = ? AND owner_id = current_user` in EVERY query that fetches resources — not UI hiding
- For real-world bug bounty: IDOR has high payout because impact is direct (data exfil/takeover) with no chaining required
- Distinct from BAC (Broken Access Control) at a conceptual level — IDOR is the most common BAC subtype
