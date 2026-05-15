# Web Attacks

HTB Academy module — three classes of web vulnerabilities frequently chained together: **HTTP Verb Tampering**, **IDOR**, and **XXE**. The skills assessment combines all three.

## Sections

| # | Title | Type | Flag / Answer |
|---|-------|------|---------------|
| [01](01-Introduction.md) | Introduction | Theory | — |
| [02](02-Intro_to_HTTP_Verb_Tampering.md) | Intro to HTTP Verb Tampering | Theory | — |
| [03](03-Bypassing_Basic_Authentication.md) | Bypassing Basic Authentication | Lab | `HTB{4lw4y5_c0v3r_4ll_v3rb5}` |
| [04](04-Bypassing_Security_Filters.md) | Bypassing Security Filters | Lab | `HTB{b3_v3rb_c0n51573n7}` |
| [05](05-Verb_Tampering_Prevention.md) | Verb Tampering Prevention | Theory | — |
| [06](06-Intro_to_IDOR.md) | Intro to IDOR | Theory | — |
| [07](07-Identifying_IDORs.md) | Identifying IDORs | Theory | — |
| [08](08-Mass_IDOR_Enumeration.md) | Mass IDOR Enumeration | Lab | `HTB{4ll_f1l35_4r3_m1n3}` |
| [09](09-Bypassing_Encoded_References.md) | Bypassing Encoded References | Lab | `HTB{h45h1n6_1d5_w0n7_570p_m3}` |
| [10](10-IDOR_in_Insecure_APIs.md) | IDOR in Insecure APIs | Lab | uuid: `eb4fe264c10eb7a528b047aa983a4829` |
| [11](11-Chaining_IDOR_Vulnerabilities.md) | Chaining IDOR Vulnerabilities | Lab | `HTB{1_4m_4n_1d0r_m4573r}` |
| [12](12-IDOR_Prevention.md) | IDOR Prevention | Theory | — |
| [13](13-Intro_to_XXE.md) | Intro to XXE | Theory | — |
| [14](14-Local_File_Disclosure.md) | Local File Disclosure | Lab | api_key: `UTM1NjM0MmRzJ2dmcTIzND0wMXJnZXdmc2RmCg` |
| [15](15-Advanced_File_Disclosure.md) | Advanced File Disclosure | Lab | `HTB{3rr0r5_c4n_l34k_d474}` |
| [16](16-Blind_Data_Exfiltration.md) | Blind Data Exfiltration | Lab | `HTB{1_d0n7_n33d_0u7pu7_70_3xf1l7r473_d474}` |
| [17](17-XXE_Prevention.md) | XXE Prevention | Theory | — |
| [18](18-Skills_Assessment.md) | Skills Assessment | Lab | `HTB{m4573r_w3b_4774ck3r}` |

**[00-EXAM_CHEATSHEET.md](00-EXAM_CHEATSHEET.md)** — fast-reference distillation of all three attack classes.

## Attack Class Summary

### HTTP Verb Tampering
Server-side auth/filters that only check **some** HTTP methods can be bypassed by sending a different verb. Two flavors:
1. **Apache `<Limit GET POST>`** — denies these verbs to non-authed users; other verbs (PUT, DELETE, PATCH, OPTIONS) bypass entirely
2. **Code-level input source mismatch** — auth check reads `$_POST`, action reads `$_REQUEST` → switching to PUT empties `$_POST` and bypasses the check while still carrying data via query string

### IDOR (Insecure Direct Object Reference)
Direct references to resources (IDs in URLs, body, cookies) without proper authorization checks. Two flavors:
1. **Information disclosure** — read another user's data
2. **Insecure function calls** — modify/delete other users' state, escalate privileges

Mass enumeration is the primary attack pattern. Even encoded/hashed references are exploitable when the encoding scheme is visible in the front-end JS.

### XXE (XML External Entity)
XML parsers that resolve `<!ENTITY x SYSTEM "URI">` references can be tricked into reading arbitrary files, making SSRF requests, or even achieving RCE. Three exploitation modes:
1. **Reflected** — file content returns in the response body
2. **Error-based** — file content leaks via parser error messages
3. **Blind OOB** — file content exfiltrated via callback URLs to attacker-controlled server

PHP source code requires `php://filter/convert.base64-encode/resource=...` because raw source contains XML metacharacters. CDATA wrapping via parameter entities works for any language.

## Skills Assessment Chain

The capstone exercise required combining all three classes:

```
1. GET IDOR on /api.php/token/{uid}     → leak reset tokens
2. Verb tampering on /reset.php          → bypass auth with PUT+querystring
3. Mass enumeration                      → identify admin (uid=52)
4. Take over admin via token reset       → log in as a.corrales
5. XXE on /addEvent.php (admin-only)    → read /flag.php source
```

**Flag:** `HTB{m4573r_w3b_4774ck3r}`

## Key Tools

| Tool | Use |
|------|-----|
| `curl` with `-X VERB` | Verb tampering probes |
| `ffuf` / `gobuster` | Endpoint discovery |
| `php -S 0.0.0.0:8000` | XXE OOB listener |
| `python3 -m http.server 8000` | DTD/payload host |
| [XXEinjector](https://github.com/enjoiz/XXEinjector) | Automated XXE exfiltration |
| Burp Suite | Interception, repeater for crafting payloads |
