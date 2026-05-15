# 14 — Well-Known URIs

> Standardized paths under `/.well-known/` that expose security policies, auth configs, and metadata — free structured intel.

---

## What Are Well-Known URIs?

The `/.well-known/` directory is a standardized location in a website's root for hosting metadata, configuration files, and service information. It is defined in RFC 8615. The Internet Assigned Numbers Authority (IANA) maintains a registry of all registered well-known URIs.

```bash
# Check for well-known URIs on any target
curl -s https://TARGET/.well-known/security.txt
curl -s https://TARGET/.well-known/openid-configuration
```
> Fetches two common well-known URIs. `security.txt` returns the security contact and disclosure policy. `openid-configuration` returns a JSON document mapping the entire authentication infrastructure. Replace TARGET with your IP or domain. Run both on every target.

---

## Key Well-Known URIs for Recon

| URI | What It Contains | Recon Value |
|---|---|---|
| `security.txt` | Security contact info, PGP keys, disclosure policy | Identifies security team, reporting process, sometimes scope |
| `openid-configuration` | OAuth/OIDC endpoints, supported auth methods, signing algorithms | Maps auth infrastructure — authorization, token, userinfo endpoints |
| `change-password` | Redirects to password change page | Confirms auth system exists, identifies password reset flow |
| `assetlinks.json` | Digital asset ownership verification (apps linked to domain) | Reveals associated mobile apps and services |
| `mta-sts.txt` | SMTP MTA Strict Transport Security policy | Email security posture — enforced TLS for mail |

---

## OpenID Configuration — Deep Dive

This is the richest well-known URI for recon. It returns a JSON document that maps the entire authentication infrastructure:

```bash
curl -s https://TARGET/.well-known/openid-configuration | jq .
```
> Fetches the OpenID Connect (OIDC) discovery document and pretty-prints it with `jq`. The JSON response maps every authentication endpoint — authorization, token, userinfo, and the JSON Web Key Set (JWKS). Each endpoint is a potential attack surface.

### Example Response

```json
{
  "issuer": "https://example.com",
  "authorization_endpoint": "https://example.com/oauth2/authorize",
  "token_endpoint": "https://example.com/oauth2/token",
  "userinfo_endpoint": "https://example.com/oauth2/userinfo",
  "jwks_uri": "https://example.com/oauth2/jwks",
  "response_types_supported": ["code", "token", "id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"]
}
```

### What Each Field Reveals

| Field | What It Is | What To Do With It |
|---|---|---|
| `authorization_endpoint` | Where users authorize | Test for open redirect, parameter tampering |
| `token_endpoint` | Where tokens are issued | Test for token leakage, improper grant types |
| `userinfo_endpoint` | Returns user profile data | Test for IDOR, unauthorized access |
| `jwks_uri` | Cryptographic keys used by the server | Check key strength, algorithm confusion attacks |
| `response_types_supported` | Auth flows available (code, token, id_token) | Identify implicit flow (less secure) if supported |
| `scopes_supported` | What data the auth system exposes | Map available user data (email, profile, etc.) |
| `id_token_signing_alg_values_supported` | Signing algorithms | Check for weak algorithms (e.g., `none`, `HS256` vs `RS256`) |

---

## Quick Recon Workflow

```bash
# 1. Check security.txt
curl -s https://TARGET/.well-known/security.txt

# 2. Check OpenID configuration
curl -s https://TARGET/.well-known/openid-configuration | jq .

# 3. Extract all endpoints from OpenID config
curl -s https://TARGET/.well-known/openid-configuration | jq -r 'to_entries[] | select(.value | type == "string" and startswith("http")) | .value'

# 4. Check for additional well-known URIs
curl -s https://TARGET/.well-known/assetlinks.json
curl -s https://TARGET/.well-known/mta-sts.txt
curl -s https://TARGET/.well-known/change-password
```
> Step 1 gets the security contact info. Step 2 gets and pretty-prints the full OpenID discovery document. Step 3 uses `jq` to extract every value that starts with `http` — pulling out all endpoint URLs at once without manual reading. Steps 4+ check additional well-known URIs that may reveal mobile app associations or email security policy. Replace TARGET throughout.

---

## Key Takeaways

- Always check `/.well-known/` paths early in recon. The information is structured and standardized.
- `openid-configuration` is the richest target — it maps the entire auth infrastructure in one request.
- `security.txt` reveals the security team and the responsible disclosure process.
- The IANA registry has the full list of registered well-known URIs — check it for less common paths that may be present on the target.
- Every endpoint you discover becomes a new attack surface to test.
- `jq` is essential for parsing the JSON responses efficiently.

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
