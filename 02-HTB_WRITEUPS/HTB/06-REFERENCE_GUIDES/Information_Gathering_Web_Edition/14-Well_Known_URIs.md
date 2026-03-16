# 14 — Well-Known URIs

> Standardized paths under `/.well-known/` that expose security policies, auth configs, and metadata — free structured intel.

---

## What Are Well-Known URIs?

Defined in **RFC 8615**, the `/.well-known/` directory is a standardized location in a website's root for hosting metadata, configuration files, and service information. The **IANA** maintains a registry of all registered URIs.

```bash
# Check for well-known URIs on any target
curl -s https://TARGET/.well-known/security.txt
curl -s https://TARGET/.well-known/openid-configuration
```

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

This is the most recon-rich well-known URI. It returns a JSON document mapping the entire auth infrastructure:

```bash
curl -s https://TARGET/.well-known/openid-configuration | jq .
```

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

---

## Key Takeaways

- **Always check `/.well-known/`** paths early in recon — it's structured, standardized intel
- **`openid-configuration`** is the richest target — maps the entire auth infrastructure in one request
- **`security.txt`** reveals the security team and disclosure process
- **IANA registry** has the full list — browse it for less common URIs that may be present
- **Each endpoint discovered** becomes a new attack surface to test
- **`jq`** is essential for parsing the JSON responses efficiently

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
