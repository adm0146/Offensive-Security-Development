# Section 13 — Splunk: Discovery & Enumeration

Splunk is a SIEM/log aggregation platform. Two attack-relevant deployment modes:

- **Enterprise** (licensed): Full auth, role-based access, admin default creds `admin:changeme`
- **Free** (trial expired or Community): No authentication at all — web UI and REST API both open

Default ports: `8000` (web UI), `8089` (REST API / management), `5000` (forwarder input)

---

## Fingerprinting Splunk

### Version via REST API (unauthenticated)
```bash
curl -sk https://TARGET:8089/services/server/info \
  | grep -oP 'version="[^"]+'
# version="8.2.2"
```

The REST API is always open — even in Enterprise mode, `/services/server/info` leaks version without auth.

### Web UI fingerprint
```bash
curl -sk https://TARGET:8000/en-US/account/login | grep -i "splunk\|version" | head -5
```

Telltale: Splunk login page at `/en-US/account/login`. Header includes `Server: Splunkd`.

### Check if auth is disabled (Free mode)
```bash
curl -sk https://TARGET:8089/services/authentication/users \
  -o /dev/null -w "%{http_code}\n"
# 200 = Free mode (no auth)
# 401 = Enterprise (requires credentials)
```

### Check license type
```bash
curl -sk "https://TARGET:8089/services/server/info?output_mode=json" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); [print(e['content'].get('license_labels','')) for e in d.get('entry',[])]"
# ['Splunk Free']  → no auth required
# ['Splunk Enterprise']  → credentials needed
```

---

## Authentication Modes

| Mode | Web UI | REST API | Notes |
|------|--------|----------|-------|
| Free (no trial) | No auth | No auth | Full access as SYSTEM/root |
| Enterprise | Login required | Basic auth | Default `admin:changeme` |
| LDAP/SSO | SSO redirect | API key | Less common |

---

## Exam Notes

- Always check port 8089 REST API first — it leaks version unauthenticated
- Free mode = instant full access, runs as SYSTEM (Windows) or root (Linux) — trivial RCE
- Web UI uses HTTPS on port 8000 (not HTTP)
- Version in `X-Splunk-Version` header or `/services/server/info` REST endpoint
- `isFree: true` in server info response = no auth needed

---

## Lab Answer (`10.129.201.50:8089`)

**Q1 — Splunk version:** `8.2.2`

```bash
curl -sk "https://10.129.201.50:8089/services/server/info" | grep -oP 'version="\K[^"]+'
# 8.2.2
```
