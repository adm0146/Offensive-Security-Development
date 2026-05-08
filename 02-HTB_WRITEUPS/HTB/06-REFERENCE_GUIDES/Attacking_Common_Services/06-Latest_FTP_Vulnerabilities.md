# 06 — Latest FTP Vulnerabilities

## Overview

This section covers a real-world FTP vulnerability using the **Concept of Attacks** framework introduced in section 02. The vulnerability demonstrates how a path traversal flaw combined with improper HTTP method handling can lead to arbitrary file write — outside of any restricted directory.

---

## CVE-2022-22836 — CoreFTP Before Build 727

| Detail | Value |
|--------|-------|
| **Software** | CoreFTP Server (before build 727) |
| **CVE** | CVE-2022-22836 |
| **Type** | Authenticated Directory/Path Traversal + Arbitrary File Write |
| **Protocol Abuse** | HTTP PUT request (should only accept POST for uploads) |
| **Auth Required** | Yes — valid credentials needed |
| **Impact** | Write files anywhere on the filesystem outside the FTP root |

### Root Cause

CoreFTP's FTP service also handles HTTP requests. It:
1. Accepts `HTTP PUT` requests (intended for upload), but does **not** sanitize path input
2. Fails to restrict write operations to the authorized FTP directory
3. Allows `../` escape sequences to traverse outside the FTP root

---

## The Exploit

### Command
```bash
curl -k -X PUT -H "Host: <IP>" \
  --basic -u <username>:<password> \
  --data-binary "PoC." \
  --path-as-is https://<IP>/../../../../../../whoops
```

### Flag Breakdown

| Flag | Purpose |
|------|---------|
| `-k` | Skip SSL certificate verification |
| `-X PUT` | Use HTTP PUT method instead of POST |
| `-H "Host: <IP>"` | Set the Host header to target IP |
| `--basic -u user:pass` | HTTP Basic Authentication |
| `--data-binary "PoC."` | File content to write |
| `--path-as-is` | Prevent curl from normalizing `../` sequences |
| `https://<IP>/../../../../../../whoops` | Path traversal to write outside FTP root |

### Verify on Target
```cmd
C:\> type C:\whoops
PoC.
```

---

## Mapped to the Concept of Attacks

### Phase 1 — Directory Traversal

| Step | What Happens | Category |
|------|-------------|----------|
| 1 | User crafts an HTTP PUT request with `../` escape sequences in the path | **Source** |
| 2 | CoreFTP receives and processes the HTTP PUT request with the traversal path | **Process** |
| 3 | App checks auth against the FTP root only — traversal breaks out of that scope, bypassing restrictions | **Privileges** |
| 4 | Execution is handed to the write process, now operating outside the restricted directory | **Destination** |

### Phase 2 — Arbitrary File Write

| Step | What Happens | Category |
|------|-------------|----------|
| 5 | The filename (`whoops`) and content (`PoC.`) from the user become the new input | **Source** |
| 6 | The write process uses the specified filename and content | **Process** |
| 7 | All access restrictions were already bypassed in Phase 1 — write is approved | **Privileges** |
| 8 | File `whoops` is written with content `PoC.` at the traversed path on the local filesystem | **Destination** |

---

## Attack Impact

| Primitive | What an Attacker Can Do |
|-----------|------------------------|
| **Arbitrary file write** | Overwrite config files, drop webshells, plant SSH keys |
| **Write to web root** | If a web server is running, write a PHP/ASPX shell for RCE |
| **Overwrite startup scripts** | Persistence via modified boot/login scripts |
| **Drop cron jobs** | Write to `/etc/cron.d/` for scheduled execution |

---

## Key Takeaways

| Concept | Takeaway |
|---------|----------|
| HTTP method abuse | Services accepting unexpected HTTP methods (PUT vs POST) expand the attack surface |
| Path traversal + write = critical | Traversal alone is bad; combined with write access it becomes file system control |
| Auth doesn't mean safe | CVE-2022-22836 requires valid creds — misconfigured services with weak passwords are still fully exploitable |
| Concept of Attacks applies universally | The same Source → Process → Privileges → Destination pattern maps cleanly to this two-phase exploit |
| `--path-as-is` matters | Without it, curl normalizes `../` and the traversal fails — understanding your tools is essential |
