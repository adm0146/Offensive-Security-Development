# Section 11 — Jenkins: Discovery & Enumeration

Jenkins is an open-source CI/CD automation server written in Java. Runs in servlet containers (Tomcat or its own bundled Jetty). Common on internal networks — often runs as root/SYSTEM, making it a high-value target.

Key facts: 86k+ companies use it. Default port 8080 (or 8000). Port 5000 used for master-slave communication.

---

## Fingerprinting Jenkins

### Version — unauthenticated via HTTP header
```bash
curl -sI http://TARGET:8000/ | grep -i "x-jenkins\|server"
# X-Jenkins: 2.303.1
# Server: Jetty(9.4.42.v20210604)
```
The `X-Jenkins` header leaks version without authentication.

### Login page
Telltale login page at `/login?from=%2F`. Default install uses Jenkins' own user database.

### Common default credentials
- `admin:admin`
- `admin:password`
- No auth at all (anonymous access enabled — common on internal networks)

### Authentication modes
- Jenkins own user database (most common)
- LDAP
- Unix user database
- Delegate to servlet container
- No authentication

---

## Lab Answer

**Q1 — Version:** `2.303.1` (from `X-Jenkins` response header)
