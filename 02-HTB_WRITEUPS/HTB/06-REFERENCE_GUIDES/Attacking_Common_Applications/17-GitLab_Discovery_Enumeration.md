# Section 17 — GitLab: Discovery & Enumeration

GitLab is a self-hosted Git repository platform. Often found on internal networks. Even without exploiting vulnerabilities, repositories frequently contain hardcoded credentials, API keys, SSH keys, and infrastructure details.

Default setup: public registration enabled, no email domain restriction, 2FA disabled.

---

## Fingerprinting

### Identify GitLab
- URL redirects to `/users/sign_in` → GitLab login page with logo
- Common ports: 80, 443, 8080, 8081

### Get version (requires login)
```bash
# Fastest — unauthenticated API leak in older versions
curl -s http://TARGET/api/v4/version
# {"version":"13.10.2","revision":"7efd19e3716"}

# Authenticated via help page
curl -s -b cookies.txt http://TARGET/help | grep -oP 'GitLab [0-9]+\.[0-9]+\.[0-9]+'
```

---

## Unauthenticated Enumeration

### Browse public projects
```bash
curl -s http://TARGET/explore/projects
# or directly via API
curl -s "http://TARGET/api/v4/projects?visibility=public&per_page=100" \
  | python3 -c "import sys,json; [print(p['id'], p['path_with_namespace']) for p in json.load(sys.stdin)]"
```

### Username enumeration via registration
```bash
# If username exists → "Username is already taken"
# If email exists → "Email has already been taken"
curl -s -X POST "http://TARGET/users" \
  -d "user[username]=root&user[email]=test@test.com&user[password]=Pass1234!"
```

---

## Authenticated Enumeration

### Register account (if open registration)
```bash
# 1. Get CSRF token
TOKEN=$(curl -s -c /tmp/gl.txt "http://TARGET/users/sign_up" \
  | grep -oP 'authenticity_token[^>]+value="\K[^"]+' | head -1)

# 2. Register
curl -s -c /tmp/gl.txt -b /tmp/gl.txt -X POST "http://TARGET/users" \
  -d "authenticity_token=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$TOKEN'))")&user[first_name]=hacker&user[last_name]=hacker&user[username]=hacker1337&user[email]=hacker1337%40gmail.com&user[password]=Welcome1234!" \
  -o /dev/null -L

# 3. Login (same CSRF flow)
LOGIN_TOKEN=$(curl -s -c /tmp/gl2.txt "http://TARGET/users/sign_in" \
  | grep -oP 'authenticity_token[^>]+value="\K[^"]+' | head -1)
curl -s -c /tmp/gl2.txt -b /tmp/gl2.txt -X POST "http://TARGET/users/sign_in" \
  -d "authenticity_token=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$LOGIN_TOKEN'))")&user[login]=hacker1337&user[password]=Welcome1234!" \
  -o /dev/null -L
```

### List all accessible projects via API
```bash
curl -s -b /tmp/gl2.txt "http://TARGET/api/v4/projects?membership=false&per_page=100" \
  | python3 -c "
import sys,json
for p in json.load(sys.stdin):
    print(p['id'], p['path_with_namespace'], p.get('visibility',''))
"
```

### List all files in a project (recursively)
```bash
curl -s -b /tmp/gl2.txt \
  "http://TARGET/api/v4/projects/PROJECT_ID/repository/tree?recursive=true&per_page=100" \
  | python3 -c "
import sys,json
for f in json.load(sys.stdin):
    if f['type'] == 'blob': print(f['path'])
"
```

### Read a specific file
```bash
curl -s -b /tmp/gl2.txt \
  "http://TARGET/api/v4/projects/PROJECT_ID/repository/files/path%2Fto%2Ffile/raw?ref=master"
# URL-encode slashes in the path: / → %2F
```

### Search for secrets across repositories
```bash
# Via web search
curl -s -b /tmp/gl2.txt "http://TARGET/search?search=password&scope=blobs" \
  | grep -i "password\|secret\|key"

# High-value files to check in any repo
# .gitlab-ci.yml    — CI vars, MYSQL_ROOT_PASSWORD, secrets
# phpunit_*.xml     — DB connection strings with credentials
# config.php        — app credentials
# .env              — environment variables
# database.yml      — Rails DB config
```

---

## What to Look For in GitLab Repos

| File | What to extract |
|------|----------------|
| `.gitlab-ci.yml` | CI variables (MYSQL_ROOT_PASSWORD, API keys, env secrets) |
| `phpunit_pgsql.xml` / `phpunit_mysql.xml` | DB hostnames, usernames, passwords |
| `.env` | All environment variables |
| `config/*.yml` | Database URLs, API endpoints |
| `*.php`, `*.py`, `*.rb` | Hardcoded credentials, connection strings |
| SSH keys / `id_rsa` | Private keys for pivoting |

---

## Known Exploits

| Version | CVE | Type |
|---------|-----|------|
| 11.4.7 | CVE-2018-19571 + CVE-2018-19585 | SSRF + CRLF → RCE |
| 12.9.0 | CVE-2020-10977 | Arbitrary file read |
| 13.9.3 / 13.10.2 / 13.10.3 | CVE-2021-22205 | Pre-auth RCE (exiftool) |

Check version before trying exploits. CVE-2021-22205 is particularly severe — pre-auth RCE via image upload.

---

## Exam Notes

- Version: `GET /api/v4/version` (works unauth in some versions, or after login)
- Public repos visible at `/explore` without login
- Internal repos visible after registering (if open registration)
- Registration bypasses org email restriction in many default installs
- Username enumeration works even with sign-up disabled (browse to `/users/sign_up`)
- CI/CD files (`.gitlab-ci.yml`) often contain DB passwords as variables
- Search GitLab's built-in search: `/search?search=password&scope=blobs`

---

## Lab Walkthrough (`gitlab.inlanefreight.local:8081` → `10.129.99.86`)

**Q1 — GitLab version:**

```bash
curl -s -H "Host: gitlab.inlanefreight.local" \
  "http://10.129.99.86:8081/api/v4/version"
# {"version":"13.10.2","revision":"7efd19e3716"}
```
**Version:** `13.10.2`

**Q2 — PostgreSQL password in example project:**

```bash
# Register + login (see above)
# List projects → project 2 = root/inlanefreight-dev (public)
# File phpunit_pgsql.xml contains DB credentials:
curl -s -b /tmp/gl2.txt -H "Host: gitlab.inlanefreight.local" \
  "http://10.129.99.86:8081/api/v4/projects/2/repository/files/phpunit_pgsql.xml/raw?ref=master"
```

```xml
<var name="db_dsn" value="pgsql:dbname=hello_world_test;host=postgres"/>
<var name="db_username" value="postgres"/>
<var name="db_password" value="postgres"/>
```

**PostgreSQL password:** `postgres`

**Bonus — MySQL root password in .gitlab-ci.yml:**
```yaml
variables:
  MYSQL_DATABASE: hello_world_test
  MYSQL_ROOT_PASSWORD: mysql
```
