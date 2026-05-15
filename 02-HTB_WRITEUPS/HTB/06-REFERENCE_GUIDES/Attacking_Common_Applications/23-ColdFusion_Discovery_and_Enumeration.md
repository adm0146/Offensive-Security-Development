# Section 23 — ColdFusion: Discovery & Enumeration

**ColdFusion** = Adobe's Java-based web app platform (Allaire 1995 → Macromedia 2001 → Adobe). Apps are written in **CFML** (ColdFusion Markup Language) — HTML-like tags (`<cfquery>`, `<cfloop>`, `<cfoutput>`). Pages use **`.cfm`** (templates) / **`.cfc`** (components) extensions. Old versions (8/9/10/11) are riddled with well-known, reliable RCE chains — a high-value find on any internal/external pentest.

---

## Default Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 80 | HTTP | Non-secure web traffic |
| 443 | HTTPS | TLS web traffic |
| 1935 | RPC | Client-server RPC |
| 25 | SMTP | Mail sending |
| 8500 | SSL | **Built-in server / app port (where you'll usually find it on labs)** |
| **5500** | **Server Monitor** | **Remote administration of the ColdFusion server** ← *§23 Q1 answer* |

> ⚠️ Ports are configurable at install time — treat this table as "where to look first," not gospel. On HTB boxes ColdFusion almost always answers on **8500** (the bundled JRun/standalone HTTP port), even though "8500" is labelled SSL in Adobe's default doc — it serves plain HTTP on labs.

> **§23 Q1 — "What ColdFusion protocol runs on port 5500?" → `Server Monitor`.** This is a *static* fact straight from the module's port table, **not** a runtime value — no need to touch the box to answer it (contrast with §22's eth0 IP, which had to be verified live). Know which questions are knowledge-recall vs. instance-specific.

---

## Enumeration — fingerprinting ColdFusion

| Method | What to look for |
|--------|------------------|
| **Port scan** | 8500 open (plus 80/443); Windows boxes often also show 135 + a high RPC port |
| **File extensions** | `.cfm` / `.cfc` URLs anywhere in the app |
| **HTTP headers** | `Server: JRun Web Server`, `Server: ColdFusion`, or `X-Powered-By: ColdFusion`; ColdFusion session cookies **`CFID` / `CFTOKEN`** |
| **Error messages** | Verbose CFML stack traces ("Invalid request of Application.cfm", `coldfusion.runtime.*`) leak the platform and often the version |
| **Default files/paths** | `/CFIDE/`, `/cfdocs/`, `/CFIDE/administrator/index.cfm`, `/CFIDE/adminapi/`, `/CFIDE/administrator/enter.cfm`, `install.cfm` |

**Version pinning:** the `/CFIDE/administrator/index.cfm` login page is the fastest tell. The page **title**, **copyright year**, and the look of the login form differ per release:

| Copyright string on admin login | Version |
|---|---|
| `Copyright (c) 1995-2006 Adobe` | **ColdFusion 8** |
| `1995-2009` | ColdFusion 9 |
| `1995-2012` | ColdFusion 10 |
| `1995-2016` / `2018` / `2021` | CF 2016 / 2018 / 2021 |

> Also try `/CFIDE/adminapi/administrator.cfc?wsdl` and `/CFIDE/componentutils/cfcexplorer.cfc` — `.cfc` components frequently dump the exact build/version in WSDL or error output. Wordlist for content discovery: `~/SecLists/Discovery/Web-Content/CMS/ColdFusion.fuzz.txt`.

---

## Lab Walkthrough — ACADEMY-ACA-ARCTIC (10.129.100.114)

> Note: Arctic is **slow** — responses can take up to ~90s. Set generous timeouts (`curl -m 90`, `nmap --host-timeout`) or you'll get false negatives.

### Step 1 — Port scan

```bash
nmap -p- -sC -Pn 10.129.100.114 --open --host-timeout 30m
# (fast triage used here)
for p in 135 8500 49154 80 443; do nc -zv -w3 10.129.100.114 $p; done
```
Result (verified live):
```
135/tcp   open  msrpc        <- Windows RPC
8500/tcp  open  fmtp         <- ColdFusion (JRun)
49154/tcp open  unknown      <- Windows dynamic RPC
80/443    filtered/timeout   <- no plain web; everything is on 8500
```
> `-p-` scans all 65535 ports (ColdFusion's 8500 is non-standard and a top-1000 scan misses it); `-Pn` skips host discovery (HTB blocks ICMP); `--open` hides closed/filtered noise. Three ports, web on **8500** → classic ColdFusion footprint.

### Step 2 — Confirm ColdFusion on 8500

```bash
curl -s -m 90 -i http://10.129.100.114:8500/
```
Verified output — directory listing, **`CFIDE/`** and **`cfdocs/`** present:
```
Server: JRun Web Server
Index of /  →  CFIDE/   dir   03/22/17
              cfdocs/  dir   03/22/17
```
> Two signals at once: the **`Server: JRun Web Server`** header (JRun = ColdFusion's bundled servlet container) and the default **`CFIDE`/`cfdocs`** directories. Directory listing being enabled is itself a misconfiguration worth noting in a report.

### Step 3 — Hit the Administrator + pin the version

```bash
curl -s -m 90 -i http://10.129.100.114:8500/CFIDE/administrator/index.cfm | grep -iE "title|Copyright|Set-Cookie"
```
Verified output:
```
Set-Cookie: CFID=...; CFTOKEN=...; CFAUTHORIZATION_cfadmin=...
<title>ColdFusion Administrator Login</title>
<meta name="Author" content="Copyright (c) 1995-2006 Adobe Software LLC...">
```
> `CFID`/`CFTOKEN`/`CFAUTHORIZATION_cfadmin` cookies confirm ColdFusion. The **`1995-2006`** copyright on the admin login page pins it to **ColdFusion 8** — exactly what the module states. Version in hand, pivot to known CF8 exploits.

### Step 4 — Known vulns for the identified version

ColdFusion 8 (Arctic) is the textbook target for:
- **CVE-2010-2861** — directory-traversal LFI in `administrator/index.cfm` (`locale` param) → read `password.properties` (admin SHA-1 hash). Path: `/CFIDE/administrator/enter.cfm?locale=../../../../../../../<path>%00en`
- **CVE-2009-2265** — authenticated FCKeditor / scheduled-task arbitrary file upload → CFM webshell → RCE
- Other historical CF CVEs to keep in mind:

| CVE | Class |
|-----|-------|
| CVE-2021-21087 | JSP upload restriction bypass |
| CVE-2020-24453 | AD integration misconfig |
| CVE-2020-24450 | Command injection |
| CVE-2020-24449 | Arbitrary file read |
| CVE-2019-15909 | Stored/Reflected XSS |

> Discovery/enumeration ends here — version identified, attack surface mapped. The exploitation (LFI → crack the SHA-1 admin hash → log in → scheduled-task/FCKeditor upload → shell) is the **next section ("Attacking ColdFusion")**.

---

## Exam Notes

- **CF lives on weird ports (8500)** — always `-p-`; a default nmap misses it.
- **Three fast fingerprints:** `Server: JRun`/`ColdFusion` header, `CFID`/`CFTOKEN` cookies, `/CFIDE/` + `/cfdocs/` dirs.
- **Pin the version from the admin login page's copyright year** before searching exploits — CF8 vs CF9+ have completely different exploit chains.
- **Port 5500 = Server Monitor; 8500 = built-in app server** — memorise the port/protocol table; it's pure recall on the exam.
- **Slow target:** raise every timeout; "no response" on Arctic often just means you didn't wait 90s.
- **Static vs runtime answers:** port/protocol questions are knowledge-recall — answer from the material, don't burn lab time verifying. (Runtime values like IPs/hashes *must* be pulled from the box — see §22.)
- Content-discovery wordlist: `~/SecLists/Discovery/Web-Content/CMS/ColdFusion.fuzz.txt`.

---

## Lab Walkthrough (quick steps)

```
1. nmap -p- -sC -Pn <ip> --open      -> 135, 8500, 49154
2. curl :8500/                        -> JRun header + CFIDE/ cfdocs/  (= ColdFusion)
3. curl :8500/CFIDE/administrator/index.cfm
                                       -> CFID/CFTOKEN cookies + "1995-2006" = ColdFusion 8
4. Map CVEs for CF8 (CVE-2010-2861 LFI, CVE-2009-2265 upload)
5. Q1: protocol on port 5500 -> Server Monitor  ✅  (static, from port table)
```

> Discovery is just: find 8500 → confirm it's ColdFusion (header/cookies/dirs) → pin the version (admin login copyright) → list that version's CVEs. Everything actionable flows from the version number.
