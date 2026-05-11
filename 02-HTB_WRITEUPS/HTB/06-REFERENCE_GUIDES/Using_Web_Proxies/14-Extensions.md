# Section 14 — Extensions

> Burp BApp Store and ZAP Marketplace add community-built features to both tools. No lab question.

---

## Burp — BApp Store

```
Burp → Extensions tab → BApp Store sub-tab
Sort by Popularity to see the most useful ones first
```

Some extensions require **Jython** (Python for Burp) — install that first if an extension fails to load.

### Extensions Worth Installing

| Extension | What It Does | When to Use |
|-----------|-------------|-------------|
| **Active Scan++** | Adds more active scan checks (host header attacks, ESI, XML) | Before running active scans — more coverage |
| **Decoder Improved** | Better encoder/decoder with MD5, more formats, hex editor | When standard Decoder isn't enough |
| **Autorize** | Tests authorization/access control by replaying requests as lower-privilege users | Auth bypass testing |
| **CSRF Scanner** | Detects CSRF vulnerabilities automatically | Testing CSRF protections |
| **JS Link Finder** | Extracts URLs and endpoints from JavaScript files | Recon — finds hidden API endpoints |
| **Retire.JS** | Identifies outdated/vulnerable JavaScript libraries | CVE-based JS vuln detection |
| **Software Vulnerability Scanner** | Scans for known CVEs in detected software versions | Quick CVE check on fingerprinted tech |
| **Backslash Powered Scanner** | Tests for server-side injection using backslash probing | SSTI, path traversal discovery |
| **JSON Beautifier** | Auto-formats JSON responses in the Repeater/Proxy | Reading JSON API responses |
| **JWT Editor** | Decode, modify, and re-sign JWT tokens | JWT algorithm confusion, none attack |
| **Error Message Checks** | Flags verbose server error messages | Information disclosure findings |

---

## ZAP — Marketplace

```
ZAP toolbar → Manage Add-ons button (puzzle piece icon)
→ Marketplace tab
→ select add-ons → Install Selected
```

**Release** = stable | **Beta/Alpha** = may have issues

### Key Add-ons to Install

| Add-on | What It Adds | When to Use |
|--------|-------------|-------------|
| **FuzzDB Files** | Adds FuzzDB wordlists to the File Fuzzers | Directory discovery, parameter fuzzing |
| **FuzzDB Offensive** | Adds attack payloads (SQLi, XSS, command injection, etc.) | Finding injection vulnerabilities |
| **Technology Detection** | Fingerprints tech stack from responses | Recon, identifying CVE targets |
| **WSDL Scanner** | Enumerates SOAP/WSDL web services | API security testing |
| **Active Scanner Rules** | Additional passive/active check rules | More vulnerability coverage |
| **Community Scripts** | Community-written scripts for various checks | Ad-hoc testing |

**FuzzDB Offensive in ZAP Fuzzer:**
After installing, when adding payloads in the Fuzzer → File Fuzzers → you'll see a new `fuzzdb` folder:
```
fuzzdb → attack → os-cmd-execution → command_execution-unix.txt
fuzzdb → attack → sql-injection → ...
fuzzdb → attack → xss → ...
```
This gives you ready-made attack wordlists without needing to find external files.

---

## Key Extensions for the CPTS Exam

| Tool | Extension | Why It Matters |
|------|-----------|---------------|
| Burp | **Active Scan++** | Better active scan coverage without Pro |
| Burp | **JWT Editor** | JWT attacks (algorithm confusion, none) |
| Burp | **Autorize** | Access control / privilege escalation testing |
| Burp | **JS Link Finder** | Find hidden API endpoints in JS |
| ZAP | **FuzzDB Offensive** | Attack payloads built-in to ZAP Fuzzer |
| ZAP | **FuzzDB Files** | More wordlists for directory/content discovery |

---

## Exam Notes

- BApp Store is built into Burp under the Extensions tab — no download needed
- Some BApp extensions require Jython (Python interpreter for Java) — install from the Extensions → Options tab
- ZAP add-ons from Marketplace require a restart to take full effect
- **FuzzDB Offensive** in ZAP is the quickest way to add command injection, SQLi, and XSS payloads to the fuzzer without external files
- JWT Editor is critical for web auth attacks — covers alg:none, RS256→HS256 confusion, weak secret cracking
- Autorize is one of the most useful Burp extensions for real engagements — automates testing "can user A access user B's resources?"
- Pro-only BApp extensions are labeled — skip them in Community, they're for Pro users
