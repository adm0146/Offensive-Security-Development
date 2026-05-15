# Section 5 — XSS Discovery

---

## Automated Discovery

Web vulnerability scanners do two-phase XSS scanning:
- **Passive** — review rendered HTML/JS for risky sinks (DOM XSS)
- **Active** — send a payload list, diff the response against the original

| Tool | Type | Notes |
|------|------|-------|
| Nessus, Burp Pro, ZAP | Commercial/free | Full active+passive scanning |
| **XSStrike** | Open-source | Smart payload generation, WAF detection — best free option |
| Brute XSS | Open-source | Brute-force payload tester |
| XSSer | Open-source | Older, broader payload set |

### XSStrike Quick Run

```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike && pip install -r requirements.txt
python xsstrike.py -u "http://TARGET/index.php?task=test"
```
> Downloads XSStrike, installs dependencies, then runs it against a URL. Replace `task=test` with the parameter you want to test. XSStrike auto-generates context-aware payloads and reports which ones succeeded.

Output reports the vulnerable parameter, working payload, and confidence/efficiency scores.

---

## Manual Discovery

### Payload-list testing

Curated XSS lists on Kali:
```bash
ls ~/SecLists/Fuzzing/XSS/
# robot-friendly/  — one payload per line, ffuf/burp-friendly
# human-friendly/  — annotated for manual Burp testing
# Polyglots/        — multi-context single-string payloads
```
> Lists the XSS payload directories on Kali. Use `robot-friendly/` with ffuf or Burp Intruder. Use `Polyglots/` when you do not know the injection context.

Most payloads will not fire on a given target. They are written for specific contexts (after a quote, inside an attribute, around a filter). Manual brute-force is slow.

### Custom Python harness

For high-value targets: write a script that sends a unique marker through each input and each header, then diffs the rendered HTML, and reports where the marker appears unescaped.

```python
import requests
marker = "XSSPROBE_xY9k"
params = {"fullname": "x", "username": "x", "password": "x", "email": "x"}
for p in params:
    test = dict(params, **{p: marker})
    r = requests.get(URL, params=test)
    if marker in r.text:
        print(f"REFLECTS: {p}")
```
> Loops over each parameter, substituting the unique marker for one parameter at a time. If the marker appears in the response, that parameter reflects input back to the page.

### Code review (most reliable)

When source is available — trace inputs (`$_GET`, `$_POST`, `req.body`) through to sinks (`echo`, `innerHTML`, `document.write`). Skip the payload roulette entirely.

---

## Where XSS Hides

Not just form fields:

- URL query params (`?q=`, `?search=`)
- URL fragments (`#hash=`) — DOM-only
- Form bodies (POST)
- **HTTP headers reflected in the page**: `User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`
- File upload filenames
- Error messages (this section's lab — the `email` field echoed back in the validation error)
- Search result pages (the search term appearing in "0 results for X")

---

## Lab — Registration Form

**Target:** `154.57.164.79:30998`

Form has four inputs: `fullname`, `username`, `password`, `email`. The form does a GET, all fields required, with a client-side email regex check (`<>` blocked by regex in JS — server-side check is separate).

### Workflow

1. **Probe each parameter with a marker** — only the success page (`"Thank you for registering."`) returned for all fields → no obvious reflection
2. **Trigger the alternate response path** — submit with a deliberately invalid email:
   ```bash
   curl -sk -G "http://154.57.164.79:30998/" \
     --data-urlencode "fullname=John" \
     --data-urlencode "username=john" \
     --data-urlencode "password=secret123" \
     --data-urlencode "email=<script>alert(1)</script>"
   ```
> Submits the form with a deliberately invalid email value. The `--data-urlencode` flags encode special characters automatically. The `-G` flag sends everything as a GET request.
3. **Error page reflects the email value verbatim:**
   ```html
   <center><h1>'<script>alert(1)</script>' is an invalid email!</h1></center>
   ```
4. Reflection survives across refresh? No — it requires the URL parameters. **Reflected XSS.**

### Answers

**Q1 — Vulnerable parameter:** `email`
**Q2 — Type:** `reflected`

> Key lesson: the success path showed nothing, but the **error path** reflected user input. Always probe both happy-path and failure-path responses — many XSS bugs live in error messages.

---

## Exam Notes

- Run XSStrike first on any test URL — it generates context-aware payloads automatically
- Manual list-bashing is the slowest method — only useful when you have one tiny scope
- Headers (`User-Agent`, `Referer`) are often-overlooked XSS sinks — test them with `-H "User-Agent: <script>alert(1)</script>"`
- The client-side email regex on this lab blocks `<>` in the BROWSER — but the server still echoes the raw value back in the error. Client-side validation is never a security control.
- When asked "what type of XSS?" — check if the payload persists across refresh (stored), requires URL params (reflected), or never touches the server (DOM-based).
