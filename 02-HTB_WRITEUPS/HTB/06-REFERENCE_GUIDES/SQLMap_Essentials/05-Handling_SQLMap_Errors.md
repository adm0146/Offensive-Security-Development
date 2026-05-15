# Section 5 — Handling SQLMap Errors

> Theory only. No lab.

---

## Debugging Options

| Option | Purpose |
|--------|---------|
| `--parse-errors` | Print DBMS error messages inline as they occur |
| `-t /tmp/traffic.txt` | Save all raw HTTP request/response traffic to file |
| `-v 6` | Max verbosity — prints every request/response to terminal in real time |
| `--proxy=http://127.0.0.1:8080` | Route all traffic through Burp for manual inspection |

---

## When to Use Each

**`--parse-errors`** — add this first when sqlmap finds nothing. Database Management System (DBMS) errors reveal the query structure and confirm the parameter is reaching SQL. Example output:
```
[WARNING] parsed DBMS error message: 'SQLSTATE[42000]: Syntax error ... near '))"',),)(('
```

**`-t /tmp/traffic.txt`** — saves the full Hypertext Transfer Protocol (HTTP) conversation to disk. Use it when you need to study exactly what payloads were sent or replay a request manually.

**`-v 6`** — streams requests and responses live. Use this when the saved `-t` file is too large to dig through later. Verbosity levels:
```
0 = errors only
1 = default (info + warnings)
2 = debug
3 = payloads sent
4 = HTTP requests
5 = HTTP responses
6 = full HTTP traffic (requests + responses)
```

**`--proxy=http://127.0.0.1:8080`** — routes all traffic through Burp Suite. Use this when you want to intercept, modify, or replay sqlmap's exact requests. It is also useful for capturing session data to build request files for `-r`.

---

## Exam Notes

- When a run produces no results, add `--parse-errors` first — DBMS errors often reveal the exact query context needed to craft the right injection
- `-v 6` is noisy but definitive — if you can see the request going out and the response coming back, you know whether the issue is the payload or the target
- `--proxy` + Burp is the best way to understand what sqlmap is actually doing on a complex target
