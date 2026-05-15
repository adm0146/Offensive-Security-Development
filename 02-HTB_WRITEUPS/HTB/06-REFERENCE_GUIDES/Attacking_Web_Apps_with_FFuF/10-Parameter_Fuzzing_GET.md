# Section 10 — Parameter Fuzzing (GET)

> Fuzz the query string to find hidden/undocumented GET parameters accepted by a page.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Parameter accepted by admin.php | `user` |

Visiting `?user=key` returns "This method is deprecated." — the parameter exists but is deprecated. The real flag comes via POST (Section 11).

---

## How GET Parameter Fuzzing Works

Put `FUZZ` where the parameter name goes in the query string (Uniform Resource Locator):

```
http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key
```

ffuf tries every parameter name from the wordlist. If the response size changes, the server recognized that parameter.

---

## The Command

```bash
# Step 1: get the default response size
curl -s -o /dev/null -w "%{size_download}" \
  -H 'Host: admin.academy.htb' \
  "http://TARGET_IP:PORT/admin/admin.php"
# Returns: 798

# Step 2: fuzz GET params, filter that size
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u "http://TARGET_IP:PORT/admin/admin.php?FUZZ=key" \
  -H 'Host: admin.academy.htb' \
  -fs 798 \
  -t 100
# Returns: user
```
> Step 1 measures the "no parameter" response size. Step 2 fuzzes GET parameter names and filters out that size — any different size means the server recognized the parameter. `burp-parameter-names.txt` has ~6.7k common parameter names.

---

## Wordlist

```bash
~/SecLists/Discovery/Web-Content/burp-parameter-names.txt   # ~6.7k common param names
```
> This is a path, not a command. Use it as the wordlist in `-w`. It was compiled from real Burp Suite captures and covers the most common parameter names seen in web apps.

This is the first list to try for parameter fuzzing. It was built from real Burp Suite captures and covers the most common parameter names in web apps.

---

## GET vs POST

| | GET | POST |
|--|-----|------|
| Location | URL query string `?param=value` | Request body |
| FUZZ position | `?FUZZ=key` in `-u` | `-d 'FUZZ=key'` with `-X POST` |
| Visible in logs/history | Yes | No |
| Used for | Read operations, filters, lookups | Auth, data submission, sensitive ops |

---

## Exam Notes

- Always check the default response size first and filter with `-fs` — parameter fuzzing returns a hit for every recognized param, and most are noise
- A deprecated parameter is still a finding — it reveals parameter naming conventions and confirms the endpoint accepts named params
- `burp-parameter-names.txt` covers most common cases; if nothing hits, try `raft-medium-words.txt`
- After finding a GET param, test it with various values: `?user=admin`, `?user=1`, `?user=../etc/passwd`
