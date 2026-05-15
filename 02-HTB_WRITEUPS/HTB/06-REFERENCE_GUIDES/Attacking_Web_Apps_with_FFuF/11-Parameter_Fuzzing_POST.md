# Section 11 — Parameter Fuzzing (POST)

> Fuzz the POST body to find hidden parameters — same idea as GET fuzzing but sent in the request body.

---

## Lab Answer

No lab question in this section. Key finding: admin.php accepts a POST parameter named `id` (returns "Invalid id!" — correct param, wrong value). Value fuzzing is Section 12.

---

## The Command

```bash
# Step 1: get the default POST response size
curl -s -o /dev/null -w "%{size_download}" \
  -H 'Host: admin.academy.htb' \
  -X POST -d 'foo=key' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  "http://TARGET_IP:PORT/admin/admin.php"
# Returns: 798

# Step 2: fuzz POST param names, filter that size
ffuf -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u "http://TARGET_IP:PORT/admin/admin.php" \
  -H 'Host: admin.academy.htb' \
  -X POST -d 'FUZZ=key' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -fs 798 \
  -t 100
# Returns: id, user
```
> Same two-step workflow as GET fuzzing. The difference: `-X POST` switches the method and `-d 'FUZZ=key'` puts `FUZZ` in the request body. The `Content-Type` header is required for PHP to parse the form data.

---

## Key Differences from GET Fuzzing

| | GET | POST |
|--|-----|------|
| FUZZ position | `?FUZZ=key` in the URL (`-u`) | `FUZZ=key` in body (`-d`) |
| Method flag | none needed (default GET) | `-X POST` |
| Content-Type | not needed | `-H 'Content-Type: application/x-www-form-urlencoded'` |
| Visible in URL | Yes | No |

**PHP requires** the `application/x-www-form-urlencoded` header to parse POST body data. Always set it when fuzzing PHP endpoints or the server won't see the parameter at all.

---

## Verifying a Hit with curl

```bash
curl -s \
  -H 'Host: admin.academy.htb' \
  -X POST -d 'id=key' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  "http://TARGET_IP:PORT/admin/admin.php"

# Response: "Invalid id!"  ← parameter accepted, value wrong → fuzz the value next
```
> Manually verify a hit from ffuf by sending the found parameter with curl. "Invalid id!" means the parameter name is correct. The server processes it but rejects the value — move to value fuzzing next.

"Invalid id!" means the parameter name is correct but the value is wrong. Move on to value fuzzing (Section 12).

---

## Exam Notes

- Always set `Content-Type: application/x-www-form-urlencoded` for POST fuzzing against PHP
- Same `-fs` filter workflow as GET — probe a junk request first to get the baseline size
- "Invalid X!" response = correct parameter name found, wrong value — pivot to value fuzzing
- POST params are less likely to appear in logs/browser history — devs sometimes leave sensitive ones unprotected
- If a page accepts both GET and POST for the same param, POST version often has less validation
