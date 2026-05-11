# Section 8 — Encoding / Decoding

> Understanding encoding layers is critical for web pentesting — cookies, tokens, and parameters are often encoded.
> The tools: Burp Decoder (Decoder tab) and ZAP Encoder/Decoder/Hash (Ctrl+E).

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Decode the multi-encoded string | `HTB{3nc0d1n6_n1nj4}` |

**The encoding chain (4× Base64 → URL encoded):**

```
Original string (Base64)
  → Base64 decode → Base64 string
  → Base64 decode → Base64 string  
  → Base64 decode → Base64 string
  → Base64 decode → %48%54%42%7b... (URL encoded)
  → URL decode    → HTB{3nc0d1n6_n1nj4}
```

**Quick decode in Python (works for any multi-layer encoding):**

```python
import base64, urllib.parse, html

s = "PASTE_ENCODED_STRING_HERE"

# Keep decoding until nothing changes
while True:
    # Try base64
    try:
        decoded = base64.b64decode(s).decode('utf-8')
        print(f"Base64: {decoded[:80]}")
        s = decoded
        continue
    except: pass
    
    # Try URL decode
    url_decoded = urllib.parse.unquote(s)
    if url_decoded != s:
        print(f"URL: {url_decoded[:80]}")
        s = url_decoded
        continue
    
    # Try HTML decode
    html_decoded = html.unescape(s)
    if html_decoded != s:
        print(f"HTML: {html_decoded[:80]}")
        s = html_decoded
        continue
    
    print(f"FINAL: {s}")
    break
```

---

## Why Encoding Matters

HTTP only safely transmits certain characters. Special characters must be encoded or they break the request structure:

| Character | Problem if raw | URL encoded form |
|-----------|----------------|-----------------|
| Space | Ends the request data | `%20` or `+` |
| `&` | Treated as parameter delimiter | `%26` |
| `#` | Treated as URL fragment | `%23` |
| `=` | Treated as key=value separator | `%3D` |
| `+` | Treated as space in URL | `%2B` |

**Rule:** When injecting payloads with special characters, always URL-encode them. Burp Repeater: select the text → `Ctrl+U` to encode.

---

## Burp Decoder

```
Decoder tab (or: Inspector panel in Proxy/Repeater)
```

**To decode:**
1. Paste the string in the top input field
2. Click "Decode as" → select the encoding type (Base64, URL, HTML, etc.)
3. Output appears below
4. You can chain: click "Decode as" again on the output pane to decode again

**To encode:**
1. Paste the plaintext
2. Click "Encode as" → select type
3. Copy the output

**Smart Decode button:** Tries to detect and decode the encoding automatically. Works for obvious cases.

**Burp Inspector (easier access):**
- Available directly in Proxy → Intercept and Repeater
- Click the Inspector panel on the right side
- Automatically shows URL-decoded and Base64-decoded versions of selected text

---

## ZAP Encoder/Decoder/Hash

```
Ctrl+E  (or Tools → Encoder/Decoder/Hash)
```

- Paste text in the input field
- ZAP shows the string decoded/encoded in all formats simultaneously
- Tabs: Encode | Decode | Hash
- "Add New Tab" → create custom tabs with only the encoders you care about

---

## Common Encoding Types — Quick Reference

| Type | Looks Like | When You See It | Tool Mode |
|------|-----------|-----------------|-----------|
| Base64 | `eyJ1c2VybmFtZSI6...` (ends in `=`) | Cookies, tokens, API responses | Decode as Base64 |
| URL encoding | `%48%54%42` or `Hello+World` | URL parameters, POST body | Decode as URL |
| HTML entities | `&lt;script&gt;` | Page source, reflected XSS output | Decode as HTML |
| Hex/ASCII | `48 54 42 7b` | Binary data, raw values | Decode as ASCII Hex |
| Double URL | `%2526` (% is itself encoded) | WAF bypass attempts | Decode URL twice |

---

## Practical Use Cases

**Cookie tampering:**
```
1. Find a base64-encoded cookie (looks like random gibberish ending in =)
2. Decode it → {"username":"guest","is_admin":false}
3. Change the values → {"username":"admin","is_admin":true}
4. Re-encode to base64
5. Replace the cookie in your next request
```

**Payload encoding for WAF bypass:**
```bash
# Encode your injection payload before sending:
# In Burp Repeater: type payload → Ctrl+U to URL-encode
# Or encode manually:
python3 -c "import urllib.parse; print(urllib.parse.quote(';cat /etc/passwd;'))"
# Output: %3Bcat%20%2Fetc%2Fpasswd%3B
```

---

## Exam Notes

- Burp keyboard shortcut: `Ctrl+U` = URL-encode selected text in Repeater (memorize this)
- Always check cookies for base64 encoding — most session tokens and JWT headers are base64
- "Smart Decode" in Burp Decoder is a good starting point when you don't know the encoding
- Multi-layer encoding (decode → decode → decode) is common in CTFs and real apps
- URL-encode your payloads before sending — spaces and `&` will break the request otherwise
- ZAP auto-URL-encodes request data internally before sending, even if you don't see it
