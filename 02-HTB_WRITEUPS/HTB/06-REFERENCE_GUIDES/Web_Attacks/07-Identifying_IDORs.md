# Section 7 — Identifying IDORs

> Theory only. No lab.

---

## Where Object References Live

| Location | Example |
|----------|---------|
| URL query | `?uid=42`, `?file_id=123` |
| URL path | `/users/42/profile`, `/orders/789` |
| POST body | `user_id=42&action=view` |
| JSON body | `{"user_id": 42, "doc_id": 789}` |
| Cookie | `Cookie: userid=42` |
| HTTP header | `X-User-Id: 42`, `Authorization: Bearer ...` |
| Hidden form input | `<input type="hidden" name="uid" value="42">` |
| JWT claim | `{"sub": 42, "role": "user"}` |
| Filename in path | `/uploads/user_42.pdf` |
| Referrer / source page | URL parameters that leak via Referer header |

If user input ANYWHERE references a specific record, test for IDOR.

---

## Identification Methodology

### 1. Inventory all references
Browse the app normally — collect every URL/body that contains an ID. Burp's HTTP History is perfect for this.

### 2. Increment / decrement basic IDs
```
/profile?uid=42  → your profile
/profile?uid=41  → ?
/profile?uid=43  → ?
```
Look for: 200 with different data, 200 with the SAME structure but other user's content, 403 (auth check exists), or 404 (no IDOR).

### 3. Fuzz the range
```bash
ffuf -w <(seq 1 1000) -u "http://TARGET/profile?uid=FUZZ" \
     -mc 200 -ac -t 50

# Or with curl in a loop:
for i in {1..1000}; do
  resp=$(curl -sk -b "session=..." "http://TARGET/profile?uid=$i")
  if echo "$resp" | grep -q "username"; then
    echo "$i: $(echo "$resp" | grep -oP 'username":"[^"]+')"
  fi
done
```

### 4. Try different value styles
For each parameter, try:
- Negative (`-1`, `-42`)
- Zero (`0`)
- Very large (`999999999`)
- Special (`null`, `undefined`, `*`)
- Array-style (`?uid[]=42&uid[]=43`)
- Other user IDs you've harvested elsewhere

### 5. Cross-account compare
Register two users. Compare their HTTP requests — the references will differ. Then try using user A's references while authenticated as user B.

---

## Hidden / Unused Endpoints

The front-end JS often contains references to API endpoints not currently called. Search JS source for AJAX calls:

```bash
# Pull all JS files from the app, grep for $.ajax/fetch/axios calls
curl -sk "http://TARGET/app.js" | grep -E "url:|fetch\(|\\\$\\.ajax|axios\\."
```

Example finding:
```javascript
function changeUserPassword() {
    $.ajax({
        url: "change_password.php",
        type: "post",
        data: { uid: user.uid, password: user.password, is_admin: is_admin },
        ...
    });
}
```
Function exists in the front-end but is never called for non-admin users. Probe it directly via curl with your standard user session — if the back-end doesn't check role server-side, it's IDOR + privilege escalation.

---

## Decoding Obfuscated References

### Base64-style references
```
?filename=ZmlsZV8xMjMucGRm
```
`ZmlsZV8xMjMucGRm` decodes (base64) → `file_123.pdf`. Increment → `file_124.pdf` → re-encode → `ZmlsZV8xMjQucGRm` → submit.

```bash
echo "ZmlsZV8xMjMucGRm" | base64 -d         # file_123.pdf
echo -n "file_124.pdf" | base64              # ZmlsZV8xMjQucGRm
```

### Hashed references
```
?filename=c81e728d9d4c2f636f067f89cc14862c
```
That's MD5 of `2`. If the JS code shows what's hashed:
```javascript
data: { filename: CryptoJS.MD5('file_1.pdf').toString() }
```
You now know the algorithm + input pattern. Compute hashes for `file_2.pdf`, `file_3.pdf`, etc.

```bash
echo -n "file_2.pdf" | md5sum
# c81e728d9d4c2f636f067f89cc14862c   ← would be the new reference
```

### Hash format detection
```bash
echo -n "c81e728d9d4c2f636f067f89cc14862c" | wc -c   # 32 chars = MD5 / NTLM
# Other lengths: 40=SHA1, 64=SHA256, 28=base64-SHA1
```

When the hash input isn't obvious, try common patterns: filename, user_id, timestamp, concatenations.

---

## Cookie-Based IDORs

```
Cookie: userid=42; role=user
```
- Replay with `userid=43` — read another user's session?
- Change `role=user` to `role=admin` — privilege escalation?

JWT claims can be similar — if the JWT is unsigned or weakly signed:
```
{"sub":42,"role":"user","iat":...}
```
Tamper claims, re-sign with weak key (or strip signature on `alg=none` bug), replay.

---

## Compare User Roles

Register two accounts (`alice`, `bob`). For every action:
1. Capture Alice's HTTP request
2. Replay with Bob's session cookie
3. If it succeeds → Bob accessed Alice's resource → IDOR

Test:
- Read profile / settings
- Read files / uploads
- Read orders / billing
- Modify Alice's data using Bob's session
- Delete Alice's data using Bob's session
- Call admin functions (if you have an admin account, capture; replay as standard user)

---

## Sequential vs Non-Sequential IDs

| ID style | Strategy |
|----------|----------|
| Sequential integers (`1, 2, 3`) | Iterate range, exploit any 200 |
| GUIDs (`UUID v4`) | Look for leaks: shared URLs, email links, JS code, error messages |
| Hashes | Reverse algorithm from source (Section above) |
| Email/username | Try targeted accounts you know exist |
| Timestamps | Predict based on signup time + sample patterns |
| Encoded composites | Decode and analyze structure |

GUIDs aren't a perfect defense — they're hard to brute force but trivially leak via:
- Share URLs
- Referer headers
- Browser history
- Email attachments / notifications
- Public logs
- Error messages displaying the GUID

---

## Quick Workflow Summary

```
1. Browse normally → collect ALL request IDs
2. For each ID-bearing parameter:
   - Increment / decrement
   - Try negative, zero, very large
   - Try other user IDs from cross-account compare
3. Decode any base64/hex/hashed references
4. Grep JS for unused AJAX endpoints → probe them
5. Cross-account: replay Alice's requests with Bob's session
6. Cross-role: replay admin endpoints with standard user session
7. Document successful access to other users' data → IDOR confirmed
```

---

## Exam Notes

- **Numeric IDs in URLs** are the #1 sign — flag every one and increment-test
- **Hashed references** look secure but if the hash input is predictable (filename, user_id), they're not
- **AJAX calls in JS** reveal endpoints the UI doesn't expose for your role — Burp/DevTools both find these
- **Cross-account compare** is the gold-standard test — most IDORs surface when Bob's session can read Alice's IDs
- Don't ignore GUIDs — they leak via referer, share links, logs
- For real bug bounty: IDORs are the lowest-effort, highest-yield finding — quick to identify, hard to false-positive
