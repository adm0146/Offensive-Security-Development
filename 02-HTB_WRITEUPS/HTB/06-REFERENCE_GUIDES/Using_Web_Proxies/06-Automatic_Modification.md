# Section 6 — Automatic Modification

> Set rules so the proxy auto-edits every request or response — no manual interception needed.
> Useful for: persistent header changes, permanently unlocking input fields, auto-injecting payloads.

---

## Burp — Match and Replace

```
Proxy → Proxy Settings → HTTP Match and Replace Rules → Add
```

**Fields:**
- **Type** — where the rule applies: Request header / Request body / Response header / Response body
- **Match** — the exact string or regex pattern to find
- **Replace** — what to substitute in
- **Regex match** — check this when you don't know the exact value (e.g., User-Agent varies by browser)

### Example 1 — Replace User-Agent in every request

| Field | Value |
|-------|-------|
| Type | Request header |
| Match | `^User-Agent.*$` |
| Replace | `User-Agent: HackTheBox Agent 1.0` |
| Regex match | ✅ True |

The regex `^User-Agent.*$` matches the entire User-Agent header line regardless of the actual browser string. Every outgoing request automatically gets the replaced value.

### Example 2 — Permanently unlock the IP input field in every response

| Field | Value |
|-------|-------|
| Type | Response body |
| Match | `type="number"` |
| Replace | `type="text"` |
| Regex match | False |

Add a second rule:

| Field | Value |
|-------|-------|
| Type | Response body |
| Match | `maxlength="3"` |
| Replace | `maxlength="100"` |
| Regex match | False |

Now every time the page loads, Burp swaps `type="number"` → `type="text"` before the browser sees it. The field stays unlocked across refreshes without intercepting anything.

### Example 3 — Auto-inject payload into every Ping request (Exercise 2)

| Field | Value |
|-------|-------|
| Type | Request body |
| Match | `ip=1` |
| Replace | `ip=;ls;` |
| Regex match | False |

Every time you click Ping, Burp automatically changes the POST body so the server runs `ls` instead of ping. Change `;ls;` to `;cat flag.txt;` to auto-read files.

---

## ZAP — Replacer

```
Ctrl+R  (or Options → Replacer → Add)
```

**Fields:**
- **Description** — label for the rule
- **Match Type** — Request Header / Response Body / Request Body / etc.
- **Match String** — the value to find (can use regex)
- **Replacement String** — what to put in its place
- **Enable** — toggle the rule on/off

### Example 1 — Replace User-Agent

| Field | Value |
|-------|-------|
| Description | HTB User-Agent |
| Match Type | Request Header (will add if not present) |
| Match String | `User-Agent` |
| Replacement String | `HackTheBox Agent 1.0` |
| Enable | ✅ |

Note: ZAP's "Request Header (will add if not present)" type matches by header name and replaces only the value, so you just put `User-Agent` in Match and the new value in Replacement.

### Example 2 — Unlock input field in every response

| Field | Value |
|-------|-------|
| Description | Unlock IP field |
| Match Type | Response Body |
| Match String | `type="number"` |
| Replacement String | `type="text"` |
| Enable | ✅ |

**Initiators tab:** Controls where the rule applies. Default = all HTTP(S) messages. Leave as-is for global rules.

---

## When to Use Each Approach

| Scenario | Best Approach |
|----------|--------------|
| One-off test, single request | Manual interception (Sections 4-5) |
| Same change needed on every request | Match and Replace / Replacer rule |
| Unlocking a restricted input field | Auto response modification rule |
| Testing how server responds to different headers | Auto request modification rule |
| Injecting a payload on every form submit | Auto request body modification rule |

---

## Exam Notes

- Match and Replace rules persist for the session — delete them when done or they'll affect unrelated requests
- Response rules fire on every page load — very powerful for removing persistent restrictions
- Request body rules match literal strings — if the body format changes, the rule won't fire
- Regex rules need `^...$` anchors if you want to match the whole header line
- ZAP Replacer and Burp Match and Replace do the same thing — know the menu path for both:
  - Burp: `Proxy → Proxy Settings → HTTP Match and Replace Rules`
  - ZAP: `Ctrl+R` or `Options → Replacer`
