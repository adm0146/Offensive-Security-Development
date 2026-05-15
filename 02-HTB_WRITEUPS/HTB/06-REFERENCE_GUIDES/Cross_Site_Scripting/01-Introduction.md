# Section 1 — Introduction

> Theory only. No lab.

---

## What XSS Is

Cross-Site Scripting (XSS) is a vulnerability where user input is rendered as HTML/JavaScript without proper sanitization. The browser executes the injected JavaScript as if it came from the trusted page.

**Key distinction from SQLi:** XSS runs in the **victim's browser**, not on the server. The server is just the delivery mechanism.

```
Server stores/reflects unsanitized input  →  Victim browser renders it  →  JS executes in victim's session
```

---

## Impact

XSS runs inside the browser sandbox, scoped to the vulnerable site's origin (Same-Origin Policy, or SOP). Within that scope it can:

- Steal cookies / session tokens → account takeover
- Force authenticated API calls (change password, transfer funds, etc.)
- Keylog the page
- Deface content / inject phishing UI
- Crypto-mine
- Chain with browser-binary exploits → sandbox escape → RCE

> Low *direct* server impact + high probability of presence = **medium risk** overall. Worth detecting and remediating in every assessment.

---

## Notable Real-World XSS Incidents

| Year | Target | What happened |
|------|--------|---------------|
| 2005 | MySpace | Samy Worm — stored XSS posted "Samy is my hero" + replicated to viewers' profiles; 1M+ infections in a day |
| 2014 | Twitter TweetDeck | Self-retweeting tweet; 38k retweets in 2 min; TweetDeck temporarily taken offline |
| 2019 | Google Search | XSS in XML library used by search bar |
| Past | Apache HTTPD admin | XSS exploited to steal admin passwords at certain companies |

---

## Three Types of XSS

| Type | Where input goes | Persistence | Example |
|------|------------------|-------------|---------|
| **Stored (Persistent)** | Saved to DB, served to other users | Permanent | Forum post, comment, profile bio |
| **Reflected (Non-Persistent)** | Echoed in immediate response from server | Per-request | Search result echoing query, error messages |
| **DOM-based** | Processed entirely client-side; never reaches server | Per-request | `location.hash` written into `innerHTML` by JS |

**Severity ranking:** Stored > Reflected > DOM-based
Stored XSS hits every viewer automatically. Reflected and DOM-based XSS require tricking a victim into clicking a crafted link.

---

## Exam Notes

- XSS = code injection in the browser, not the server
- The Same-Origin Policy (SOP) limits XSS to the vulnerable site's origin — but that's enough to fully compromise a user's session there
- Memorize the 3 types — questions almost always ask which type applies to a given scenario
- "Reduce risk" wording matters: XSS is rarely "accepted" because the probability is so high
