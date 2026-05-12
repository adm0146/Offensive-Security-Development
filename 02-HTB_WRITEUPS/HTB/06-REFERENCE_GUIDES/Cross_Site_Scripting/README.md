# Cross-Site Scripting (XSS)

Reference guides from the HTB Academy XSS module. Stored / Reflected / DOM-based XSS, discovery, defacing, phishing form injection, session hijacking via blind XSS.

---

## Reference Guides

- [00-EXAM_CHEATSHEET.md](00-EXAM_CHEATSHEET.md) — Full XSS playbook: types, detection payloads, breakout patterns by context, cookie stealer, phishing form, defacing, prevention reference, decision tree for when stuck.

- [01-Introduction.md](01-Introduction.md) — What XSS is, real-world incidents (Samy Worm 2005, TweetDeck 2014), three types comparison.

- [02-Stored_XSS.md](02-Stored_XSS.md) — Persistent XSS via stored input (forum posts, comments). Detection payloads, page-source verification, `window.origin` vs `document.cookie`.

- [03-Reflected_XSS.md](03-Reflected_XSS.md) — Non-persistent XSS in error messages / search results. GET-based payload delivery via crafted URL.

- [04-DOM_XSS.md](04-DOM_XSS.md) — Client-side-only XSS. Source/sink model (`document.URL` → `innerHTML`). Payloads that bypass `<script>` filtering: `<img onerror>`, `<svg onload>`.

- [05-XSS_Discovery.md](05-XSS_Discovery.md) — Automated (XSStrike, Burp, ZAP) and manual discovery. SecLists XSS wordlists. Lesson: check error paths, not just success paths.

- [06-Defacing.md](06-Defacing.md) — Visible XSS impact: `document.body.style.background`, `document.title`, `innerHTML` body replacement. Why source still shows original markup.

- [07-Phishing.md](07-Phishing.md) — Inject fake login form via `document.write`, remove original form, capture creds with PHP listener + silent redirect.

- [08-Session_Hijacking.md](08-Session_Hijacking.md) — Blind XSS field probing (unique callback paths per input), cookie exfil via `new Image().src`, replaying stolen cookies with curl.

- [09-XSS_Prevention.md](09-XSS_Prevention.md) — Defense in depth: output encoding (`htmlspecialchars`), CSP `script-src 'self'`, `HttpOnly` cookies, DOMPurify, input validation, WAF.

- [10-Skills_Assessment.md](10-Skills_Assessment.md) — WordPress 5.7.2 Security Blog: blind XSS via comment `url` field with `http://x"><script src=...>` breakout → admin moderation queue triggers payload → `flag` cookie exfiltrated.
