# Section 1 — Intro to Web Proxies

> Overview section — no labs, no commands. Concepts and tool comparison only.

---

## What a Web Proxy Does

A web proxy sits between your browser and the web server and intercepts every HTTP/HTTPS request and response. This lets you:

- **See** exactly what data your browser is sending (including hidden fields, cookies, headers)
- **Modify** requests before they reach the server (change parameters, bypass client-side checks)
- **Replay** requests as many times as you want with different values
- **Automate** sending thousands of variations (fuzzing, brute force)

**Key difference from Wireshark:** Wireshark captures ALL network traffic at the packet level. Web proxies work specifically at the HTTP application layer — they show you requests and responses as structured, readable data you can interact with.

---

## Why Web Proxies Are Essential for Web Pentesting

Most modern web apps don't do everything in the page you see — they constantly send requests to back-end APIs. Without a proxy you'd never see those requests. With a proxy you can:

- Find hidden parameters the front-end doesn't expose
- Bypass JavaScript validation (the server still needs to validate — often it doesn't)
- Understand authentication flows (cookies, tokens, session management)
- Test for injection vulnerabilities (SQLi, XSS, SSTI, command injection)
- Fuzz endpoints for hidden functionality
- Map the full attack surface of an application

---

## The Two Tools: Burp Suite vs ZAP

### Burp Suite
The industry standard. Best UI, most mature, most widely documented.

| Feature | Community (Free) | Pro (Paid) |
|---------|-----------------|------------|
| Intercept & modify requests | ✅ | ✅ |
| Repeater (replay requests) | ✅ | ✅ |
| Intruder (fuzzing/brute force) | ✅ (rate-limited) | ✅ (fast) |
| Decoder / Comparer | ✅ | ✅ |
| Built-in Chromium browser | ✅ | ✅ |
| Active web app scanner | ❌ | ✅ |
| Burp Collaborator (SSRF/blind) | ❌ | ✅ |
| Extensions from BApp Store | Limited | ✅ |

**Use Burp when:** You want the most polished workflow and documentation. Default choice for most web pentests.

**Free trial:** If you have an edu/business email, apply at portswigger.net for a free Pro trial.

### ZAP (OWASP Zed Attack Proxy)
Free, open-source, actively maintained by the community. No paid tier, no throttling.

**ZAP advantages over Burp Free:**
- Active scanner is completely free (Burp requires Pro)
- No rate limiting on fuzzing/brute force
- Built-in AJAX spider (handles JavaScript-heavy apps)
- Completely open source — no licensing concerns on engagements

**ZAP disadvantages:**
- Less polished UI than Burp
- Smaller community and fewer write-ups online
- Some workflows are less intuitive

**Use ZAP when:** You need an active scanner without paying for Burp Pro, or you're on a budget engagement.

---

## Module Coverage

This module covers both tools in parallel — same technique, shown in Burp AND ZAP.

Topics covered across this module:
- Setting up the proxy and configuring the browser
- Intercepting and modifying HTTP and HTTPS requests
- Using Repeater/Requester to replay modified requests
- Encoding/decoding data (base64, URL, HTML entities)
- Comparing responses
- Scanning with the active scanner (ZAP free, Burp Pro)
- Burp Intruder and ZAP Fuzzer for automated testing
- Extensions and add-ons
- Bypassing HTTPS certificate errors

---

## Exam Notes

- Burp and ZAP are both on Kali and the lab hosts — know both
- Burp keyboard shortcuts matter: `Ctrl+R` = send to Repeater, `Ctrl+I` = send to Intruder
- ZAP's active scanner is free; Burp's requires Pro — on the exam you have Burp Pro
- The FoxyProxy extension in Firefox is the standard way to toggle the proxy on/off
- All intercept should be OFF by default — only enable when you need to modify a specific request
- HTTPS interception requires installing the proxy's CA certificate in the browser
