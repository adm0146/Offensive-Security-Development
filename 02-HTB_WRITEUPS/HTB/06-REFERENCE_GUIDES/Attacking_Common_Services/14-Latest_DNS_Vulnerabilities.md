# Latest DNS Vulnerabilities

> HTB Academy · Attacking Common Services · Section 14 / 19

Where Section 13 covered the offensive primitives (AXFR, subdomain enum, cache poisoning), Section 14 zooms in on the **single highest-EV DNS bug class for bounty hunters today**: dangling-resource subdomain takeover. RedHuntLabs' *Project Resonance Wave 1* (2020) scanned 220 M domains and flagged **424,120** as takeover-able across 33 third-party providers — 139 of those in the Alexa Top 1000, 62% in e-commerce. The vector is cheap to scan, cheap to claim, and pays out on H1 / Bugcrowd / Intigriti.

---

## Quick Reference

| Goal | Tool / Command |
|------|----------------|
| Mass passive subdomain harvest | `subfinder -d <domain> -all -recursive` |
| Resolve at scale | `puredns resolve subs.txt -r resolvers.txt` |
| Probe for live HTTP(S) | `httpx -l subs.txt -title -status-code -tech-detect` |
| Fingerprint takeover | `subjack -w subs.txt -t 100 -ssl -c fingerprints.json -v` |
| Modern fingerprint scanner | `nuclei -t http/takeovers/ -l subs.txt` |
| DNS-only takeover scanner | `dnstake -d <domain>` |
| Provider matrix | <https://github.com/EdOverflow/can-i-take-over-xyz> |
| H1 disclosed reports | `hackerone.com/reports?q=subdomain+takeover` |

---

## The Concept

A **subdomain takeover** happens when a DNS record (`CNAME`, `A` to a third-party IP, `NS`, or `MX`) points to a third-party resource that:

1. The legitimate owner **provisioned** (e.g., S3 bucket, Heroku app, Azure site, GitHub Pages site, Fastly service, Shopify store).
2. Was later **deleted, expired, or unclaimed** at the provider.
3. The DNS record was **never cleaned up** because DNS entries cost nothing to keep.

The attacker re-registers the dangling resource at the provider — the victim's CNAME now resolves to attacker-controlled infrastructure. Browsers, MTAs, OAuth callbacks, cookies scoped to `*.victim.com`, and CSP `script-src` whitelists all follow the CNAME and treat the attacker's content as first-party.

### Why CNAMEs are the Sharpest Edge

```
customer-drive.inlanefreight.com.   3600   IN   CNAME   ilf-customer-drive.s3.amazonaws.com.
```
> This is an example DNS record showing a CNAME to an S3 bucket. If the bucket `ilf-customer-drive` is deleted but this record stays, the subdomain is open for takeover.

If `ilf-customer-drive` no longer exists in S3, **anyone** can register it. The CNAME still resolves; the browser still shows `customer-drive.inlanefreight.com` in the address bar; the TLS certificate the attacker provisions (e.g., via S3 + CloudFront ACM, or just bare S3 with a wildcard cert from the victim) still validates as far as the user is concerned.

---

## Mapping Takeover to the "Concept of Attacks" Model

HTB's framework decomposes any attack into **Source → Process → Privileges → Destination**. Two passes apply for subdomain takeover:

### Pass 1 — Initiation (claiming the dangling resource)

| Step | Subdomain Takeover | Category |
|------|--------------------|----------|
| 1 | Discover an unclaimed subdomain CNAME (`sub.victim.com → unclaimed.s3.amazonaws.com`) | **Source** |
| 2 | Register the dangling resource at the third-party provider (create the S3 bucket / Heroku app / GH Pages repo) | **Process** |
| 3 | Privileges still belong to the apex-domain owner — provider does not arbitrate who claims abandoned names | **Privileges** |
| 4 | Attacker-controlled infra is now the resolution target | **Destination** |

### Pass 2 — Exploitation (weaponizing the subdomain)

| Step | Subdomain Takeover | Category |
|------|--------------------|----------|
| 5 | Victim user / app makes a request to `sub.victim.com` (link click, OAuth redirect, cookie write, CSP fetch) | **Source** |
| 6 | Recursive resolver follows the still-valid CNAME → attacker host | **Process** |
| 7 | Apex DNS administrators (not provider) implicitly trust the record because they wrote it | **Privileges** |
| 8 | Attacker server returns malicious content under a trusted origin | **Destination** |

---

## Impact Beyond Phishing

A clean phish on `customer-drive.victim.com` is the obvious win, but takeovers chain into far worse:

| Attack | Why takeover enables it |
|--------|-------------------------|
| **Session hijack** | `Domain=.victim.com` cookies are sent to subdomains; attacker reads `Cookie:` header |
| **CSRF** | `*.victim.com` origins are often allowlisted in `Origin` / `Referer` checks |
| **CORS abuse** | `Access-Control-Allow-Origin: https://*.victim.com` lets attacker JS read victim API responses |
| **CSP bypass** | `script-src *.victim.com` — attacker can host arbitrary JS that the main app loads |
| **OAuth redirect_uri** | Many apps allow `*.victim.com` as a redirect target — full OAuth code theft |
| **Email spoofing (MX takeover)** | Dangling MX → attacker receives password-reset / 2FA emails for `*@victim.com` |
| **Supply chain (NS takeover)** | Dangling NS delegation gives attacker full DNS control of an entire subzone |

H1 has paid **5-figure bounties** for OAuth-chained takeovers (e.g., Uber, Starbucks, Snapchat reports).

---

## Provider Fingerprint Cheat Sheet

| Provider | DNS pattern | "Takeover-able" tell |
|----------|-------------|----------------------|
| AWS S3 | `*.s3.amazonaws.com` / `*.s3-website-*.amazonaws.com` | `<Code>NoSuchBucket</Code>` |
| AWS CloudFront | `*.cloudfront.net` | `Bad request. ERROR: The request could not be satisfied` (sometimes) |
| GitHub Pages | `*.github.io` / A → 185.199.108.153 | `There isn't a GitHub Pages site here.` |
| Heroku | `*.herokuapp.com` | `No such app` |
| Azure | `*.azurewebsites.net`, `*.cloudapp.net`, `*.trafficmanager.net` | `404 Web Site not found` / NXDOMAIN |
| Fastly | `*.fastly.net` | `Fastly error: unknown domain` |
| Shopify | `shops.myshopify.com` | `Sorry, this shop is currently unavailable.` |
| Tumblr | `*.tumblr.com` | `Whatever you were looking for doesn't currently exist.` |
| Unbounce | `*.unbouncepages.com` | `The requested URL was not found on this server.` |
| Zendesk | `*.zendesk.com` | `Help Center Closed` |
| Surge.sh | `*.surge.sh` | `project not found` |
| Bitbucket | `*.bitbucket.io` | `Repository not found` |
| Pantheon | `*.pantheonsite.io` | `The gods are wise, but do not know of the site which you seek.` |

Always cross-reference <https://github.com/EdOverflow/can-i-take-over-xyz> — the provider list shifts as vendors patch the dangling-resource vector.

---

## End-to-End Hunt Workflow

### 1. Surface Enumeration

```bash
# Passive — CT logs, OTX, DNSDumpster, BufferOver, etc.
subfinder -d victim.com -all -recursive -silent -o subs.txt
amass enum -passive -d victim.com -o subs2.txt
sort -u subs.txt subs2.txt > all_subs.txt
```
> Combine two passive tools and deduplicate with `sort -u`. Replace `victim.com` with your target domain. Both tools send no traffic to the target — safe for stealth recon.

### 2. Resolve & Find CNAME Tails

```bash
# Mass resolve with a clean resolver list
puredns resolve all_subs.txt -r resolvers.txt -w resolved.txt

# Pull every CNAME — these are your takeover candidates
dnsx -l resolved.txt -cname -resp -silent | tee cnames.txt
```
> `puredns` resolves the subdomain list against a trusted resolver set. `dnsx -cname` extracts CNAME records from every resolved host — these are your takeover leads.

### 3. Identify Dangling Targets

```bash
# Filter CNAMEs to known third-party providers
grep -Ei 's3.amazonaws|cloudfront|github\.io|herokuapp|azurewebsites|fastly|shopify|unbouncepages|zendesk|surge\.sh|bitbucket\.io' cnames.txt > suspects.txt
```
> Filters the CNAME list to only records pointing at providers known to allow unclaimed resource registration. Add more patterns as new providers are discovered.

### 4. Fingerprint

```bash
# subjack — classic, fast, has built-in fingerprints.json
subjack -w suspects.txt -t 50 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v -o vulnerable.txt

# nuclei — actively maintained templates
nuclei -t http/takeovers/ -l suspects.txt -o nuclei_takeovers.txt

# dnstake — DNS-layer detection (catches NS takeovers subjack misses)
dnstake -d victim.com -t 50 -o dnstake.txt
```
> Use all three in sequence — they have different fingerprint databases. `-t 50` sets parallel threads. `-v` enables verbose output to see which checks are running.

### 5. Verify (manually, before claiming)

```bash
# Confirm the CNAME and the error string
dig sub.victim.com CNAME +short
curl -sI https://sub.victim.com
curl -s  https://sub.victim.com | head
```
> Always verify manually before claiming. `dig CNAME` confirms the delegation is still active. `curl -sI` checks the HTTP response headers. `curl | head` looks for the provider's "not found" fingerprint string.

If the response matches a fingerprint **and** the resource is genuinely unclaimed at the provider, proceed to PoC.

### 6. Proof-of-Concept (do NOT exploit users)

For a bug bounty submission, the PoC is the **claim itself** + a benign HTML page proving control:

```html
<!doctype html>
<html><body>
  <h1>Subdomain Takeover PoC</h1>
  <p>Researcher: @yourhandle</p>
  <p>Subdomain: sub.victim.com</p>
  <p>Date: 2026-MM-DD</p>
  <p>Reported under <a href="https://hackerone.com/victim">victim's bounty program</a>.</p>
</body></html>
```
> This is the minimum acceptable PoC page. Replace `@yourhandle` and `sub.victim.com` with your values. Host this and screenshot it — this is your proof of control without harming real users.

Host on the claimed S3 bucket / GH Pages / Heroku app and screenshot. **Never** harvest credentials, send phishing, or set cookies on real users — that converts a paid finding into a CFAA problem.

---

## Reporting Template (H1-style)

```
Title: Subdomain takeover on sub.victim.com via dangling AWS S3 CNAME

Summary
-------
sub.victim.com has a CNAME pointing to ilf-customer-drive.s3.amazonaws.com.
The bucket "ilf-customer-drive" is unclaimed in us-east-1, and I have
registered it to demonstrate takeover. An attacker can host arbitrary
content under sub.victim.com, enabling phishing, cookie theft (cookies
scoped to .victim.com), and CSP/CORS bypass.

Steps to Reproduce
------------------
1. dig sub.victim.com CNAME  → ilf-customer-drive.s3.amazonaws.com
2. curl https://sub.victim.com → NoSuchBucket error (pre-claim screenshot)
3. Bucket claimed by researcher; current page demonstrates control (post-claim screenshot)

Impact
------
- Phishing under trusted origin (TLS-valid)
- Cookie theft for any cookies with Domain=.victim.com
- CORS / CSP allowlist abuse for *.victim.com
- OAuth redirect_uri abuse if *.victim.com is whitelisted

Remediation
-----------
- Delete the dangling CNAME at the apex DNS provider, OR
- Re-create the S3 bucket under your account
- Audit DNS for other dangling third-party CNAMEs (subjack / dnstake)

Researcher
----------
@yourhandle  -  yourhandle@protonmail.com
```
> Use this as a template for H1/Bugcrowd submissions. Replace all placeholder values. The "Steps to Reproduce" section with screenshots (before and after claim) is the most important part for triage.

---

## Defenses (for Blue Team / report's "Remediation" section)

| Control | Implementation |
|---------|----------------|
| DNS hygiene | Treat DNS records as code; require ticketed deprovisioning of provider resource **before** record removal, then remove record |
| Continuous monitoring | Daily run of `subjack` / `nuclei -t http/takeovers/` against your own zone |
| Provider-side prevention | AWS Route53 **alias** records (vs CNAME) tie to account-owned ARN — cannot be claimed by another tenant |
| Domain verification | Many providers (GitHub, Heroku, Azure) now require TXT-record domain verification before binding a custom domain |
| CAA records | Restrict which CAs can issue certs for the apex — limits attacker's TLS options on a hijacked sub |
| Tiered subdomain trust | Avoid `Domain=.victim.com` cookies; use exact-match origins; tighten CSP `script-src`/`connect-src` to specific hosts not `*.victim.com` |

---

## Key Takeaways

- **Takeover ≠ phishing.** It's an **identity** bug — the attacker speaks as the victim's origin. Phishing, cookie theft, CSP bypass, OAuth abuse, and email interception all chain off it.
- **CNAMEs are the highest-yield records**, but `NS`, `MX`, and even `A` (against shared third-party IP pools) are takeover-able under the right circumstances.
- **Hunt at scale, verify by hand.** Automation produces leads; only manual verification + provider claim proves the bug.
- **Cross-reference can-i-take-over-xyz** — providers patch over time. A "GitHub Pages" hit from 2019 templates is no longer exploitable.
- **Bug bounty is the legitimate channel.** Claim the resource, prove control with a benign page, report. Do not weaponize.

---

## References

- HTB Academy — *Attacking Common Services*, Section 14: Latest DNS Vulnerabilities
- RedHuntLabs — *Project Resonance Wave 1*: <https://redhuntlabs.com/blog/project-resonance-wave-1.html>
- EdOverflow — *can-i-take-over-xyz*: <https://github.com/EdOverflow/can-i-take-over-xyz>
- HackerOne disclosed reports tagged "subdomain takeover": <https://hackerone.com/reports?q=subdomain+takeover>
- Detectify Labs — *Hostile Subdomain Takeover*: <https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/>
- Frans Rosén — *A deep dive into AWS S3 access controls*
- ProjectDiscovery — `subfinder`, `dnsx`, `httpx`, `nuclei`
- haccer — `subjack`: <https://github.com/haccer/subjack>
- pwnesia — `dnstake`: <https://github.com/pwnesia/dnstake>
