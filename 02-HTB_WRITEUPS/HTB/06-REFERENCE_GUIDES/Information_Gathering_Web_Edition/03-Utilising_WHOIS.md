# 🔍 Utilising WHOIS

## Overview

WHOIS gives you more than raw data — it gives you actionable intelligence. This section covers how to apply WHOIS findings across real-world scenarios.

---

## Practical WHOIS Lookup

### Installation

```bash
sudo apt update && sudo apt install whois -y
```
> Installs the `whois` command-line client. Skip this if it is already installed.

### Run the Query

```bash
whois facebook.com
```
> Queries the WHOIS registry for `facebook.com`. Swap the domain for your target. The output block below shows what a real response looks like.

### Example Output

```
Domain Name: FACEBOOK.COM
Registry Domain ID: 2320948_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrarsafe.com
Registrar URL: http://www.registrarsafe.com
Updated Date: 2024-04-24T19:06:12Z
Creation Date: 1997-03-29T05:00:00Z
Registry Expiry Date: 2033-03-30T04:00:00Z
Registrar: RegistrarSafe, LLC
Domain Status: clientDeleteProhibited
Domain Status: clientTransferProhibited
Domain Status: clientUpdateProhibited
Domain Status: serverDeleteProhibited
Domain Status: serverTransferProhibited
Domain Status: serverUpdateProhibited
Name Server: A.NS.FACEBOOK.COM
Name Server: B.NS.FACEBOOK.COM
Name Server: C.NS.FACEBOOK.COM
Name Server: D.NS.FACEBOOK.COM
[...]
Registrant Organization: Meta Platforms, Inc.
```

---

## Analysing the Output

| What to Check | What You See | What It Means |
|---|---|---|
| **Creation Date** | `1997-03-29` | Established domain — legitimate and long-standing |
| **Expiry Date** | `2033-03-30` | Far-out expiry — not going anywhere |
| **Domain Status** | 6x `Prohibited` flags (client + server) | Locked down — protected against unauthorized changes, transfers, deletions |
| **Name Servers** | `A-D.NS.FACEBOOK.COM` | Self-hosted DNS — Meta manages its own infrastructure |
| **Registrant Org** | Meta Platforms, Inc. | Confirms ownership matches expectations |

---

## WHOIS in Action — What You're Looking For

### Phishing Investigation

You get a suspicious email linking to `secure-bank-login.com`:

```bash
whois secure-bank-login.com
```
> Run WHOIS on any suspicious domain to check when it was registered, who owns it, and what name servers it uses. Recent registration + privacy service + sketchy hosting = strong phishing indicator.

**Red flags in output:**
- `Creation Date: 2026-03-10` → registered 3 days ago
- `Registrant: WhoisGuard` → hidden behind privacy service
- `Name Server: ns1.bulletproof-host.ru` → sketchy hosting provider

**Action:** Block the domain, alert the team, investigate the hosting provider for linked domains.

### Malware C2 Domain

Malware sample phones home to `update-service-cdn.net`:

```bash
whois update-service-cdn.net
```
> Same command, different target. Extract the hosting provider, registrant details, registration date, and name servers — then cross-reference against known threat actor infrastructure.

**What to extract:** Hosting provider, registrant details (even if fake), registration date, name servers → cross-reference against known threat actor infrastructure.

### Threat Intelligence

Multiple campaign domains linked to the same actor:

```bash
whois domain1.com
whois domain2.com
whois domain3.com
```
> Run WHOIS on each suspected campaign domain separately. Compare the registrant email, name servers, registrar, and registration date cluster across all results — shared values link domains to the same actor.

**Look for patterns across domains:**
- Same registrant email or organization
- Same name servers
- Registration dates clustered before known attacks
- Same registrar used repeatedly

---

## Key Takeaways

- WHOIS is a first-response tool. Check the registration date, registrant, and name servers immediately.
- Recently registered domains combined with a privacy service and bulletproof hosting are strong phishing indicators.
- For threat intelligence, WHOIS enables pattern recognition. Look for shared registrants, name servers, or registrars across multiple campaign domains.
- Domain status flags reveal security posture. `Prohibited` flags mean the domain is locked against unauthorized transfers or changes.
- Always feed name servers from WHOIS output into `dig` for DNS enumeration next.

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
