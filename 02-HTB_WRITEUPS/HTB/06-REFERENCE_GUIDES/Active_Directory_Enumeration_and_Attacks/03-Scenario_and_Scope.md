# Section 03 — Scenario & Scope

> No lab questions. Defines the engagement used throughout this module.

---

## Engagement Summary

| Item | Detail |
|------|--------|
| Client | Inlanefreight |
| Assessor | CAT-5 Security |
| Type | Internal penetration test (two phases) |
| Phase 1 | Start anonymous inside internal network → work toward DA |
| Phase 2 | Start with attack box already inside the network |

---

## Scope

### In Scope
| Target | Description |
|--------|-------------|
| `INLANEFREIGHT.LOCAL` | Primary domain |
| `LOGISTICS.INLANEFREIGHT.LOCAL` | Child subdomain |
| `FREIGHTLOGISTICS.LOCAL` | External subsidiary (forest trust with INLANEFREIGHT.LOCAL) |
| `172.16.5.0/23` | Internal subnet |

### Out of Scope
- Other subdomains of INLANEFREIGHT.LOCAL or FREIGHTLOGISTICS.LOCAL
- Phishing / social engineering
- Active attacks against real-world inlanefreight.com (passive recon only)

---

## Goals

1. Enumerate the domain from unauthenticated position
2. Discover credentials
3. Lateral movement to gain a foothold
4. Privilege escalate toward Domain Admin
5. Compromise all in-scope internal domains

---

## Key Notes

- Start anonymous — no credentials provided upfront
- Forest trust between INLANEFREIGHT.LOCAL ↔ FREIGHTLOGISTICS.LOCAL = cross-domain attack path
- Non-destructive — no intentional interruption of systems
