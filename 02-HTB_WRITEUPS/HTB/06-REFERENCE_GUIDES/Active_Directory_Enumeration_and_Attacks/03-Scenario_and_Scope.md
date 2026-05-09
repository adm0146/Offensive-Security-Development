# 03 — Scenario & Scope

> No lab questions. Context section — defines the engagement scope used throughout the module.

---

## Engagement Context

**Client:** Inlanefreight  
**Assessor:** CAT-5 Security  
**Type:** Internal penetration test (two phases)

**Phase 1:** Simulate external breach — start from anonymous position inside internal network, work toward Domain Admin  
**Phase 2:** Start with attack box already inside the internal network

---

## Scope

### In Scope
| Range / Domain | Description |
|----------------|-------------|
| `INLANEFREIGHT.LOCAL` | Primary customer domain — AD and web services |
| `LOGISTICS.INLANEFREIGHT.LOCAL` | Customer subdomain |
| `FREIGHTLOGISTICS.LOCAL` | Subsidiary — external forest trust with INLANEFREIGHT.LOCAL |
| `172.16.5.0/23` | In-scope internal subnet |

### Out of Scope
- Any other subdomains of INLANEFREIGHT.LOCAL or FREIGHTLOGISTICS.LOCAL
- Phishing or social engineering
- Active attacks against real-world inlanefreight.com (passive recon only)

---

## Assessment Goals

1. Enumerate the domain from an unauthenticated position
2. Discover credentials
3. Lateral movement to gain a foothold
4. Privilege escalation toward Domain Admin
5. Compromise all in-scope internal domains

---

## Key Notes for Testing

- Start anonymous — no credentials provided upfront
- No intentional interruption of computer systems or network operations
- Captured password files handled securely, not shared outside the assessment team
- Forest trust between INLANEFREIGHT.LOCAL and FREIGHTLOGISTICS.LOCAL — potential cross-domain attack path

---

## References

- Previous: [02-Tools_of_the_Trade.md](02-Tools_of_the_Trade.md)
- Next: [04-External_Recon_and_Enumeration.md](04-External_Recon_and_Enumeration.md)
