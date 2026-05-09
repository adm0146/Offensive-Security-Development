# 17 — Detection & Prevention

> Defensive counterpart to the pivoting module. For each offensive TTP practiced, these are the controls defenders use to detect and prevent them — relevant for reporting and recommendations during assessments.

---

## Baseline — Know Your Environment

Document and track:
- DNS records, DHCP configs, network device backups
- Full application inventory
- All enterprise hosts and locations
- Users with elevated permissions
- **Dual-homed hosts** (multiple NICs — primary pivot candidates)
- Up-to-date visual network diagram (Netbrain, diagrams.net)

---

## MITRE ATT&CK Mapping

| TTP | MITRE | Detection / Prevention |
|-----|-------|----------------------|
| **External Remote Services** | T1133 | Firewall segmentation; block internal protocols from reaching internet; require VPN before service access |
| **Remote Services (SSH/RDP)** | T1021 | MFA on all remote services; limit which accounts have remote access; firewall rules on host and perimeter; OOB management for infrastructure devices |
| **Non-Standard Ports** | T1571 | Baseline normal port/protocol usage; alert on known protocols (HTTP/HTTPS) on non-standard ports; NIDS/NIPS |
| **Protocol Tunneling** | T1572 | Lock down allowed protocols; block external DNS resolution from non-DNS hosts; monitor for C2 beaconing patterns (periodic encrypted traffic) |
| **Proxy Use** | T1090 | Allowlist of approved domains/IPs; block all non-approved outbound; understand baseline netflow to spot anomalies |
| **LOTL (Living off the Land)** | N/A | Behavioral baseline for users and network; EDR + AV with command shell visibility; SIEM correlation of logs |

---

## People, Process, Technology Framework

### People
- Enforce MFA — especially on admin accounts
- BYOD risk: personal devices on corporate networks extend attacker foothold (malware on employee laptop → network access)
- Security awareness training
- SOC or SOC-as-a-Service for 24/7 monitoring
- Documented incident response plan

### Process
- Asset management policies (host audits, asset tags, periodic inventory)
- Access control policies — provisioning and de-provisioning
- Host hardening baselines and gold images
- Change management — document who did what and when

### Technology
- Patch legacy misconfigurations regularly
- Network segmentation — separate HR from infrastructure, prod from management
- SIEM for log correlation across hosts and infrastructure
- Host-based IDS/IPS and event logging
- DMZ for any internet-facing hosts
- NGFW with ability to block suspicious IPs and quickly disconnect connections

---

## Perimeter Checklist (from outside in)

- What is public-facing? Minimize exposure.
- NGFW: block by IP, enforce VPN, quick disconnect capability
- Who has remote admin access? Is it tracked?
- External trust relationships documented?
- OOB management for routers/switches — never exposed to the enterprise network

## Internal Checklist

- Internet-facing hosts in DMZ?
- IDS/IPS deployed internally?
- Network segments per team/function?
- Separate prod and management networks?
- SIEM aggregating host + infrastructure logs?
- Standard users cannot reach network admin panels

---

## Key Takeaways for Pentest Reporting

1. **Dual-homed hosts** are the highest-value pivot targets — recommend documenting and monitoring all hosts with multiple NICs.
2. **Protocol tunneling** (SSH, DNS, ICMP) is hard to block entirely — recommend behavioral monitoring and beaconing detection rather than blanket blocks.
3. **LOTL techniques** (netsh, ssh, built-in tools) bypass AV — EDR with behavioral detection is the only reliable control.
4. **MFA on RDP/SSH** is the single highest-impact control against credential-based lateral movement.
5. **Network segmentation** — if a compromised host can't reach the DC or other segments, the blast radius is contained.

---

## References

- Previous: [16-Skills_Assessment.md](16-Skills_Assessment.md)
- Next: [18-Module_Summary.md](18-Module_Summary.md)
- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
