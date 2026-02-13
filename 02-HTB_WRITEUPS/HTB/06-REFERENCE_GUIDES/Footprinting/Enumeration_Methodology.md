# Enumeration Methodology

## Why a Standardized Methodology?

Target systems offer too much variety to rely on habits or comfort zones. Most pentesters follow experience-based approaches, but this leads to missed attack surfaces. A static methodology with built-in flexibility ensures nothing gets overlooked while allowing adaptation to any environment.

---

## Three Levels of Enumeration

| Level | Focus |
|-------|-------|
| Infrastructure-based | External presence, network ranges, cloud resources |
| Host-based | Individual services, configurations, interfaces |
| OS-based | Internal components, permissions, system setup |

Reference diagram: [HTB Academy - Enumeration Methodology](https://academy.hackthebox.com/module/112/section/1185)

---

## Six Layers of Enumeration

Think of each layer as a wall. The goal is to find the entrance or gap -- not smash through with brute force. Forcing through one spot often leads nowhere because there's no entry point to pass to the next wall.

| Layer | Description | Information Categories |
|-------|-------------|----------------------|
| 1. Internet Presence | Identify internet presence and externally accessible infrastructure | Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures |
| 2. Gateway | Identify security measures protecting external and internal infrastructure | Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare |
| 3. Accessible Services | Identify accessible interfaces and services hosted externally or internally | Service Type, Functionality, Configuration, Port, Version, Interface |
| 4. Processes | Identify internal processes, sources, and destinations associated with services | PID, Processed Data, Tasks, Source, Destination |
| 5. Privileges | Identify internal permissions and privileges to accessible services | Groups, Users, Permissions, Restrictions, Environment |
| 6. OS Setup | Identify internal components and system setup | OS Type, Patch Level, Network Config, OS Environment, Configuration Files, Sensitive Private Files |

**Note:** The human aspect and OSINT-derived employee information has been removed from Layer 1 (Internet Presence) for simplicity.

---

## The Labyrinth Analogy

The entire pentest is like a labyrinth -- identify gaps and find a way inside as quickly and effectively as possible.

Key realities:
- You will encounter multiple gaps, but **not all gaps lead inside**
- All pentests are time-limited
- Even after a 4-week pentest, you cannot say 100% that no more vulnerabilities exist
- An attacker studying a company for months will have deeper understanding than a few-week assessment

**Example:** The SolarWinds cyber attack -- a sophisticated, long-term operation that standard assessment timescales would not have caught. This reinforces why methodology must account for what we cannot find within our time window.

---

## Key Takeaways

- Experience-based approaches miss things -- use a standardized methodology
- Each layer is a boundary to pass through, not force through
- Find the entrance, don't smash walls -- brute force wastes time and often leads nowhere
- Multiple gaps exist but not all lead forward
- Time constraints mean we can never guarantee 100% coverage
- Methodology must be static in structure but dynamic in execution
