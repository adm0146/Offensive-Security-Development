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

---

## Layer Breakdown

### Layer 1: Internet Presence

**Goal:** Identify all possible target systems and interfaces that can be tested.

If the scope allows looking for additional hosts, this layer becomes even more critical. Techniques focus on finding domains, subdomains, netblocks, and other components that represent the company's presence and infrastructure.

### Layer 2: Gateway

**Goal:** Understand what we are dealing with and what to watch out for.

Understand the interface of the reachable target -- how it is protected and where it is located in the network. Due to the diversity of functionalities and procedures, this layer is covered in depth in other modules.

### Layer 3: Accessible Services

**Goal:** Understand the reason and functionality of the target system to communicate with it and exploit it effectively.

Examine each destination for all the services it offers. Each service:
- Has a specific purpose installed by the administrator
- Has certain functions that lead to specific results
- Requires understanding how it works to exploit it

**This is the primary focus of the Footprinting module.**

### Layer 4: Processes

**Goal:** Understand processing factors and identify dependencies between them.

Every command or function execution processes data (user-initiated or system-generated). Each process performs specific tasks with at least one source and one target.

### Layer 5: Privileges

**Goal:** Identify privileges and understand what is and isn't possible with them.

Each service runs through a specific user in a particular group with defined permissions. Administrators often overlook functions these privileges provide -- especially common in:
- Active Directory infrastructures
- Case-specific administration environments
- Servers where users manage multiple administration areas

### Layer 6: OS Setup

**Goal:** Assess internal security and the skill level of the company's admin teams.

Collect information about the actual operating system and its setup using internal access. This reveals how admins manage systems and what sensitive internal information can be gleaned.

---

## Methodology vs Cheat Sheet

A methodology is **not a step-by-step guide** -- it is a summary of systematic procedures for exploring a given target.

- **Methodology** = the systematic approach (what layers to enumerate, in what order, with what goals)
- **Cheat sheet** = the collection of tools and commands used within that approach

How individual components are identified is dynamic and constantly changing. Countless tools exist for the same purpose, each delivering different results. The goal remains the same -- the tools are interchangeable.

---

## Key Takeaways

- 6 layers from Internet Presence down to OS Setup -- each has a specific goal
- Layer 3 (Accessible Services) is the core focus of the Footprinting module
- Privileges (Layer 5) are frequently overlooked by administrators, especially in AD environments
- Methodology defines the approach, not the tools -- tools are a cheat sheet, not the methodology
- The methodology is static, but how you execute within it is dynamic
