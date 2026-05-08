# 15 — Detection & Prevention

## Overview

After covering offensive techniques for shells and payloads, this section flips to the **defensive perspective** — how to detect active shells, identify payload delivery and execution, and implement mitigations to prevent or limit the impact of these attacks.

---

## MITRE ATT&CK Framework

The **ATT&CK Framework** is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. Three key tactics tie directly to Shells & Payloads:

| Tactic / Technique | Description |
|---------------------|-------------|
| **Initial Access** | Compromising public-facing hosts or services (web apps, misconfigured SMB, auth protocol bugs). Gives a foothold but not full access. Reference: OWASP Top Ten |
| **Execution** | Code supplied by an attacker running on the victim host. This is the core of the Shells & Payloads module — payloads, delivery methods, shell scripting, browser-based execution, PowerShell one-liners, Metasploit, file uploads |
| **Command & Control (C2)** | The culmination of gaining access + establishing continued interactive access. Uses standard ports/protocols (HTTP/S, DNS, NTP) or apps (Slack, Discord, MS Teams). Ranges from basic cleartext (Netcat) to encrypted/obfuscated channels with proxies and VPNs |

---

## Events To Watch For

| Event | Description | Why It Matters |
|-------|-------------|----------------|
| **File uploads** | Especially via web applications — most common method of acquiring a shell besides direct command execution | Monitor application logs for potentially malicious uploads. Layer firewalls and AV around internet-facing hosts |
| **Suspicious non-admin user actions** | Normal users issuing commands via Bash or cmd (e.g., `whoami`). Users connecting to non-infrastructure SMB shares (end host → end host instead of end host → server) | Enable security logging, PowerShell logging, and alerting on shell interface usage |
| **Anomalous network sessions** | Unusual site visits, heartbeat traffic on nonstandard ports (e.g., 4444 — Meterpreter default), remote login attempts, bulk GET/POST requests in short timeframes | Parse NetFlow data, use network monitors, firewall logs, and SIEMs to spot deviations from baseline |

---

## Establishing Network Visibility

### Why It Matters

If a payload is successfully executed, it **must communicate over the network**. Network visibility is essential for detecting shells and payloads in action.

### Documentation & Topology

| Practice | Purpose |
|----------|---------|
| **Visual network topology diagrams** | Visualize traffic flow and identify anomalies |
| **Tools like Netbrain** | Combines visual diagramming (like Draw.io) with documentation and remote management |
| **Interactive topologies** | Interact with routers, firewalls, IDS/IPS, switches, and hosts directly |

### Cloud-Based Network Controllers

| Vendor | Capability |
|--------|------------|
| **Cisco Meraki** | Layer 7 visibility, cloud-managed dashboards |
| **Ubiquiti** | Cloud controller with traffic analytics |
| **Check Point** | Cloud-based management with visual dashboards |
| **Palo Alto Networks** | Layer 7 inspection, cloud-managed |

> These provide traffic baseline dashboards showing protocol usage, application traffic, and inbound/outbound patterns. **Any deviation from the baseline becomes immediately visible.**

### Deep Packet Inspection (DPI)

| Concept | Detail |
|---------|--------|
| **DPI appliances** | Act as "anti-virus for the network" — inspect packet content, not just headers |
| **Unencrypted traffic** | Tools like Netcat send cleartext — DPI can read every command sent between attacker and target |
| **Encrypted traffic** | Harder to inspect but SSL/TLS inspection appliances can decrypt and re-encrypt for analysis |

---

## Cleartext Shell Traffic — What Defenders See

### Example: Netcat Reverse Shell in Wireshark

When shells like Netcat are used without encryption, all traffic is visible:

**What network monitoring reveals:**
1. **NetFlow analysis** → Frequent TCP connections between two hosts on suspicious port (e.g., 4444)
2. **Packet inspection** → Expanding the traffic shows commands in cleartext
3. **Attacker actions visible** → Commands like `net user /add`, `net localgroup`, directory listings — all readable

| Indicator | What It Reveals |
|-----------|-----------------|
| Nonstandard port traffic (4444, 9001) | Potential Meterpreter or reverse shell |
| Frequent small TCP packets between two hosts | Interactive shell session |
| `net user` / `net localgroup` commands in packet data | Attacker creating persistence via new user accounts |
| Cleartext command execution | Full visibility into attacker's actions |

> **Key Insight:** Command-line logging paired with NetFlow data enables rapid triage — determine if commands are malicious or just an admin "playing around."

---

## Protecting End Devices

### What Are End Devices?

| Device Type | Examples |
|-------------|----------|
| **Workstations** | Employee computers |
| **Servers** | Web servers, file servers, domain controllers |
| **Peripherals** | Printers, NAS, cameras |
| **IoT** | Smart TVs, smart speakers |

> **Priority:** Any device with a CLI that can be remotely accessed. The same interface that enables administration also enables attackers.

### Windows-Specific Protections

| Protection | Detail |
|------------|--------|
| **Windows Defender** | Present at install — leave it **enabled** |
| **Defender Firewall** | Leave enabled with **all profiles** (Domain, Private, Public) |
| **Firewall exceptions** | Only for approved applications via change management |
| **Patch management** | Apply Microsoft updates shortly after release |
| **Server AV** | Even though it slows performance, AV on servers prevents payload execution |

> **Core principle:** The most common successful attack vector (besides misconfiguration) is the **human element** — a single click on a link or file can lead to compromise.

---

## Potential Mitigations

| Mitigation | How It Helps |
|------------|--------------|
| **Application Sandboxing** | Limits scope of access and damage if an attacker exploits a vulnerability in an internet-facing application |
| **Least Privilege Permissions** | Ordinary users don't need admin or domain admin access. Proper permissions can stop or significantly hinder an attack |
| **Host Segmentation & Hardening** | Place internet-facing hosts (web servers, VPN servers) in a DMZ. Follow STIG hardening guides. Prevents lateral movement if a boundary host is compromised |
| **Physical & Application Layer Firewalls** | Proper inbound/outbound rules allowing only traffic initiated from within the network. NAT can break shell payload functionality. Denying traffic on unapproved ports cripples many bind and reverse shells |

### How Mitigations Map to Shell Attacks

| Shell/Payload Technique | Blocked By |
|--------------------------|------------|
| **Bind shells** (listener on target) | Inbound firewall rules, host segmentation |
| **Reverse shells** (callback to attacker) | Outbound firewall rules, DPI, NAT breaking payload functionality |
| **Web shell uploads** | Application sandboxing, file upload validation, AV scanning |
| **Meterpreter/C2 beacons** | DPI, network monitoring for nonstandard port traffic |
| **Lateral movement via SMB** | Host segmentation (DMZ), least privilege, NetFlow monitoring |
| **Payload execution** | Endpoint AV (Windows Defender), application whitelisting |

---

## Defense-in-Depth Strategy

```
┌─────────────────────────────────────────────────────┐
│                PERIMETER DEFENSE                     │
│  Physical & Application Firewalls, NAT, DMZ         │
├─────────────────────────────────────────────────────┤
│              NETWORK MONITORING                      │
│  DPI, NetFlow, SIEM, IDS/IPS, Network Topology      │
├─────────────────────────────────────────────────────┤
│              HOST PROTECTION                         │
│  AV/Defender, Patch Management, STIG Hardening       │
├─────────────────────────────────────────────────────┤
│              ACCESS CONTROL                          │
│  Least Privilege, Segmentation, Sandboxing           │
├─────────────────────────────────────────────────────┤
│              LOGGING & ALERTING                      │
│  PowerShell Logging, Command-Line Logging,           │
│  Application Logs, User Activity Monitoring          │
└─────────────────────────────────────────────────────┘
```

> No single protection is sufficient. **Layered defenses** ensure that if one control fails, others are in place to detect, slow, or stop the attacker.

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **MITRE ATT&CK** | Map techniques to Initial Access, Execution, and C2 for structured detection |
| **Cleartext shells are trivially detected** | Netcat traffic is fully readable in Wireshark — use DPI and NetFlow |
| **Nonstandard ports are red flags** | 4444, 9001, etc. should trigger alerts immediately |
| **Human element is #1 vector** | Users clicking links/files — awareness training matters |
| **Windows Defender works** | Don't disable it. Keep firewall on with all profiles enabled |
| **Baseline your network** | Know what normal looks like so deviations are immediately obvious |
| **Segment and harden** | DMZ for internet-facing hosts, STIG guides for hardening |
| **Defense-in-depth** | No single solution stops everything — layer your controls |
| **Log everything** | PowerShell logging, command-line logging, application logs, NetFlow |
| **NAT breaks shells** | Network Address Translation can disrupt bind/reverse shell functionality if attackers don't account for it |
