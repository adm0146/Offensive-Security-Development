# Reference Guides & Learning Modules

A comprehensive collection of cybersecurity techniques, tools, and methodologies organized for easy navigation and practical application during penetration testing and CPTS exam preparation.

---

## 📚 Quick Navigation

### Foundation Guides
Essential reference materials covering core pentesting techniques and methodologies.

| Guide | Description |
|-------|-------------|
| [Enumeration_Process.md](Foundation/Enumeration_Process.md) | Systematic enumeration methodology (Nmap → Service-specific → Web → Privilege Escalation) |
| [Service_Scanning_Enumeration.md](Foundation/Service_Scanning_Enumeration.md) | Service-specific enumeration commands (FTP, SMB, SNMP, etc.) |
| [Web_Enumeration.md](Foundation/Web_Enumeration.md) | Web application enumeration and discovery techniques |
| [File_Transfer.md](Foundation/File_Transfer.md) | Techniques for transferring files between systems |
| [Types_of_Shells.md](Foundation/Types_of_Shells.md) | Comprehensive guide to different shell types and usage |
| [Privilege_Escalation.md](Foundation/Privilege_Escalation.md) | Linux and Windows privilege escalation techniques |
| [Public_Exploits.md](Foundation/Public_Exploits.md) | Finding and utilizing public CVE exploits |
| [MASTER_ENUMERATION_CHEATSHEET.md](Foundation/MASTER_ENUMERATION_CHEATSHEET.md) | Complete flowchart and decision tree for box methodology |

---

### Academy Learning Modules
Detailed notes from CPTS Academy modules, organized by topic.

#### Network Enumeration with Nmap
Complete guide to network scanning and enumeration using Nmap.

| Section | Description |
|---------|-------------|
| [Host_Discovery.md](Network_Enumeration_With_Nmap/Host_Discovery.md) | Host discovery methods (ICMP, ARP, network ranges, IP lists) |
| [Port_Scanning.md](Network_Enumeration_With_Nmap/Port_Scanning.md) | *(Coming soon)* Port scanning techniques and options |
| [Service_Detection.md](Network_Enumeration_With_Nmap/Service_Detection.md) | *(Coming soon)* Service version detection and OS fingerprinting |
| [NSE_Scripts.md](Network_Enumeration_With_Nmap/NSE_Scripts.md) | *(Coming soon)* Nmap Scripting Engine usage and examples |
| [Firewall_IDS_Evasion.md](Network_Enumeration_With_Nmap/Firewall_IDS_Evasion.md) | *(Coming soon)* Bypassing firewalls and IDS detection |

**How to Use:** Start with `Host_Discovery.md` and progress through each section as you complete the CPTS academy module. Each section builds on the previous one.

---

## 🎯 Usage by Phase

### Phase 1: Initial Reconnaissance
**Start here when beginning a new target:**
1. [Enumeration_Process.md](Foundation/Enumeration_Process.md) - Overall methodology
2. [Network_Enumeration_With_Nmap/Host_Discovery.md](Network_Enumeration_With_Nmap/Host_Discovery.md) - Find targets
3. [Service_Scanning_Enumeration.md](Foundation/Service_Scanning_Enumeration.md) - Scan and enumerate services

### Phase 2: Service-Specific Enumeration
**Based on services discovered:**
- HTTP/HTTPS → [Web_Enumeration.md](Foundation/Web_Enumeration.md)
- SMB/FTP/SNMP → [Service_Scanning_Enumeration.md](Foundation/Service_Scanning_Enumeration.md)

### Phase 3: Exploitation
**Finding and using exploits:**
1. [Public_Exploits.md](Foundation/Public_Exploits.md) - CVE research
2. [Types_of_Shells.md](Foundation/Types_of_Shells.md) - Shell types after exploitation

### Phase 4: Post-Exploitation
**After gaining shell access:**
1. [File_Transfer.md](Foundation/File_Transfer.md) - Transfer tools to target
2. [Privilege_Escalation.md](Foundation/Privilege_Escalation.md) - Escalate privileges

---

## 📖 Learning Path

### For CPTS Academy Module Completion
Follow the module structure to build comprehensive penetration testing skills:

**Week 1-2: Network Enumeration with Nmap**
- ✅ [Host_Discovery.md](Network_Enumeration_With_Nmap/Host_Discovery.md)
- ⬜ [Port_Scanning.md](Network_Enumeration_With_Nmap/Port_Scanning.md) *(In Progress)*
- ⬜ [Service_Detection.md](Network_Enumeration_With_Nmap/Service_Detection.md)
- ⬜ [NSE_Scripts.md](Network_Enumeration_With_Nmap/NSE_Scripts.md)
- ⬜ [Firewall_IDS_Evasion.md](Network_Enumeration_With_Nmap/Firewall_IDS_Evasion.md)

**Week 3-4: Next Module** *(Placeholder for upcoming modules)*
- Vulnerability Assessment
- Web Application Enumeration
- Privilege Escalation

---

## 🔍 Command Reference Quick Links

**Nmap Commands:**
- Basic scans, port ranges, service detection → [Service_Scanning_Enumeration.md](Foundation/Service_Scanning_Enumeration.md#nmap---network-mapping--port-scanning)
- Host discovery techniques → [Host_Discovery.md](Network_Enumeration_With_Nmap/Host_Discovery.md)

**Service Enumeration:**
- FTP, SMB, SNMP, HTTP → [Service_Scanning_Enumeration.md](Foundation/Service_Scanning_Enumeration.md)

**Post-Exploitation:**
- Transferring files → [File_Transfer.md](Foundation/File_Transfer.md)
- Escalating privileges → [Privilege_Escalation.md](Foundation/Privilege_Escalation.md)

---

## 📝 Notes for Users

- **Print/Bookmark:** Consider printing or bookmarking the Foundation guides for quick offline reference
- **Mobile Access:** All markdown files can be viewed on mobile for field reference
- **Git History:** Check commit history for when each section was completed
- **Updates:** New module sections added regularly as CPTS academy modules are completed

---

## 📂 Directory Structure

```
06-REFERENCE_GUIDES/
│
├── README.md (this file)
│
├── Foundation/
│   ├── Enumeration_Process.md
│   ├── Service_Scanning_Enumeration.md
│   ├── Web_Enumeration.md
│   ├── File_Transfer.md
│   ├── Types_of_Shells.md
│   ├── Privilege_Escalation.md
│   ├── Public_Exploits.md
│   └── MASTER_ENUMERATION_CHEATSHEET.md
│
└── Network_Enumeration_With_Nmap/
    ├── Host_Discovery.md
    ├── Port_Scanning.md (coming)
    ├── Service_Detection.md (coming)
    ├── NSE_Scripts.md (coming)
    └── Firewall_IDS_Evasion.md (coming)
```

---

## 🎓 Learning Resources

- **Nmap Official Guide:** https://nmap.org/book/
- **CPTS Curriculum:** HackTheBox Academy
- **Related Writeups:** See `/01-FOUNDATIONAL/` and `/02-EASY/` for practical examples

---

**Last Updated:** February 9, 2026  
**Status:** Actively maintained with new modules added weekly

