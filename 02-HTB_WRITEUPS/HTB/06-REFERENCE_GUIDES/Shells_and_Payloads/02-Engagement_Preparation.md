# 02 — Engagement Preparation (Module Roadmap)

## Overview

This module uses a scenario: you work for **CAT5 Security** and must prove your shells & payloads skills before joining a live engagement against the client **Inlanefreight**. Each section builds toward a final challenge.

---

## Module Skill Checkpoints

| Section | Skill Being Tested | What You Need to Demonstrate |
|---------|-------------------|------------------------------|
| **Shell Basics** | Bind & reverse shells | Get a bind shell on Linux, reverse shell on Windows |
| **Payload Basics** | Payload creation & delivery | Launch from Metasploit, build from ExploitDB PoC, create custom payloads |
| **Getting a Shell on Windows** | Windows exploitation | Use recon results → craft payload → get a shell |
| **Getting a Shell on Linux** | Linux exploitation | Use recon results → craft payload → establish session |
| **Landing a Web Shell** | Web application attacks | Identify web app & language → deploy a web shell via browser |
| **Spotting a Shell or Payload** | Blue team / detection | Analyze host info to detect presence of shells or payloads |
| **Final Challenge** | Everything combined | Select, craft, deploy payloads → get shells → grab flags |

---

## The Attack Flow This Module Teaches

```
Recon Results (provided)
    ↓
Identify Target OS & Services
    ↓
Select/Craft Appropriate Payload
    ↓
Deliver Payload → Get Shell
    ↓
Extract Information (flags)
```

> This module skips enumeration (that's covered in earlier modules) and focuses entirely on the **exploitation → shell** phase.

---

## Key Takeaway

This is a **hands-on, lab-heavy module**. Every section ends with you actually popping a shell. The final challenge chains everything together — Windows shells, Linux shells, web shells, and detection.
