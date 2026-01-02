# TryHackMe Learning Path - Notes & Writeups

## Overview
This folder contains comprehensive writeups and notes from my TryHackMe Junior Pentester learning path completion. Each writeup documents the techniques learned, attack chains used, vulnerabilities discovered, and lessons gained from each room.

**Status:** In Progress (14% complete as of Jan 2, 2026)  
**Target:** Complete Junior Pentester path by Mid-February 2026

---

## Completed Rooms

### Day 1 - Authentication Bypass
- **Date:** January 2, 2026
- **Difficulty:** Easy-Medium
- **Time:** 2-3 hours
- **Topics:** Username enumeration, password brute force, logic flaws, cookie manipulation, hash cracking
- **Key Techniques:** ffuf, curl, Base64 encoding, password cracking
- **File:** [Day_1_Authentication_Bypass.md](Day_1_Authentication_Bypass.md)

---

## Learning Path Overview

**Junior Pentester Path Progression:**
- Web Fundamentals
- Security Fundamentals
- Network Security
- Linux & System Administration
- Penetration Testing Tools
- Web Application Security
- Privilege Escalation
- Post-Exploitation
- Advanced Web Exploitation
- Red Team Operations

---

## Methodology

Each writeup follows this structure:

1. **Overview** - What the room teaches
2. **Skills Learned** - Technical abilities gained
3. **Attack Chain** - Phased exploitation walkthrough
4. **Tools & Resources** - What was used
5. **Challenges** - Problems encountered and solutions
6. **Vulnerabilities** - Security issues identified (CWE, CVSS)
7. **Lessons Learned** - Technical and methodology insights
8. **Tool Proficiency** - Skills improved

---

## Key Resources

### Wordlists (Kali Linux)
```
/usr/share/wordlists/SecLists/
├── Usernames/
├── Passwords/
├── Discovery/
└── Web-Content/
```

### Tools Mastered
- ffuf (web fuzzing)
- curl (HTTP requests)
- Burp Suite (web proxy)
- Browser DevTools
- Linux command line utilities

### References
- CWE (Common Weakness Enumeration) - vulnerability classification
- CVSS (Common Vulnerability Scoring System) - severity ratings
- OWASP Top 10 - web application vulnerabilities

---

## Progress Tracking

| Room | Difficulty | Date | Hours | Status |
|------|-----------|------|-------|--------|
| Authentication Bypass | Easy-Medium | Jan 2 | 2-3 | ✅ Complete |
| | | | | |

---

## Integration with Certification Path

**How THM fits into overall certifications:**

- **PNPT Prep (Jan-May):** THM + HackTheBox machines
- **OSCP Prep (May-Sept):** Harder HTB/Proving Grounds machines
- **CRTO Prep (Sept-Dec):** Red team scenarios + AD labs

**Portfolio Value:**
- Each completed room = 1 documented machine
- Target: 50-60 documented machines for PNPT readiness
- Demonstrates systematic methodology and tool proficiency

---

**Updated:** January 2, 2026  
**Next Update:** After Day 2 completion
