# Offensive Security Development - 2026 Certification Pathway

A comprehensive guide and repository documenting my journey to **multiple advanced security certifications** in 2026:
- **Security+** ✅ (Jan 10 - PASSED 768/900, 85.3%)
- **CPTS** (Feb 1 - April 10)  
- **OSCP** (May 20 - Sept 26)
- **CRTO** (Sept 26 - Dec 15)

**Total Hours:** 2,678 hours across all certifications in 2026

---

## Repository Structure

```
offensive-security-development/
├── 00-roadmap/                    # Certification roadmaps & planning
│   ├── CPTS_PREPARATION_PLAN.md
│   ├── OSCP_PREPARATION_PLAN.md
│   ├── CRTO_PREPARATION_PLAN.md
│   └── INDEX.md
│
├── 00-archived/                   # Historical materials
│   └── Security_Plus_2026/        # Security+ study notes (completed)
│
├── 02-foundation/                 # Security+ reference materials
│   ├── Section_1.2_Security_Concepts.md
│   ├── Section_1.3_Change_Management.md
│   └── Section_1.4_Cryptographic_Solutions.md
│
├── 05-writeups/                   # Lab writeups & documentation
│   └── THM/                       # TryHackMe machines (current)
│       ├── README.md              # THM progress tracker
│       ├── Day_1_Authentication_Bypass.md
│       ├── Race_Conditions_Reference.md
│       ├── Command_Injection_Reference.md
│       └── Burp_Suite_Repeater_Guide.md
│
├── 08-reference-guides/           # Quick reference materials
│   ├── Kali_Docker_Quick_Guide.md
│   ├── QUICK_REFERENCE.md
│   └── Security+_SY0-701_Info.md
│
└── README.md (this file)
```

---

## 2026 Timeline (LOCKED IN)

### Phase 1: Security+ ✅ COMPLETE
- **Dates:** Jan 3-10, 2026
- **Result:** PASSED 768/900 (85.3%)
- **Materials:** `/02-foundation/` (study notes, reference guides)

### Phase 2: CPTS
- **Dates:** Feb 1 - April 10, 2026
- **Duration:** 400 hours
- **Course:** HackTheBox Academy Certified Penetration Tester Specialist
- **Format:** 10-day lab-based practical exam (April 1-10)
- **Pace:** 40 hours/week over 10 weeks
- **Spring Semester:** 12 credits (DROPPED Linear Algebra to maximize CPTS focus)
- **Plan:** [CPTS_PREPARATION_PLAN.md](00-roadmap/CPTS_PREPARATION_PLAN.md)

### Phase 3: OSCP
- **Dates:** May 20 - Sept 26, 2026
- **Duration:** 1,278 total hours
  - Jan 12 - May 9: 288 hours (foundational)
  - May 10 - Aug 16: 890 hours (intensive summer)
  - Aug 17 - Sept 26: 100 hours (pre-exam)
- **Course:** PwK (PEN-200), 70+ vulnerable machines
- **Format:** 24-hour proctored exam
- **Plan:** [OSCP_PREPARATION_PLAN.md](00-roadmap/OSCP_PREPARATION_PLAN.1md)

### Phase 4: CRTO
- **Dates:** Sept 26 - Dec 15, 2026
- **Duration:** 300 hours
- **Course:** Certified Red Team Operator (eLearnSecurity)
- **Focus:** Active Directory, C2 frameworks, red team operations
- **Format:** 24-hour practical exam
- **Plan:** [CRTO_PREPARATION_PLAN.md](00-roadmap/CRTO_PREPARATION_PLAN.md)

---

## Daily Discipline Protocol

**Non-Negotiable:**
- **5:00 - 6:00 AM** - Gym (mental clarity, stress relief)
- **7:00 - 9:00 AM** - Primary Study Block (daily, protected time)
- **8+ hours sleep** - Critical for retention and performance

**Lab Work:**
- Afternoon/Evening - 4-6 hours minimum on TryHackMe/HTB/PWK labs
- Document everything in writeups (portfolio quality)
- Use reference guides to learn faster

---

## Current Progress (Jan 14, 2026)

| Phase | Status | % Complete | Days Elapsed | Next Milestone |
|-------|--------|------------|--------------|----------------|
| Security+ | ✅ Complete | 100% | - | ✅ Completed Jan 10 |
| CPTS | ⏳ In Progress | 0% | - | 300-350 hours → April 1-10 exam |
| OSCP | ⏳ Not started | 0% | - | 1,278 hours → Sept 26 exam |
| CRTO | ⏳ Not started | 0% | - | 300 hours → Dec 15 exam |

**THM Progress:** 25% complete (targeting 100% by Jan 31)
**GitHub:** Organized and synced, ready for portfolio growth

---

## Study Materials

### Quick Reference Guides
Located in `/05-writeups/THM/`:
- **Race_Conditions_Reference.md** - TOCTOU vulnerabilities, exploitation, testing
- **Command_Injection_Reference.md** - Separators, payloads, blind injection techniques
- **Burp_Suite_Repeater_Guide.md** - Interface, workflows, race condition testing

Use these guides while doing labs to accelerate learning.

### Lab Writeups
All machine exploitation documents stored in `/05-writeups/THM/`:
- Portfolio-quality documentation (600+ lines per machine)
- Enumeration → Vulnerability → Exploitation → Lessons Learned format
- Screenshot evidence and command walkthroughs

### Historical Materials
- `/00-archived/Security_Plus_2026/` - Security+ study notes (for reference)
- `/02-foundation/` - Security+ markdown guides (for reference)

---

## Technical Stack

**Lab Environment:**
- Proxmox hypervisor with Kali Linux VM
- TryHackMe AttackBox integration
- OpenVPN for lab connectivity
- 2TB NVMe storage

**Documentation:**
- Markdown for all guides and writeups
- GitHub for version control and portfolio
- VS Code for editing

**Tools & Frameworks:**
- Burp Suite (web application testing)
- Nmap (network enumeration)
- Metasploit Framework
- Covenant C2 (CRTO phase)
- Custom Python/Bash scripts

---

## Goals & Strategy

### 2026 Goals
✅ Earn 4 advanced security certifications
✅ Build professional writeup portfolio (50+ machines)
✅ Master network penetration testing methodology
✅ Develop custom exploitation tools
✅ Position for Fort Meade/BAH CNO role

### Career Trajectory
- **2026:** Certifications + Portfolio building
- **Spring 2027:** Custom tool development (500 hours)
- **Summer 2027:** Job search begins
- **Target Role:** CNO (Chief Network Operations) at Fort Meade/BAH
- **Target Salary:** $120-150k entry specialist (negotiable to $140-170k)

### Competitive Advantages
- Rare skill combination: certs + leadership + developer background
- Leadership experience (sous chef, team of 12)
- Operations management background (orders, invoices, logistics)
- CS degree + cybersecurity focus
- Custom tool-building capability

---

## How to Use This Repository

1. **For Learning:** Follow the roadmap files in `/00-roadmap/` for each certification
2. **For Reference:** Check `/05-writeups/THM/` for quick guides and techniques
3. **For Tracking:** Monitor progress in `/05-writeups/THM/README.md`
4. **For Study:** Use `/02-foundation/` materials as Security+ reference
5. **For Portfolio:** Showcase writeups in `/05-writeups/THM/` to employers

---

## Commitment & Timeline

This is a structured, disciplined approach to earning 4 advanced certifications in a single year while maintaining daily gym routines and 8+ hours of sleep. The timeline is locked in and execution is underway.

**Status:** ✅ On track, executing Phase 1 → Phase 2 transition

---

**Last Updated:** January 14, 2026
**Next Update:** After PNPT course starts (Jan 15, 2026)
**Repository:** https://github.com/adm0146/Offensive-security-development (Private)
