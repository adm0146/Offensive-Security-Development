# CPTS Progress Tracking

**Start Date:** February 1, 2026  
**Target Exam:** April 1-10, 2026  
**Total Hours:** 400 (40 hours/week for 10 weeks)  
**Machines to Complete:** 30+ vulnerable systems  

---

## Learning Path Integration Guide

**Foundation Phase (Jan 14-31):** Complete HTB Junior Pentester learning path  
Complete these modules BEFORE starting CPTS labs to ensure foundation knowledge:

- **Completed ✅:** Getting Started (25%)
- **Week 1 (Jan 21-27):** Pentesting Process + Core Security Concepts
- **Week 2 (Jan 28-31):** Web App Fundamentals + Common Web Vulnerabilities

### Machine Difficulty Recommendations by Learning Module

| Module Completion | Ready For | Box Target | Example Topics |
|-------------------|-----------|-----------|-----------------|
| Getting Started (25%) | Jan 15+ | None yet | Wait until Feb 1 |
| Pentesting Process (50%) | Jan 25+ | Easy boxes | Basic recon, simple exploitation |
| Core Security Concepts (65%) | Jan 29+ | Easy/Medium | HTTP, DNS, basic auth bypass |
| Web App Fundamentals (80%) | Feb 1+ | **START Easy machines** | Frontend/backend interaction |
| Common Web Vulns (90%) | Feb 8+ | **PROGRESS to Medium** | SQLi, XSS, command injection |
| Exploitation Techniques (100%) | Feb 15+ | **PROGRESS to Hard/AD** | File inclusion, privilege escalation |

---

## Weekly Progress

### Week 1-2 (Feb 1-14): Foundation
**Target:** 80 hours, 3-4 Easy machines  
**Modules:** Networking, Web Basics, Reconnaissance  
**Learning Path Status:** Web App Fundamentals COMPLETE + Starting Common Web Vulnerabilities (80%+)

**Box Guidance:** Easy machines focus on basic reconnaissance and simple web app vulnerabilities (parameter tampering, basic auth bypass, simple SQL injection). These correlate directly with "Web App Fundamentals" and early "Common Web Vulnerabilities" modules.

| Machine | Difficulty | Status | Date | Hours | Notes |
|---------|-----------|--------|------|-------|-------|
| [Name] | Easy | ⬜ Not Started | - | - | Focus: Basic recon + simple web vulnerability |
| [Name] | Easy | ⬜ Not Started | - | - | Focus: Parameter tampering/auth bypass |
| [Name] | Easy | ⬜ Not Started | - | - | Focus: Simple SQL injection or XSS |

**Weekly Summary:**
- Hours Used: __ / 80
- Machines Completed: __ / 3-4
- On Track: [ ] Yes [ ] No
- Learning Path Check: Ensure Common Web Vulns (SQLi/XSS/Auth) covered before tackling machines

---

### Week 3-4 (Feb 15-28): Intermediate
**Target:** 80 hours, 4-5 Medium machines  
**Modules:** Vulnerability Assessment, Exploitation  
**Learning Path Status:** Common Web Vulnerabilities COMPLETE (90%+) + Exploitation Techniques starting

**Box Guidance:** Medium machines introduce chained exploitation (multiple vulnerabilities in sequence), privilege escalation concepts, and more complex web app logic. By now you should understand SQLi, XSS, file uploads, and command injection deeply. Focus on combining techniques.

| Machine | Difficulty | Status | Date | Hours | Notes |
|---------|-----------|--------|------|-------|-------|
| [Name] | Medium | ⬜ Not Started | - | - | Focus: Chained vulns (recon → SQLi → privesc) |
| [Name] | Medium | ⬜ Not Started | - | - | Focus: File upload + execution chain |
| [Name] | Medium | ⬜ Not Started | - | - | Focus: Complex auth bypass + access control |

**Weekly Summary:**
- Hours Used: __ / 80
- Machines Completed: __ / 4-5
- On Track: [ ] Yes [ ] No
- Learning Path Check: Exploitation Techniques modules should be complete before tackling chains

---

### Week 5-6 (Mar 1-14): Advanced
**Target:** 80 hours, 5-6 Medium/Hard machines  
**Modules:** Privilege Escalation (Linux/Windows), Post-Exploitation  
**Learning Path Status:** All modules COMPLETE (100%) + Advanced Topics optional

**Box Guidance:** Hard machines emphasize privilege escalation chains, post-exploitation, and real-world complexity. By this point, Junior Pentester learning is complete and you've seen all fundamental exploitation techniques. Focus on privilege escalation paths (kernel exploits, configuration issues, credential reuse).

| Machine | Difficulty | Status | Date | Hours | Notes |
|---------|-----------|--------|------|-------|-------|
| [Name] | Medium | ⬜ Not Started | - | - | Focus: Linux privilege escalation |
| [Name] | Hard | ⬜ Not Started | - | - | Focus: Windows privilege escalation |
| [Name] | Hard | ⬜ Not Started | - | - | Focus: Post-exploitation + persistence |

**Weekly Summary:**
- Hours Used: __ / 80
- Machines Completed: __ / 5-6
- On Track: [ ] Yes [ ] No
- Learning Path Check: All fundamentals should be internalized; focus on technique combinations

---

### Week 7-8 (Mar 15-28): Active Directory
**Target:** 80 hours, 4-5 AD/Hard machines  
**Modules:** Active Directory, Complex Networks  
**Learning Path Status:** All HTB Junior Pentester modules complete; CPTS-specific AD training active

**Box Guidance:** AD machines are highly specialized—focus on Kerberos exploitation, trust relationships, group policies, and domain privilege escalation. These are NOT covered in Junior Pentester, but build on all your exploitation fundamentals. Approach each AD box methodically (enum → bloodhound analysis → attack path).

| Machine | Difficulty | Status | Date | Hours | Notes |
|---------|-----------|--------|------|-------|-------|
| [Name] | Hard | ⬜ Not Started | - | - | Focus: Kerberos + ASREP Roasting |
| [Name] | Hard | ⬜ Not Started | - | - | Focus: Trust relationships + delegation |
| [Name] | Hard | ⬜ Not Started | - | - | Focus: Domain privilege escalation |

**Weekly Summary:**
- Hours Used: __ / 80
- Machines Completed: __ / 4-5
- On Track: [ ] Yes [ ] No
- AD-Specific: Use BloodHound heavily, map trust chains, practice Kerberos exploitation

---

### Week 9 (Mar 29-Apr 4): Mock Exam & Review
**Target:** 40-50 hours, Final practice + weak area review

| Activity | Target | Status | Hours | Notes |
|----------|--------|--------|-------|-------|
| Mock Exam Simulation | 8-12 hrs | ⬜ | - | Practice test scenario |
| Weak Area Review | 20 hrs | ⬜ | - | Review difficult concepts |
| Reporting Practice | 10 hrs | ⬜ | - | Polish report quality |
| Tool Mastery | 5 hrs | ⬜ | - | Finalize tool configs |

**Weekly Summary:**
- Hours Used: __ / 50
- Status: [ ] Ready [ ] Need more prep

---

### Week 10 (Apr 5-10): CPTS Exam
**Activity:** 10-day lab-based practical exam

| Day | Activity | Status | Notes |
|-----|----------|--------|-------|
| Apr 1 | Exam begins | ⬜ | Start reconnaissance |
| Apr 2 | Active testing | ⬜ | Exploitation phase |
| Apr 3-4 | Active testing | ⬜ | Continue chains |
| Apr 5-8 | Exploitation | ⬜ | Final systems |
| Apr 9 | Report prep | ⬜ | Professional writeup |
| Apr 10 | Report final | ⬜ | Submit before deadline |

---

## Overall Progress Summary

### Month Totals

**February 2026**
- Target Hours: 160 (40/week × 4 weeks)
- Actual Hours: __ / 160
- Machines: __ / 7-9
- Completion: __%

**March 2026**
- Target Hours: 160 (40/week × 4 weeks)
- Actual Hours: __ / 160
- Machines: __ / 9-11
- Completion: __%

**April 2026** (Partial)
- Target Hours: 80 (40/week × 2 weeks + exam)
- Actual Hours: __ / 80
- Machines: __ / 5-7
- Exam: [ ] Passed [ ] Pending

---

## Machine Completion Tracker

### Easy Machines (Target: 8-10)
- [ ] Machine 1 - __ hrs - [Link to writeup]
- [ ] Machine 2 - __ hrs - [Link to writeup]
- [ ] Machine 3 - __ hrs - [Link to writeup]
- [ ] Machine 4 - __ hrs - [Link to writeup]
- [ ] Machine 5 - __ hrs - [Link to writeup]
- [ ] Machine 6 - __ hrs - [Link to writeup]
- [ ] Machine 7 - __ hrs - [Link to writeup]
- [ ] Machine 8 - __ hrs - [Link to writeup]

**Easy Status:** __ / 8

---

### Medium Machines (Target: 10-12)
- [ ] Machine 1 - __ hrs - [Link to writeup]
- [ ] Machine 2 - __ hrs - [Link to writeup]
- [ ] Machine 3 - __ hrs - [Link to writeup]
- [ ] Machine 4 - __ hrs - [Link to writeup]
- [ ] Machine 5 - __ hrs - [Link to writeup]
- [ ] Machine 6 - __ hrs - [Link to writeup]
- [ ] Machine 7 - __ hrs - [Link to writeup]
- [ ] Machine 8 - __ hrs - [Link to writeup]
- [ ] Machine 9 - __ hrs - [Link to writeup]
- [ ] Machine 10 - __ hrs - [Link to writeup]

**Medium Status:** __ / 10

---

### Hard Machines (Target: 8-10)
- [ ] Machine 1 - __ hrs - [Link to writeup]
- [ ] Machine 2 - __ hrs - [Link to writeup]
- [ ] Machine 3 - __ hrs - [Link to writeup]
- [ ] Machine 4 - __ hrs - [Link to writeup]
- [ ] Machine 5 - __ hrs - [Link to writeup]
- [ ] Machine 6 - __ hrs - [Link to writeup]
- [ ] Machine 7 - __ hrs - [Link to writeup]
- [ ] Machine 8 - __ hrs - [Link to writeup]

**Hard Status:** __ / 8

---

### Active Directory Focus (Target: 3-4)
- [ ] AD Machine 1 - __ hrs - [Link to writeup]
- [ ] AD Machine 2 - __ hrs - [Link to writeup]
- [ ] AD Machine 3 - __ hrs - [Link to writeup]
- [ ] AD Machine 4 - __ hrs - [Link to writeup]

**AD Status:** __ / 3

---

## Performance Metrics

### Speed Metrics
| Category | Target | Actual | Trend |
|----------|--------|--------|-------|
| Avg Easy Machine | 6-8 hrs | - | - |
| Avg Medium Machine | 8-10 hrs | - | - |
| Avg Hard Machine | 10-12 hrs | - | - |
| Avg AD Machine | 12-15 hrs | - | - |

### Skill Development

**Reconnaissance Skills**
- [ ] Nmap mastery
- [ ] Service enumeration
- [ ] Web app analysis
- [ ] Information gathering

**Exploitation Skills**
- [ ] Web vulnerabilities
- [ ] RCE techniques
- [ ] Custom exploits
- [ ] Metasploit proficiency

**Privilege Escalation**
- [ ] Linux vectors (100%)
- [ ] Windows vectors (100%)
- [ ] OPSEC techniques
- [ ] Post-exploitation

**Active Directory**
- [ ] ASREP Roasting
- [ ] Kerberoasting
- [ ] Lateral movement
- [ ] Domain domination

---

## Weak Areas & Focus

### Areas to Improve
1. [Skill/Topic] - Need more practice
2. [Skill/Topic] - Got stuck on this
3. [Skill/Topic] - Took too long

### Extra Practice Scheduled
- [ ] Re-do Machine X for speed
- [ ] Study [Technique] deeper
- [ ] Practice [Exploit type] more
- [ ] Review [Module] videos

---

## Exam Preparation Readiness

### Readiness Checklist (Track weekly)

**End of Week 2:**
- [ ] Foundation modules completed
- [ ] 3-4 Easy machines done
- [ ] Reporting format established
- [ ] Comfortable with tools

**End of Week 4:**
- [ ] Intermediate modules done
- [ ] 7-9 machines completed
- [ ] Speed improving
- [ ] Weak areas identified

**End of Week 6:**
- [ ] Advanced modules done
- [ ] 16-20 machines completed
- [ ] Exploitation techniques solid
- [ ] Reporting quality high

**End of Week 8:**
- [ ] AD modules complete
- [ ] 25+ machines done
- [ ] Ready for complex scenarios
- [ ] Confident and prepared

**Before Week 10 Exam:**
- [ ] All systems practiced
- [ ] Mock exam passed
- [ ] Weak areas reinforced
- [ ] Ready to execute

---

## Notes & Observations

### Week-by-Week Learnings
**Week 1-2:**
- 

**Week 3-4:**
- 

**Week 5-6:**
- 

**Week 7-8:**
- 

---

## HTB Learning Path → CPTS Machine Mapping

### Foundation (Jan 14-31): Before Starting CPTS
**HTB Junior Pentester modules build the knowledge base for all CPTS boxes.**

- **Module 1: Getting Started** → Understand HTB platform mechanics
- **Module 2: Pentesting Process** → Learn full penetration testing methodology
- **Module 3: Core Security Concepts** → Master networking, HTTP, DNS fundamentals
- **Module 4: Web App Fundamentals** → Understand frontend/backend/database architecture
- **Module 5: Common Web Vulnerabilities** → Deep dive into SQLi, XSS, auth bypass
- **Module 6: Exploitation Techniques** → Learn file inclusion, uploads, command injection
- **Module 7: Advanced Topics** → OWASP Top 10, additional techniques (optional but recommended)

### CPTS Machines: Progression Strategy

**Week 1-2 (Feb 1-14): Easy Machines - Direct Application of Junior Pentester**
- ✅ Prerequisites: Modules 1-4 complete (Getting Started → Web App Fundamentals)
- 📍 What they test: Basic web app vulnerabilities learned in Common Web Vulnerabilities (intro phase)
- 🎯 Typical attack chain: Simple recon → single vulnerability → shell → exit
- 📊 Expected time: 6-8 hours per machine
- 💡 Skills: Basic enumeration, simple SQLi/XSS, parameter tampering, basic auth bypass

**Week 3-4 (Feb 15-28): Medium Machines - Chained Exploitation**
- ✅ Prerequisites: Modules 5-6 complete (Common Web Vulnerabilities + Exploitation Techniques)
- 📍 What they test: Combining multiple vulnerabilities, privilege escalation concepts
- 🎯 Typical attack chain: Recon → web app access → internal exploitation → privilege escalation → persistence
- 📊 Expected time: 8-10 hours per machine
- 💡 Skills: Chained vulnerabilities, Linux privesc, credential cracking, web app logic exploitation

**Week 5-6 (Mar 1-14): Hard Machines - Advanced Exploitation**
- ✅ Prerequisites: All learning modules complete (90-100%), 8-9 Easy/Medium machines done
- 📍 What they test: Complex exploitation chains, advanced privilege escalation, creative techniques
- 🎯 Typical attack chain: Complex recon → multiple web apps → lateral movement → privilege escalation → cover tracks
- 📊 Expected time: 10-12 hours per machine
- 💡 Skills: Advanced Linux/Windows privesc, kernel exploits, credential reuse, post-exploitation

**Week 7-8 (Mar 15-28): Active Directory - Specialized Knowledge**
- ✅ Prerequisites: All learning modules + 13-15 Easy/Medium/Hard machines completed
- 📍 What they test: Kerberos attacks, trust relationships, domain enumeration, lateral movement
- 🎯 Typical attack chain: Domain recon (Bloodhound) → Kerberos exploitation → trust abuse → domain admin → persistence
- 📊 Expected time: 12-15 hours per machine
- 💡 Skills: Kerberos exploitation (ASREP roasting, Kerberoasting), trust relationships, group policy abuse, Bloodhound analysis

---

## Quick Reference: Learning Path Readiness Checklist

Before attempting each box difficulty, ensure you've completed:

### ✅ Ready for EASY machines (Feb 1+)
- [ ] All "Getting Started" modules complete (25%)
- [ ] Pentesting Process modules complete (understand methodology)
- [ ] Core Security Concepts covered (HTTP, DNS, basic protocols)
- [ ] Web App Fundamentals covered (frontend/backend/database basics)
- [ ] At least 30% of "Common Web Vulnerabilities" (basic SQLi + XSS understanding)

### ✅ Ready for MEDIUM machines (Feb 15+)
- [ ] All Easy machines complete (3-4 done)
- [ ] "Common Web Vulnerabilities" 100% complete (SQLi, XSS, auth, file uploads)
- [ ] "Exploitation Techniques" 80%+ complete (file inclusion, command injection, access control)
- [ ] Can identify multiple vulnerabilities in a single application
- [ ] Comfortable with privilege escalation concepts

### ✅ Ready for HARD machines (Mar 1+)
- [ ] All Medium machines complete (7-9 total done)
- [ ] "Exploitation Techniques" 100% complete
- [ ] "Advanced Topics" review complete (OWASP context)
- [ ] Can chain 3+ vulnerabilities together
- [ ] Comfortable with Linux kernel exploit research and Windows privesc vectors

### ✅ Ready for ACTIVE DIRECTORY machines (Mar 15+)
- [ ] All Easy/Medium/Hard machines complete (13-15 total done)
- [ ] All Junior Pentester modules complete
- [ ] Active Directory reconnaissance tools studied (Bloodhound, PowerShell, impacket)
- [ ] Kerberos attack concepts understood (ASREP roasting, Kerberoasting, delegation)
- [ ] Ready for 4-5 week deep dive into AD-specific techniques

---

## How to Use This Integration

**Daily Workflow:**
1. Check `HTB_JUNIOR_PENTESTER_PROGRESS.md` for today's learning module
2. Complete the module during 7-9 AM study block
3. Check here (`CPTS_PROGRESS.md`) to see if you're ready for the next box difficulty
4. If ready, attempt next-level machine (afternoon/evening lab work)
5. Document box writeup in corresponding difficulty folder (01-EASY/, 02-MEDIUM/, etc.)
6. Update both progress files

**Weekly Sync:**
- Monday: Review learning path progress for the week
- Check if you're unlocking the next machine difficulty level
- Adjust box selection based on what you've learned
- Ensure learning modules are feeding directly into machine selection

**Strategic Checkpoint (Feb 1):**
- Complete HTB Junior Pentester 100% before starting CPTS
- This IS the required foundation; don't skip modules to get to machines faster
- Quality foundation = faster machine completion later

**Week 9:**
- 

---

## Success Indicators

✅ **On Track If:**
- Completing 3-4+ machines per week
- Each machine taking less time (speed improving)
- Quality writeups (500+ words each)
- Confident explaining methodology
- Only 1-2 gets on Hard machines

❌ **Behind If:**
- Less than 2 machines per week
- Spending 15+ hours on Easy machines
- Skipping or rushing writeups
- Getting frustrated with techniques
- Multiple fails on same vector

---

## Post-CPTS Goals

After April 10 exam:
- [ ] Celebrate completion!
- [ ] Rest/recovery (April 11-19)
- [ ] OSCP course access setup (April 20)
- [ ] PWK labs enrollment (May 1)
- [ ] OSCP intensive begins (May 20)

---

**Status:** Ready to Start (Feb 1, 2026)  
**Last Updated:** January 21, 2026  
**Next Update:** Weekly progress review
