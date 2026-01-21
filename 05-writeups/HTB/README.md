# HackTheBox Writeups & CPTS Preparation

**Learning Path:** CPTS (Certified Penetration Tester Specialist)  
**Current Focus:** HTB Academy labs (30+ vulnerable systems)  
**Target:** April 1-10, 2026 CPTS Exam
**Hours Allocated:** 400 total (40 hours/week for 10 weeks)

---

## Folder Structure

```
HTB/
├── README.md                          (this file)
├── CPTS_PROGRESS.md                  (progress tracking)
├── 00-FOUNDATION/                     (HTB Academy basics)
│   ├── Networking_Fundamentals.md
│   ├── Web_Application_Basics.md
│   ├── Reconnaissance_101.md
│   └── Vulnerability_Assessment_Guide.md
│
├── 01-EASY/                          (Easy difficulty machines)
│   ├── Machine_Name_Writeup.md
│   └── ...
│
├── 02-MEDIUM/                        (Medium difficulty machines)
│   ├── Machine_Name_Writeup.md
│   └── ...
│
├── 03-HARD/                          (Hard difficulty machines)
│   ├── Machine_Name_Writeup.md
│   └── ...
│
├── 04-EXPLOITATION/                  (Exploitation-focused)
│   ├── Web_Shells_RCE.md
│   ├── Privilege_Escalation_Linux.md
│   ├── Privilege_Escalation_Windows.md
│   └── Post_Exploitation.md
│
├── 05-ACTIVE_DIRECTORY/              (AD-specific labs)
│   ├── AD_Enumeration.md
│   ├── AD_Exploitation.md
│   └── Domain_Domination.md
│
└── 06-REFERENCE_GUIDES/              (Quick lookups)
    ├── HTB_Tools_Cheatsheet.md
    ├── Exploitation_Payloads.md
    ├── Privilege_Escalation_Vectors.md
    └── Reporting_Templates.md
```

---

## Writeup Template

Use this template for all machine writeups. Maintain consistency across all documents.

```markdown
# [Machine Name] - HTB Write-up

**Difficulty:** Easy / Medium / Hard  
**IP Address:** X.X.X.X  
**Operating System:** Linux / Windows  
**Exploited Vulnerabilities:** [List]  

---

## Reconnaissance

### Port Scanning
- Nmap output and analysis
- Open services identified
- Software versions discovered

### Service Enumeration
- Detailed service investigation
- Default credentials checked
- Configuration analysis

### Information Gathering
- Website structure (if applicable)
- Hidden files/directories found
- Interesting findings

---

## Vulnerability Analysis

### Identified Vulnerabilities
1. **Vulnerability Name**
   - Type: [XSS, SQL Injection, RCE, etc.]
   - Severity: [Critical, High, Medium, Low]
   - Description: Brief explanation
   - Evidence: Screenshots/output

### Attack Surface Analysis
- Entry points identified
- Privilege levels required
- Attack chain planned

---

## Exploitation

### Initial Access
- **Method:** [Describe how you gained initial access]
- **Command/Payload:** [Show exact commands used]
- **Output:** [Evidence of success]
- **Proof:** [Screenshot showing shell/access]

### Privilege Escalation
- **Vector:** [Explain the privilege escalation method]
- **Command/Payload:** [Exact commands]
- **Output:** [Evidence]
- **Proof:** [Screenshot showing elevated privileges]

---

## Post-Exploitation

### Persistence
- Mechanisms established
- Methods for re-access
- OPSEC considerations

### Data Exfiltration
- Data discovered
- Exfiltration method
- Flag capture

---

## Lessons Learned

1. **Key Technique 1:** What you learned and will use again
2. **Key Technique 2:** New exploitation method
3. **Common Mistake:** What you overcomplicated or missed
4. **Best Practice:** How to do this more efficiently next time

---

## Tools Used

| Tool | Purpose | Version |
|------|---------|---------|
| nmap | Port scanning | latest |
| Burp Suite | Web testing | Pro |
| [Tool] | [Purpose] | [Version] |

---

## Timeline

| Time | Activity | Result |
|------|----------|--------|
| 00:00 | Started reconnaissance | Found open ports |
| 00:15 | Enumerated services | Identified web app |
| 00:30 | Web app analysis | Found SQL injection |
| 01:00 | Gained initial access | Got www-data shell |
| 01:20 | Privilege escalation | Became root user |
| 01:30 | Captured flags | Machine complete |

---

## Additional Notes

- Any interesting observations
- Alternative exploitation methods
- Security hardening recommendations
- References/resources used
```

---

## Progress Tracking

### Completed Machines (0/30+)

- [ ] Machine 1
- [ ] Machine 2
- [ ] Machine 3

### In Progress

- [ ] Current machine

### Next Up

- [ ] Coming machines

---

## Quick Reference: Common Exploitation Techniques

### Web Application Attacks
- SQL Injection (SQLmap, manual)
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- File Upload Vulnerabilities
- Remote Code Execution (RCE)
- Server-Side Template Injection (SSTI)
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)

### System Exploitation
- Buffer Overflow (BOF)
- Format String Vulnerabilities
- Use-After-Free (UAF)
- Privilege Escalation (Linux/Windows)
- Kernel Exploits
- Misconfiguration Exploitation

### Active Directory Attacks
- ASREP Roasting
- Kerberoasting
- Pass-the-Hash
- Pass-the-Ticket
- Golden Ticket
- Silver Ticket
- Domain Domination

### Post-Exploitation
- Persistence mechanisms
- Lateral movement
- Data exfiltration
- Log cleanup
- Cover tracks

---

## Study Strategy

### Daily Workflow
1. **Morning (7-9 AM):** Watch HTB Academy modules, take notes
2. **Mid-day (9-11:30 AM):** Lab work, start reconnaissance
3. **Afternoon (3:50-5 PM):** Continue exploitation
4. **Evening (6-8 PM):** Complete machine, write writeup
5. **Review:** Read writeup next day for retention

### Weekly Goals
- **Week 1-2:** 3-4 Easy machines (foundation building)
- **Week 3-4:** 4-5 Medium machines (technique mastery)
- **Week 5-6:** 5-6 Hard machines (integration practice)
- **Week 7-8:** 3-4 AD machines (domain focus)
- **Week 9:** 2-3 Complex scenarios (pre-exam practice)
- **Week 10:** Mock exam / final review

### Success Metrics
✅ **Completion:** All 30+ machines attempted  
✅ **Documentation:** Quality writeups for 25+ machines  
✅ **Retention:** Can explain methodology without notes  
✅ **Speed:** Faster exploitation (optimize workflow)  
✅ **Thoroughness:** Catch all privilege escalation vectors  

---

## CPTS Exam Preparation

### Exam Format
- 10-day lab-based practical (April 1-10, 2026)
- Real vulnerable systems in HTB environment
- Black-box penetration testing scenarios
- Professional reporting required

### Pre-Exam Checklist
- [ ] All HTB Academy modules completed
- [ ] 25+ machines pwned with writeups
- [ ] Privilege escalation mastery (both OS)
- [ ] Active Directory chains practiced
- [ ] Post-exploitation techniques solid
- [ ] Reporting templates prepared
- [ ] Tools properly configured
- [ ] Notes organized and searchable

### Exam Strategy
1. **Start with reconnaissance** - Take your time, miss nothing
2. **Prioritize easy wins** - Low-hanging fruit first
3. **Build on success** - Use initial access for escalation chains
4. **Document everything** - Screenshots and commands as you go
5. **Don't rush** - 10-day window means pacing is key
6. **Report professionally** - Quality reporting = points
7. **OPSEC matters** - Evasion techniques count

---

## Resources

### HTB Academy
- [CPTS Learning Path](https://academy.hackthebox.com)
- Official course materials
- Lab access (30+ systems)
- Video walkthroughs (if stuck)

### External Resources
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [GTFOBins](https://gtfobins.github.io/) (privilege escalation)
- [LOLBAS](https://lolbas-project.github.io/) (Windows)
- [HackTricks](https://book.hacktricks.xyz)

### Tools Reference
- Burp Suite Pro
- Nmap
- Metasploit Framework
- Custom Python scripts
- Reverse shell generators

---

## Tips for Success

✅ **Write as you go** - Don't wait until the end to document  
✅ **Take screenshots** - Evidence of compromise is critical  
✅ **Copy commands** - Keep exact payloads for reproducibility  
✅ **Note timings** - Track how fast you solve each machine  
✅ **Review weak areas** - Spend extra time on difficult concepts  
✅ **Build muscle memory** - Repetition builds speed and accuracy  
✅ **Stay organized** - Folder structure = faster reference  
✅ **Test thoroughly** - Don't assume you have full access  

---

## Monthly Progress Summary

### February 2026
- [ ] Foundation modules completed
- [ ] 8-10 Easy machines pwned
- [ ] Initial writeups established
- [ ] Exploitation basics solid

### March 2026
- [ ] Medium/Hard machines ramping up
- [ ] Active Directory exposure
- [ ] Speed improving (faster per machine)
- [ ] Reporting quality refined

### April 2026
- [ ] Final review of weak areas
- [ ] Mock exam completed
- [ ] Ready for April 1-10 CPTS exam
- [ ] 30+ machines documented

---

## Contact & Questions

- Review notes daily for retention
- Reach out to HTB Academy community if stuck
- Reference PayloadsAllTheThings for techniques
- Use Google/HackTricks for quick lookups

---

**Status:** Ready to begin (Feb 1, 2026)  
**Last Updated:** January 21, 2026  
**Next Milestone:** Complete 3-4 Easy machines by mid-February
