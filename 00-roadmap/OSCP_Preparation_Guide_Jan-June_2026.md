# 🔥 OSCP Preparation Guide: January - July 2026

**Certification**: Offensive Security Certified Professional (OSCP)  
**Course**: PEN-200: Penetration Testing with Kali Linux  
**Preparation Period**: January 6 - July 31, 2026 (207 days)  
**Exam Date**: July 31, 2026 (target)  
**Difficulty Level**: ⚠️ EXTREME (most challenging entry-level security cert)

---

## 🎯 What is OSCP?

### Overview
The OSCP is a **hands-on offensive security certification** that proves you can:
- Enumerate and exploit real systems
- Chain multiple vulnerabilities together
- Think like an attacker
- Document findings professionally
- Work under time pressure (23h 45m exam)

### Why OSCP Matters for Your Career
- 🔥 **Most respected entry-level pentesting cert**
- 🔥 **Signals hands-on capability** (not just theory)
- 🔥 **Major salary boost**: +$15k-$25k over Security+ alone
- 🔥 **Fidelity appeal**: Shows you're serious and capable
- 🔥 **Foundation for advanced certs**: OSEP, OSWE, OSED

### Exam Format
- **Duration**: 23 hours 45 minutes (hands-on exam)
- **Report**: Additional 24 hours to submit professional report
- **Machines**: 3 standalone machines + 1 Active Directory set (3 machines)
- **Passing Score**: 70 points out of 100
- **Pass Rate**: ~40-50% first attempt (varies by preparation)
- **Retake Fee**: $249 (plan to pass first time!)

### Point Breakdown
- **3 Standalone Machines**: 20 points each (60 total)
  - 10 points for initial foothold (low-privilege shell)
  - 10 points for privilege escalation (root/admin)
- **Active Directory Set**: 40 points (all-or-nothing)
  - Must compromise all 3 AD machines
  - Chain exploitation required

**Minimum to Pass**: 70 points
- Option A: All 3 standalone (60) + partial AD bonus (10+)
- Option B: 2 standalone fully (40) + full AD set (40) = 80 points
- **Strategy**: Focus on getting all 3 standalone, then AD

---

## 💰 Investment Required

### Course & Exam
- **PEN-200 with 90 days lab access**: $1,649
  - Includes: PDF manual, videos, 90 days lab access, 1 exam attempt
- **Extra lab time** (if needed): $20/day or packages
- **Exam retake** (if needed): $249

### Practice Platforms
- **Hack The Box VIP**: $14/month × 6 = $84
- **TryHackMe Premium**: $10/month × 6 = $60
- **Proving Grounds Practice**: $19/month × 3 = $57

### Books & Resources
- "The Web Application Hacker's Handbook" - $45
- "Penetration Testing" by Georgia Weidman - $35
- Misc resources/subscriptions - $50

### **Total Budget**: ~$2,100
- **Minimum**: $1,649 (just PEN-200)
- **Recommended**: $2,000-$2,200 (with practice platforms)

---

## 📅 6.5-Month Timeline Overview (REVISED!)

**Why 6.5 months instead of 5.5?**
- ✅ More realistic and sustainable pace
- ✅ Exam in summer (no academic conflicts!)
- ✅ Extra month for deeper learning
- ✅ Higher first-attempt pass rate
- ✅ Less burnout risk

### Phase 1: Foundation Building (January)
**Goal**: Master prerequisites before PWK course starts  
**Time**: 4 weeks, 15-20 hours/week (80 hours total)  
**Cost**: $24 (TryHackMe + HTB)

### Phase 2: PWK Course - Part 1 (February)
**Goal**: Complete course material (PDF + videos)  
**Time**: 4 weeks, 20-25 hours/week (100 hours total)  
**Cost**: None (using course material)

### Phase 3: PWK Labs - Start (March)
**Goal**: Enroll in PEN-200, begin lab machines  
**Time**: 4 weeks, 25-30 hours/week (110 hours total)  
**Cost**: $1,649 (PEN-200 enrollment with 90 days lab)

### Phase 4: PWK Labs - Intensive (April)
**Goal**: Compromise 50-70 machines, master pivoting  
**Time**: 4 weeks, 25-30 hours/week (110 hours total)  
**Cost**: None (within 90 days)

### Phase 5: PWK Labs - Mastery (May + Finals)
**Goal**: Continue labs alongside finals (flexible pacing)  
**Time**: 4 weeks, 20-30 hours/week (100 hours total)  
**Cost**: None (within 90 days)

### Phase 6: Summer Intensive (June)
**Goal**: Post-semester full-time OSCP preparation  
**Time**: 4 weeks, 40-50 hours/week (180 hours total)  
**Cost**: $57 (Proving Grounds Practice)

### Phase 7: Final Sprint & Exam (July 1-31)
**Goal**: Mock exams, exam attempt, report submission  
**Time**: 4 weeks, final push  
**Cost**: None (exam included)

**Total Study Hours**: 680-750 hours over 207 days
**Average**: 3.3-3.6 hours/day (very manageable!)
**Summer Boost**: 8-10 hours/day in June-July

---

## 🗓️ DETAILED MONTH-BY-MONTH PLAN

---

## JANUARY 2026: Foundation Building (Weeks 1-4)

**Objective**: Build prerequisite skills BEFORE starting PWK course  
**Study Time**: 15-20 hours/week  
**Cost**: $24 (THM + HTB subscriptions)

### Week 1: January 6-12 (Linux Mastery)

#### Daily Tasks (2-3 hours/day)
**Monday-Wednesday: Linux Fundamentals**
- TryHackMe: "Linux Fundamentals" path (3 rooms)
- Practice: File permissions (chmod, chown, chattr)
- Practice: User/group management
- Practice: Process management (ps, top, kill)
- Practice: Service management (systemctl, service)

**Thursday-Friday: Bash Scripting**
- TryHackMe: "Bash Scripting" room
- Write scripts: Port scanner, file organizer, log parser
- Practice: Variables, loops, conditionals, functions
- Practice: Reading files, command substitution

**Weekend: Linux Privilege Escalation Intro**
- TryHackMe: "Linux PrivEsc" room
- Understand: SUID/SGID binaries
- Understand: Sudo misconfigurations
- Understand: Cron jobs exploitation
- Understand: PATH hijacking

**Week 1 Deliverables**:
- [ ] Complete 3 TryHackMe rooms
- [ ] Write 3 bash scripts
- [ ] Document 5 privesc techniques
- [ ] Comfortable in Linux terminal

---

### Week 2: January 13-19 (Networking & Enumeration)

#### Daily Tasks (2-3 hours/day)
**Monday-Tuesday: Network Fundamentals**
- Review: OSI model, TCP/IP stack
- Review: Common ports (FTP, SSH, HTTP, SMB, RDP, etc.)
- TryHackMe: "Network Services" room
- Practice: Wireshark packet analysis

**Wednesday-Friday: Nmap Mastery**
- Master ALL Nmap scan types:
  - TCP Connect: `-sT`
  - SYN Stealth: `-sS`
  - UDP: `-sU`
  - Service/Version: `-sV`
  - OS Detection: `-O`
  - Script scan: `-sC` or `--script`
- Practice: Scan timing, firewall evasion
- TryHackMe: "Nmap" room (complete multiple times)

**Weekend: Web Enumeration**
- Tools: gobuster, dirbuster, ffuf
- Directory/file discovery
- Subdomain enumeration
- Virtual host discovery
- TryHackMe: "Content Discovery" room

**Week 2 Deliverables**:
- [ ] Can explain all Nmap scan types
- [ ] Comfortable with gobuster/ffuf
- [ ] Understand common ports/services
- [ ] Complete 2-3 TryHackMe rooms

---

### Week 3: January 20-26 (Web Application Attacks)

#### Daily Tasks (3-4 hours/day)
**Monday-Wednesday: SQL Injection**
- Theory: SQL injection basics, union-based, blind
- Practice: SQLi on intentionally vulnerable apps
- Tools: sqlmap basics
- PortSwigger Academy: SQL injection labs (FREE!)
  - Complete ALL SQLi labs (10-15 labs)

**Thursday-Friday: Web Shells & File Uploads**
- File upload vulnerabilities
- Web shell types (PHP, ASP, JSP)
- Bypassing upload restrictions
- TryHackMe: "Upload Vulnerabilities" room

**Weekend: Local File Inclusion (LFI) / Remote File Inclusion (RFI)**
- LFI exploitation techniques
- Log poisoning
- PHP filter chains
- RFI attacks
- TryHackMe: "File Inclusion" room

**Week 3 Deliverables**:
- [ ] Complete 10+ PortSwigger SQLi labs
- [ ] Successfully upload 3 different web shells
- [ ] Understand LFI/RFI exploitation
- [ ] Complete 3 web-focused rooms

---

### Week 4: January 27 - February 2 (Initial Practice Boxes)

#### Daily Tasks (3-4 hours/day)
**Monday-Friday: HackTheBox Easy Machines**
- Join Hack The Box (VIP subscription)
- Complete 5 "Easy" retired machines:
  1. **Lame** (classic, easy)
  2. **Legacy** (Windows, simple)
  3. **Blue** (EternalBlue)
  4. **Jerry** (Tomcat)
  5. **Bashed** (web shell)

**Documentation Practice**:
- Create detailed writeup for each box:
  - Enumeration steps
  - Exploitation process
  - Privilege escalation
  - Screenshots
  - Lessons learned

**Weekend: TryHackMe "OSCP Prep" Path Start**
- Begin TryHackMe's OSCP preparation path
- Focus on methodology development

**Week 4 Deliverables**:
- [ ] 5 HTB Easy machines rooted
- [ ] 5 detailed writeups completed
- [ ] Methodology template created
- [ ] Comfortable with HTB platform

**January Summary**:
- ✅ Linux fundamentals solid
- ✅ Nmap mastery achieved
- ✅ Web attacks understood
- ✅ First 5 HTB boxes completed
- ✅ Ready for PWK course

---

## FEBRUARY 2026: PWK Course Material (Weeks 5-8)

**Objective**: Complete PEN-200 PDF and video content  
**Study Time**: 20-25 hours/week  
**Cost**: None (not enrolled yet, using leaked/old materials for preview)  
**Note**: This is prep month BEFORE official enrollment

### Week 5: February 3-9 (Information Gathering)

#### Daily Tasks (3-4 hours/day)
**Monday-Wednesday: Passive Reconnaissance**
- Theory: OSINT techniques
- Tools: Google Dorking, theHarvester, Shodan
- DNS enumeration: nslookup, dig, host
- WHOIS information gathering
- Practice: Gather info on 3 target companies

**Thursday-Friday: Active Reconnaissance**
- Port scanning strategies
- Service enumeration techniques
- Banner grabbing
- Vulnerability scanning introduction (Nessus, OpenVAS)

**Weekend: HTB Practice**
- Complete 2 more HTB Easy boxes
- Focus on enumeration phase
- Document enumeration methodology

**Week 5 Deliverables**:
- [ ] OSINT toolkit ready
- [ ] Enumeration checklist created
- [ ] 2 HTB boxes completed
- [ ] 7 total HTB boxes rooted

---

### Week 6: February 10-16 (Vulnerability Assessment)

#### Daily Tasks (3-4 hours/day)
**Monday-Tuesday: Vulnerability Scanning**
- Nessus setup and usage
- OpenVAS basics
- Interpreting scan results
- Manual verification of findings

**Wednesday-Friday: Common Vulnerabilities**
- Study: CVE database, ExploitDB
- Practice: Searchsploit usage
- Understand: Common CVEs (EternalBlue, Shellshock, etc.)
- Metasploit: Basic usage (will minimize later, but know it)

**Weekend: Buffer Overflow Introduction**
- Theory: Stack-based buffer overflows
- Setup: Immunity Debugger, mona.py
- Practice: Simple vulnerable programs
- TryHackMe: "Buffer Overflow Prep" room (start)

**Week 6 Deliverables**:
- [ ] Can run and interpret vulnerability scans
- [ ] Comfortable with searchsploit
- [ ] Basic understanding of buffer overflows
- [ ] 2 more HTB boxes (9 total)

---

### Week 7: February 17-23 (Exploitation Techniques)

#### Daily Tasks (4-5 hours/day)
**Monday-Wednesday: Client-Side Attacks**
- Social engineering basics
- Malicious document creation
- HTA attacks
- Phishing simulations

**Thursday-Friday: File Transfer Techniques**
- Windows file transfer methods
- Linux file transfer methods
- Netcat usage
- Python HTTP servers

**Weekend: Buffer Overflow Deep Dive**
- TryHackMe: "Buffer Overflow Prep" room (complete)
- Practice: Finding EIP offset
- Practice: Finding bad characters
- Practice: Generating shellcode
- Practice: Final exploit creation

**Week 7 Deliverables**:
- [ ] Master file transfer techniques
- [ ] Complete buffer overflow prep room
- [ ] Successfully exploit 2 buffer overflow challenges
- [ ] 2 more HTB boxes (11 total)

---

### Week 8: February 24 - March 2 (Post-Exploitation Basics)

#### Daily Tasks (4-5 hours/day)
**Monday-Tuesday: Linux Privilege Escalation**
- Enumeration: linpeas.sh, LinEnum.sh
- SUID binary exploitation
- Sudo misconfigurations
- Kernel exploits (last resort)
- Cron job abuse

**Wednesday-Thursday: Windows Privilege Escalation**
- Enumeration: winPEAS, PowerUp.ps1
- Unquoted service paths
- Weak service permissions
- DLL hijacking
- Token impersonation

**Friday-Weekend: HTB Practice + Review**
- Complete 3 more HTB Easy boxes (focus on privesc)
- Review all February material
- Create master notes document

**Week 8 Deliverables**:
- [ ] Linux privesc checklist created
- [ ] Windows privesc checklist created
- [ ] 3 HTB boxes rooted (14 total)
- [ ] Ready for PWK enrollment

**February Summary**:
- ✅ PWK course material preview completed
- ✅ Buffer overflows understood
- ✅ Privilege escalation foundations solid
- ✅ 14 HTB Easy boxes completed
- ✅ Ready to enroll in PEN-200

---

## MARCH 2026: PWK Enrollment & Lab Start (Weeks 9-12)

**Objective**: Enroll in PEN-200, complete official material, start labs  
**Study Time**: 25-30 hours/week  
**Cost**: $1,649 (PEN-200 with 90 days lab access)  
**CRITICAL**: Enroll March 1st for 90-day lab access through May 30th

### Week 9: March 3-9 (PWK PDF & Videos - Part 1)

#### Daily Tasks (4-5 hours/day)
**🎯 ENROLL IN PEN-200 ON MARCH 1ST**

**Monday-Wednesday: Course Setup**
- Download all course materials
- Set up PEN-200 VPN connection
- Configure Kali Linux properly
- Read: Course introduction and methodology

**Wednesday-Friday: PWK Chapters 1-5**
- Chapter 1: Penetration Testing Introduction
- Chapter 2: Getting Comfortable with Kali Linux
- Chapter 3: Practical Tools
- Chapter 4: Bash Scripting
- Chapter 5: Passive Information Gathering
- Watch: Corresponding video modules (15-20 hours)

**Weekend: PWK Lab Introduction**
- Connect to PWK lab network
- Scan and enumerate "easy" machines
- Target: 2-3 easy lab machines
- Document everything in lab notes

**Week 9 Deliverables**:
- [ ] PEN-200 enrolled and set up
- [ ] Chapters 1-5 completed
- [ ] First 2-3 PWK lab machines compromised
- [ ] Lab documentation template created

---

### Week 10: March 10-16 (PWK PDF & Videos - Part 2)

#### Daily Tasks (4-5 hours/day)
**Monday-Wednesday: PWK Chapters 6-10**
- Chapter 6: Active Information Gathering
- Chapter 7: Vulnerability Scanning
- Chapter 8: Web Application Attacks
- Chapter 9: Introduction to Exploitation
- Chapter 10: File Transfers
- Watch: Video modules (20+ hours)

**Thursday-Friday: PWK Chapters 11-15**
- Chapter 11: Antivirus Evasion
- Chapter 12: Password Attacks
- Chapter 13: Windows Privilege Escalation
- Chapter 14: Linux Privilege Escalation
- Chapter 15: Port Redirection and Tunneling

**Weekend: PWK Lab Practice**
- Target: 5-8 more lab machines
- Focus on applying course concepts
- Running total: 7-11 machines

**Week 10 Deliverables**:
- [ ] Chapters 6-15 completed
- [ ] 5-8 lab machines rooted (10+ total)
- [ ] Course exercises completed
- [ ] Lab documentation updated

---

### Week 11: March 17-23 (PWK Advanced Topics & Labs)

#### Daily Tasks (5-6 hours/day)
**Monday-Tuesday: PWK Chapters 16-18**
- Chapter 16: The Metasploit Framework
- Chapter 17: Client-Side Attacks
- Chapter 18: Buffer Overflows (Windows)
- Complete all chapter exercises

**Wednesday-Friday: PWK Lab Intensive**
- Target: 10-15 machines this week
- Mix of difficulty levels
- Practice documentation
- Lab total: 20-25 machines

**Weekend: Active Directory Introduction**
- PWK AD module content
- Understand: AD structure, trust relationships
- Practice: AD enumeration techniques
- Begin AD lab network

**Week 11 Deliverables**:
- [ ] All PWK chapters completed
- [ ] 10-15 lab machines rooted (25 total)
- [ ] AD enumeration practiced
- [ ] Strong momentum established

---

### Week 12: March 24-30 (PWK Lab Domination)

#### Daily Tasks (5-6 hours/day)
**Monday-Friday: Lab Machine Grind**
- Target: 15-20 machines this week
- Include some "medium" difficulty machines
- Practice: Pivoting through networks
- Practice: Multiple exploitation paths
- Lab total: 40-45 machines

**Weekend: First Lab Report Draft**
- Create professional penetration test report
- Include: 10 best machines with full details
- Practice: Executive summary writing
- Practice: Technical documentation

**Week 12 Deliverables**:
- [ ] 15-20 machines rooted (40-45 total)
- [ ] First draft of lab report
- [ ] Pivoting techniques mastered
- [ ] Comfortable with lab environment

**March Summary**:
- ✅ PEN-200 enrolled ($1,649 invested)
- ✅ All course material completed
- ✅ 40-45 PWK lab machines rooted
- ✅ Lab documentation strong
- ✅ 55 days of lab time remaining

---

## APRIL 2026: PWK Labs - Advanced (Weeks 13-16)

**Objective**: Master PWK labs, focus on harder machines & AD  
**Study Time**: 30-35 hours/week  
**Cost**: None (within 90-day lab access)  
**Lab Time Remaining**: 55 days at start of April

### Week 13: April 1-6 (Medium/Hard Machines)

#### Daily Tasks (5-6 hours/day)
**Monday-Friday: Challenge Yourself**
- Target: 10-15 medium difficulty machines
- Time-box attempts: 4 hours max per machine
- If stuck: Research, ask forum hints (don't look at full walkthrough)
- Lab total: 55-60 machines

**Weekend: Active Directory Chain**
- Focus on AD lab network
- Practice: BloodHound enumeration
- Practice: Kerberos attacks (Kerberoasting, AS-REP roasting)
- Practice: Lateral movement techniques

**Week 13 Deliverables**:
- [ ] 10-15 machines rooted (60 total)
- [ ] Time management improving
- [ ] AD attack paths identified
- [ ] BloodHound data collected

---

### Week 14: April 7-13 (Active Directory Deep Dive)

#### Daily Tasks (5-7 hours/day)
**Monday-Friday: AD Exploitation**
- Compromise AD lab network (3-5 machines)
- Practice: Pass-the-Hash, Pass-the-Ticket
- Practice: DCSync, Golden Ticket
- Practice: Domain controller compromise
- Document AD attack chain thoroughly

**Weekend: Pivoting Mastery**
- Practice: SSH tunneling, port forwarding
- Practice: Proxychains configuration
- Practice: Chisel, sshuttle usage
- Compromise machines only reachable via pivot

**Week 14 Deliverables**:
- [ ] AD lab network compromised
- [ ] AD attack chain documented
- [ ] Pivoting techniques solid
- [ ] 5-10 more machines (65-70 total)

---

### Week 15: April 14-20 (Weak Areas & Consistency)

#### Daily Tasks (5-7 hours/day)
**Monday-Tuesday: Identify Weak Areas**
- Review all lab notes
- What machine types are hardest?
- What techniques need more practice?
- Create targeted practice plan

**Wednesday-Friday: Focused Practice**
- Practice weak areas intensively
- Re-attempt machines you struggled with
- Time-box: Can you root previous machines faster?

**Weekend: New Machines**
- Target: 10 more machines
- Mix of difficulties
- Lab total: 75-80 machines

**Week 15 Deliverables**:
- [ ] Weak areas addressed
- [ ] 10 machines rooted (80 total)
- [ ] Speed and confidence improving
- [ ] Methodology polished

---

### Week 16: April 21-27 (Final PWK Lab Push)

#### Daily Tasks (5-7 hours/day)
**Monday-Friday: Final Machines**
- Target: Remaining machines (aim for 85-90 total)
- Document everything
- Update lab report
- Lab access ends ~May 30 (30+ days remaining)

**Weekend: Mock Exam Prep**
- Review TJ Null's OSCP list (HTB/Proving Grounds)
- Plan May practice strategy
- Order Proving Grounds Practice subscription

**Week 16 Deliverables**:
- [ ] 85-90 PWK lab machines rooted
- [ ] Comprehensive lab report
- [ ] Methodology refined
- [ ] Ready for external practice platforms

**April Summary**:
- ✅ 85-90 PWK lab machines compromised
- ✅ Active Directory mastered
- ✅ Pivoting comfortable
- ✅ Lab report professional-quality
- ✅ 30 days of lab access remaining for May review

---

## MAY 2026: Continued Labs + Finals Balance (Weeks 17-20)

**Objective**: Balance PWK labs with end of spring semester  
**Study Time**: 20-30 hours/week (flexible for finals)  
**Cost**: None (within 90-day lab access)  
**Lab Time Remaining**: 30 days at start, ends ~May 30

### Week 17: May 1-4 (Lab Review)

#### Daily Tasks (4-6 hours/day)
**Monday-Thursday: PWK Lab Revisits**
- Revisit difficult machines from earlier
- Ensure you can root them faster now
- Fill in any gaps in lab completion
- Target: 5-10 more machines (90-95 total)

**Weekend: Finals Prep Balance**
- Academic priorities as needed
- Light OSCP maintenance
- Flashcard review

**Week 17 Deliverables**:
- [ ] 5-10 PWK machines completed (90-95 total)
- [ ] Balanced with school responsibilities
- [ ] Methodology still fresh

---

### Week 18: May 5-11 (Finals Week Flexibility)

#### Daily Tasks (Flexible - prioritize finals!)
**Monday-Friday: Academic Focus**
- Finals preparation priority
- Light OSCP review (1-2 hours/day)
- Privilege escalation cheat sheet review
- No intensive new material

**Weekend: OSCP Maintenance**
- Review PWK notes
- Update lab documentation
- Plan June intensive strategy

**Week 18 Deliverables**:
- [ ] Finals completed successfully
- [ ] OSCP skills maintained
- [ ] No burnout
- [ ] Ready for June intensive

---

### Week 19: May 12-18 (Post-Finals Recovery)

#### Daily Tasks (3-5 hours/day)
**Monday-Friday: Light Ramp-Up**
- Semester is over - decompress!
- Revisit 3-5 PWK machines
- Review all AD notes
- Prepare for June full-time study

**Weekend: Planning & Rest**
- Finalize June study schedule
- Budget for Proving Grounds
- Mental preparation
- Enjoy freedom from classes!

**Week 19 Deliverables**:
- [ ] Semester complete ✅
- [ ] OSCP transition planned
- [ ] Mentally refreshed
- [ ] Ready for June intensity

---

### Week 20: May 19-25 (Soft Start to Summer)

#### Daily Tasks (4-6 hours/day)
**Monday-Friday: Buffer Overflow Review**
- Complete buffer overflow refresher
- Ensure BOF takes < 90 minutes
- Practice multiple BOF challenges
- Get timing consistent

**Weekend: PWK Lab Final Access**
- Last weekend with PWK lab access (ends ~May 30)
- Revisit favorite/most valuable machines
- Final AD practice
- Export all notes and screenshots

**Week 20 Deliverables**:
- [ ] Buffer overflows refreshed
- [ ] All PWK lab notes backed up
- [ ] Lab access concludes May 30
- [ ] Easing into full-time summer mode

**May Summary**:
- ✅ Spring semester completed successfully
- ✅ PWK lab access concluded (90-95 machines total)
- ✅ Finals balanced with cert prep
- ✅ Buffer overflows refreshed
- ✅ Ready for June full-time intensive

---

## JUNE 2026: Summer Intensive (Weeks 21-25)

#### Daily Tasks (6-8 hours/day)
**Monday-Wednesday: First Mock Exam**
- Select 4 machines (OSCP point distribution):
  - 1 "Easy" Windows (20 pts)
  - 1 "Medium" Linux (20 pts)
  - 1 "Medium" Windows (20 pts)
  - 1 AD set simulation (40 pts - if available)
- Time limit: 24 hours
- Full documentation and reporting

**Thursday-Friday: Mock Exam Review**
- What went well?
- What needs improvement?
- Speed issues?
- Documentation issues?

**Weekend: Targeted Practice**
- Practice weak areas identified in mock exam
- 5 more practice machines

**Week 19 Deliverables**:
- [ ] First mock exam completed
- [ ] Mock exam report written
- [ ] Weak areas identified
- [ ] Improvement plan created

---

### Week 20: May 19-25 (Second Mock Exam)

#### Daily Tasks (6-8 hours/day)
**Monday-Wednesday: Second Mock Exam**
- Another mock exam with different machines
- Strict time limit: 23 hours 45 minutes
- Full report in 24 hours after "exam"

**Thursday-Friday: Review & Adjust**
- Compare mock exam #1 vs #2
- Are you faster?
- Is methodology solid?
- Is reporting faster?

**Weekend: Final Practice Machines**
- 5 more practice machines
- Focus on speed and efficiency
- Total external machines: 35-40

**Week 20 Deliverables**:
- [ ] Second mock exam completed
- [ ] Significant improvement shown
- [ ] Report template perfected
- [ ] Confidence high

---

### Week 21: May 26-31 (Final Prep & Review)

#### Daily Tasks (4-6 hours/day - lighter week)
**Monday-Wednesday: PWK Lab Review**
- Revisit PWK labs (last week of access)
- Review difficult machines
- Ensure AD methodology solid
- Final lab notes cleanup

**Thursday-Friday: Rest & Light Review**
- Review cheat sheets
- Review privilege escalation checklists
- Review buffer overflow notes
- Mental preparation

**Weekend (May 31 - June 1): Relax**
- Take Saturday off completely
- Sunday: Light flashcard review
- Early bedtime
- Exam scheduled for June 15 (2 weeks away)

**Week 21 Deliverables**:
- [ ] PWK lab access concluded (May 30)
- [ ] All notes organized
- [ ] Cheat sheets ready
- [ ] Report template finalized
- [ ] Mental state: Confident and rested

**May Summary**:
- ✅ 35-40 external OSCP-like machines rooted
- ✅ 2 full mock exams completed
- ✅ Buffer overflows mastered
- ✅ Reporting template perfected
- ✅ Ready for real exam

---

## JUNE 2026: Final Sprint & EXAM (Weeks 22-24)

**Objective**: Final preparation, exam attempt, report submission  
**Study Time**: Variable (lighter leading up to exam)  
**Exam Date**: June 15, 2026 (Sunday, 8:00 AM start)

### Week 22: June 1-7 (Light Practice)

#### Daily Tasks (3-4 hours/day)
**Monday-Friday: Maintenance Practice**
- 1 machine per day (easy/medium)
- Keep skills sharp but don't burn out
- Focus on speed and methodology
- 5 more machines total

**Weekend: Rest & Review**
- Review privilege escalation cheat sheets
- Review buffer overflow steps
- Review common exploits
- No stressful practice

**Week 22 Deliverables**:
- [ ] 5 maintenance machines completed
- [ ] Skills sharp
- [ ] Not burned out
- [ ] Excitement building

---

### Week 23: June 8-14 (Exam Week Prep)

#### Daily Tasks (2-3 hours/day)
**Monday-Tuesday: Final Light Practice**
- 1 easy machine each day
- Confirm VPN access works
- Test OffSec exam portal login

**Wednesday: Cheat Sheet Final Review**
- Linux privilege escalation checklist
- Windows privilege escalation checklist
- Buffer overflow methodology
- Port/service enumeration checklist

**Thursday: Logistics & Prep**
- Confirm exam appointment: June 15, 8:00 AM
- Prepare workspace: Clean desk, good lighting
- Prepare snacks: Energy bars, water, caffeine
- Prepare breaks: Walk route, stretch plan
- Set up: Multiple alarms, backup power

**Friday (June 13): Light Day**
- 1-hour light review
- Walk outside, exercise
- Social time with friends
- Early bedtime (9 PM)

**Saturday (June 14): Rest Day**
- NO STUDYING
- Watch a movie, relax
- Light walk outside
- Prepare meals for exam day
- Organize desk and equipment
- Bedtime: 8:00 PM (get 10+ hours sleep)

---

### 🎯 EXAM DAY: Sunday, June 15, 2026

#### Pre-Exam Routine
**6:00 AM**: Wake up naturally (10 hours sleep)
**6:15 AM**: Light breakfast (avoid heavy food)
**6:30 AM**: Shower, dress comfortably
**6:45 AM**: Review quick checklist (not intensive study!)
**7:00 AM**: Set up desk, water, snacks
**7:30 AM**: Connect to VPN, verify portal access
**7:45 AM**: Breathing exercises, positive mindset
**8:00 AM**: 🔥 **EXAM START** 🔥

---

#### Exam Strategy (8:00 AM - 7:45 AM next day)

**Phase 1: Enumeration (Hours 0-3)**
- **All machines simultaneously**:
  - Run AutoRecon or manual nmap on all machines
  - While scans run, start web enumeration
  - Take detailed notes of all findings
  - Prioritize targets based on enumeration

**Phase 2: Low-Hanging Fruit (Hours 3-8)**
- **Target: Buffer Overflow machine first** (if present)
  - Should take 1-2 hours max
  - Easy 20 points
  - Confidence booster

- **Target: Easiest standalone machine**
  - Aim for both user and root
  - Full 20 points

**Break**: 30 minutes - Walk, eat, hydrate

**Phase 3: Second Standalone (Hours 8-12)**
- Focus on second easiest machine
- Aim for both flags (20 points)
- Take thorough screenshots
- Current target: 40-60 points

**Break**: 30-60 minutes - Lunch, walk, rest eyes

**Phase 4: Third Standalone (Hours 12-16)**
- Third standalone machine
- At minimum, get low-priv shell (10 points)
- Push for root (full 20 points)
- Current target: 50-80 points

**Break**: 30 minutes - Dinner, walk

**Phase 5: Active Directory Set (Hours 16-22)**
- If you have 40+ points already, push for AD
- AD is all-or-nothing (40 points)
- Enumerate all 3 machines
- Find attack path
- Chain exploitation

**Break**: As needed, don't skip!

**Phase 6: Cleanup & Verification (Hours 22-23.75)**
- Verify all flags are correct
- Retake missing screenshots
- Organize notes
- Final attempt on any incomplete machines
- **Don't give up until timer expires!**

**7:45 AM (Friday, August 1)**: Exam ends, VPN disconnected

---

#### Post-Exam: Report (Next 24 hours)

**Friday, August 1: Report Day**

**8:00 AM - 10:00 AM**: Rest, breakfast, decompress (you've earned it!)
**10:00 AM - 2:00 PM**: 
- Organize screenshots
- Fill in report template
- Executive summary
- Technical walkthrough for each machine

**2:00 PM - 3:00 PM**: Lunch break

**3:00 PM - 7:00 PM**:
- Complete technical details
- Ensure all exploits documented
- Include remediation recommendations
- Proofread everything

**7:00 PM - 8:00 PM**: 
- Final proofread
- Export to PDF
- Verify file size and format
- **SUBMIT REPORT**

**8:00 PM+**: Celebrate! 🎉

---

### Week 31: August 1-7 (Post-Exam Recovery)

**Saturday, August 2**: Full rest day - celebrate!
**Sunday-Thursday**: Light activities, decompress, no studying
**Friday-Saturday**: Wait for results (typically 3-5 business days)

**Expected Result Notification**: August 4-8, 2026

**🎉 CONGRATS - YOU'RE AN OSCP! 🎉**

---

## 📊 Success Metrics & Milestones

### January Milestones
- [ ] Linux fundamentals solid
- [ ] Web application attacks practiced
- [ ] 5-10 HTB Easy machines rooted
- [ ] Comfortable with Kali Linux

### February Milestones
- [ ] Buffer overflows understood
- [ ] Privilege escalation practiced
- [ ] 15+ HTB machines rooted
- [ ] Ready for PWK enrollment

### March Milestones
- [ ] PEN-200 enrolled ($1,649)
- [ ] All course material completed
- [ ] 40-50 PWK lab machines rooted
- [ ] Strong momentum

### April Milestones
- [ ] 85-90 PWK lab machines rooted
- [ ] Active Directory mastered
- [ ] Lab report complete
### June Milestones
- [ ] PWK lab access concluded (May 30)
- [ ] 35-45 external OSCP-like machines rooted
- [ ] 2 full mock exams completed
- [ ] Buffer overflows: < 60 minutes
- [ ] Full-time summer study achieved

### July Milestones
- [ ] Exam passed (July 31) 🎯
- [ ] Professional report submitted
- [ ] OSCP certification earned
- [ ] LinkedIn updated

### August Milestones (Post-OSCP)
- [ ] Recovery and celebration
- [ ] Resume updated with OSCP
- [ ] Begin AWS Security Specialty prep (light)
- [ ] Prepare for fall semesterort submitted
- [ ] OSCP certification earned
- [ ] LinkedIn updated

---

## 🛠️ Essential Tools & Resources

### Enumeration
- **Nmap**: Port scanning
- **AutoRecon**: Automated enumeration
- **Enum4linux**: SMB enumeration
- **ldapsearch**: LDAP enumeration
- **gobuster/ffuf**: Directory bruteforcing
- **nikto**: Web vulnerability scanner

### Exploitation
- **Searchsploit**: Exploit database
- **Metasploit**: Exploitation framework (minimal use)
- **Impacket**: SMB/AD tools
- **John the Ripper**: Password cracking
- **Hashcat**: Password cracking
- **Hydra**: Brute forcing

### Privilege Escalation
- **LinPEAS**: Linux enumeration
- **WinPEAS**: Windows enumeration
- **pspy**: Linux process monitoring
- **PowerUp.ps1**: Windows privesc
- **GTFOBins**: Linux binary exploitation

### Active Directory
- **BloodHound**: AD enumeration/visualization
- **CrackMapExec**: AD swiss army knife
- **Impacket suite**: AD exploitation
- **Rubeus**: Kerberos attacks
- **Mimikatz**: Credential dumping

### File Transfers
- **Python HTTP server**: `python3 -m http.server`
- **Netcat**: File transfer
- **Certutil**: Windows download
- **PowerShell**: Download files
- **SCP/SFTP**: Secure transfer

### Buffer Overflow
- **Immunity Debugger**: Debugging (Windows)
- **mona.py**: Exploit development
- **msfvenom**: Shellcode generation
- **pattern_create/offset**: Finding EIP

### Reporting
- **CherryTree**: Note-taking
- **KeepNote**: Note-taking
- **Obsidian**: Markdown notes
- **Greenshot**: Screenshots
- **LibreOffice**: Report writing

---

## 📝 Study Resources

### Official Resources
- **PEN-200 Course Materials**: Primary resource ($1,649)
- **Offensive Security Proving Grounds**: Practice boxes ($19/month)
- **OffSec Discord**: Community support

### Practice Platforms
- **Hack The Box**: VIP subscription ($14/month)
  - Focus on "TJ Null OSCP Prep List"
- **TryHackMe**: Premium ($10/month)
  - OSCP Preparation path
  - Buffer overflow prep
- **Proving Grounds Practice**: ($19/month)
  - Most OSCP-like machines

### Books
- **"Penetration Testing" by Georgia Weidman** - $35
- **"The Web Application Hacker's Handbook"** - $45
- **"Hacking: The Art of Exploitation"** - $30

### Video Resources
- **IppSec**: HTB walkthroughs (YouTube, FREE)
- **John Hammond**: Security content (YouTube, FREE)
- **The Cyber Mentor**: Pentesting course (Udemy, ~$15)

### Community Resources
- **r/oscp** (Reddit): Active community
- **OSCP Discord servers**: Real-time help
- **OffSec forums**: Official support
- **TJ Null's list**: OSCP-like machine list (FREE)

### Cheat Sheets
- **PayloadsAllTheThings**: Exploit techniques (GitHub, FREE)
- **HackTricks**: Pentesting wiki (FREE)
- **GTFOBins**: Linux binary exploitation (FREE)
- **LOLBAS**: Windows binary exploitation (FREE)

---

## ⚠️ Common Pitfalls & How to Avoid

### Pitfall #1: Insufficient Lab Time
- **Problem**: 90 days seems long, but goes fast
- **Solution**: Enroll by March 1, maximize usage in March-May

### Pitfall #2: Rabbit Holes
- **Problem**: Spending 8 hours on one dead-end
- **Solution**: Time-box attempts (4 hours max), move on, return later

### Pitfall #3: Over-Reliance on Metasploit
- **Problem**: Metasploit restricted on exam
- **Solution**: Learn manual exploitation, use MSF sparingly

### Pitfall #4: Poor Documentation
- **Problem**: Missing screenshots, incomplete notes
- **Solution**: Document EVERYTHING as you go, not after

### Pitfall #5: Burnout
- **Problem**: 6 months is a long grind
- **Solution**: Schedule rest days, maintain work-life balance

### Pitfall #6: Neglecting Buffer Overflows
- **Problem**: BOF seems hard, people skip it
- **Solution**: Master BOF early, it's easy 20 points on exam

### Pitfall #7: Ignoring Active Directory
- **Problem**: AD seems complex, people avoid it
- **Solution**: AD is 40 points on exam, must practice

### Pitfall #8: Poor Time Management on Exam
- **Problem**: Spending 12 hours on one machine
- **Solution**: Time-box exam machines, move on strategically

### Pitfall #9: Inadequate Breaks
- **Problem**: 23-hour exam without proper breaks
- **Solution**: Schedule breaks every 3-4 hours, non-negotiable

### Pitfall #10: Not Following Methodology
- **Problem**: Random exploitation attempts
- **Solution**: Systematic enumeration → exploitation → privesc

---

## 🎯 Exam Day Checklist

### Week Before Exam
- [ ] Exam scheduled and confirmed
- [ ] VPN connection tested
- [ ] Workspace organized
- [ ] Proctoring software tested (if applicable)

### Day Before Exam
- [ ] Light review only (no cramming)
- [ ] Snacks prepared (energy bars, nuts, fruit)
- [ ] Drinks ready (water, coffee/tea)
- [ ] Meals prepped (avoid heavy foods)
- [ ] Alarms set (backup alarms)
- [ ] Cheat sheets printed/organized
- [ ] Early bedtime (10+ hours sleep)

### Exam Day Morning
- [ ] Wake up refreshed (8-10 hours sleep)
- [ ] Light breakfast
- [ ] Shower, dress comfortably
- [ ] Test VPN connection
- [ ] Set up note-taking system
- [ ] Organize desktop (close unnecessary apps)
- [ ] Positive mindset established

### During Exam (Every 3-4 Hours)
- [ ] Take 15-30 minute breaks
- [ ] Walk around, stretch
- [ ] Eat small snacks
- [ ] Hydrate regularly
- [ ] Rest eyes from screen
- [ ] Check posture

### After Exam
- [ ] Organize screenshots immediately
- [ ] Start report within 2 hours
- [ ] Use template
- [ ] Proofread thoroughly
- [ ] Submit before 24-hour deadline

---

## 💰 ROI Analysis: Is OSCP Worth It?

### Investment
- **Money**: ~$2,100 (course + practice platforms)
- **Time**: 560-600 hours over 6 months
- **Opportunity cost**: Other activities/relaxation

### Return
- **Salary boost**: +$15,000 - $25,000 per year
  - First year ROI: 7x-12x financial investment
  - Over 5 years: $75k-$125k additional earnings
- **Career opportunities**: 
  - Access to pentesting roles
  - Fidelity appeal significantly increased
  - Competitive advantage over other candidates
- **Skill development**:
  - Real hands-on hacking skills
  - Problem-solving under pressure
## 🚀 Post-OSCP: What's Next?

### Immediate (August 1-15, 2026)
- ✅ Update resume with OSCP
- ✅ Update LinkedIn with certification
- ✅ Share achievement (GitHub, Twitter, etc.)
- ✅ Rest and decompress (2 weeks minimum!)

### Late August 2026
- Enjoy remainder of summer
- Light AWS fundamentals exploration
- Prepare for fall semester
- Maintain OSCP skills with occasional HTB
### Long-Term (Beyond OSCP)
- **AWS Security Specialty**: December 2026
- **Fidelity connection activation**: January 2027
- **Advanced certs** (future):
  - OSEP (Experienced Penetration Tester)
  - OSWE (Web Expert)
  - GPEN (GIAC Penetration Tester)
  - CEH (Certified Ethical Hacker) - easier after OSCP

---
### July 2026
- Transition to AWS Security Specialty prep
- Light AWS fundamentals review
- Maintain OSCP skills with occasional HTB

### Long-Term (Beyond OSCP)
- **AWS Security Specialty**: November 2026
- **Fidelity connection activation**: Post-graduation
- **Advanced certs** (future):
  - OSEP (Experienced Penetration Tester)
  - OSWE (Web Expert)
  - GPEN (GIAC Penetration Tester)
  - CEH (Certified Ethical Hacker) - easier after OSCP

---

## 📞 Support & Resources

### When You Need Help
- **OffSec Forums**: Official support, hint system
- **OffSec Discord**: Real-time community help
- **r/oscp**: Reddit community (avoid spoilers)
- **HTB Discord**: Help with practice machines

### Mental Health & Balance
- Schedule rest days (non-negotiable)
- Exercise regularly (combat sitting)
- Sleep 7-8 hours minimum
- Maintain social connections
- It's a marathon, not a sprint

### If You Fail the Exam
- **Don't panic**: 50-60% fail first attempt
- Review what went wrong
- Retake costs $249 (budget for it)
- Additional prep: 2-4 weeks
- You'll pass on second attempt (higher pass rate)

---

## 🎉 Motivational Reminders

### You Can Do This!
- Thousands have passed OSCP before you
- You have solid foundations (Security+, Auburn CS)
- You have 6 months to prepare (plenty of time)
- You have clear goals (Fidelity career path)
- You have motivation (career and financial goals)

### When It Gets Hard (It Will)
**You've got 6.5 months. Follow this plan. Put in the work. Stay consistent.**

**July 31, 2026: You'll be an OSCP.** 🔥🎯💪

---

**Next Steps**:
1. **Now - Dec 20**: Focus on Security+ exam
2. **Dec 21-31**: Rest, enjoy holidays
3. **January 1-5**: Review this plan, prepare mentally
4. **January 6**: Begin OSCP foundation work
5. **March 1**: Enroll in PEN-200 ($1,649)
6. **May**: Balance finals with OSCP prep
7. **June-July**: Full-time summer intensive
8. **July 31**: Pass OSCP exam 🎯
9. **August 1**: Submit professional report
10. **August 4-8**: Receive PASS notification
11. **September 1**: Begin AWS Security Specialty prep

---

**Last Updated**: November 30, 2025  
**Owner**: Andy M.  
**OSCP Exam Date**: July 31, 2026 (REVISED - Summer timing!)  
**Expected Result**: PASS 🎉

**THE EXTRA MONTH CHANGES EVERYTHING. NO SCHOOL STRESS. FULL SUMMER FOCUS.**

**LET'S FUCKING GO!** 🚀🔥💀his plan, prepare mentally
4. **January 6**: Begin OSCP foundation work
5. **March 1**: Enroll in PEN-200 ($1,649)
6. **June 15**: Pass OSCP exam
7. **June 16**: Submit professional report
8. **June 19-23**: Receive PASS notification
9. **July 1**: Begin AWS Security Specialty prep

---

**Last Updated**: November 30, 2025  
**Owner**: Andy M.  
**OSCP Exam Date**: June 15, 2026  
**Expected Result**: PASS 🎉

**LET'S FUCKING GO!** 🚀🔥💀
