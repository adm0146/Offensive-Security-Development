# 🔥 OSCP 6-MONTH GAME PLAN: January 6 - August 1, 2026
**Complete Offensive Security Certified Professional (OSCP) Preparation**

---

## 📋 QUICK OVERVIEW

| Timeline | Phase | Hours/Week | Focus | Target |
|----------|-------|-----------|-------|--------|
| **Jan 6 - Feb 2** | Foundation | 15-20 | Prerequisites | 80 hours |
| **Feb 3 - Mar 2** | PWK Content | 20-25 | Course Material | 100 hours |
| **Mar 3 - Apr 6** | PWK Labs Part 1 | 25-30 | First 50 machines | 110 hours |
| **Apr 7 - May 4** | PWK Labs Part 2 | 25-30 | Machines 51-100 | 110 hours |
| **May 5 - Jun 1** | PWK Labs Final | 20-30 | Flexibility (finals) | 100 hours |
| **Jun 2 - Jul 6** | Intensive Sprint | 40-50 | Full-time prep | 300 hours |
| **Jul 7 - Aug 1** | Mock Exams + Real Exam | Variable | Exam ready | 50-100 hours |

**Total Study Hours: 750-850 hours**  
**Average Daily (excluding June-July): 3.5 hours/day**  
**June-July: 8-10 hours/day (summer break!)**

---

## 🎯 EXAM INFORMATION

**Certification:** OSCP (Offensive Security Certified Professional)  
**Course:** PEN-200: Penetration Testing with Kali Linux  
**Exam Duration:** 23 hours 45 minutes (hands-on)  
**Report Due:** 24 hours after exam end  
**Passing Score:** 70/100 points  
**Point Breakdown:**
- 3 Standalone machines: 20 points each (60 total)
  - 10 points for foothold (low-privilege)
  - 10 points for privilege escalation
- Active Directory set: 40 points (all-or-nothing)
  - Compromise all 3 machines to get points

**Exam Strategy:**
- Get all 3 standalone (60 points) = safe pass
- Then attempt AD set (40 points) for bonus
- Minimum to pass: 70 points

---

## 💰 INVESTMENT & COSTS

### Required:
- **PEN-200 Course** (90-day lab access): $1,649
  - Includes: PDF, videos, lab access, 1 exam attempt
- **Exam Retake** (if needed): $249

### Highly Recommended:
- **HackTheBox VIP**: $14/month × 6 = $84
  - Retired machines, walkthroughs available
- **TryHackMe Premium**: $10/month × 6 = $60
  - Structured learning paths
- **Proving Grounds Practice**: $19/month × 3 = $57
  - OSCP-like machines
- **Books & Resources**: $100-150
  - "The Web Application Hacker's Handbook"
  - "Penetration Testing" by Georgia Weidman

### Optional:
- Extra lab time: $20/day (only if you need beyond 90 days)
- VPN/Proxies: $0-50

### **Total Budget: $2,100-$2,300**
- Minimum viable: $1,649
- Recommended: $2,000-$2,100

---

## 📅 PHASE-BY-PHASE BREAKDOWN

---

## PHASE 1: FOUNDATION BUILDING
**January 6 - February 2 (4 weeks, 80 hours, 15-20 hrs/week)**

### Goal
Build prerequisite skills before starting PWK course.

### What You'll Learn
1. **Linux Fundamentals**
   - File system, permissions, user management
   - Process management, service management
   - Bash scripting basics

2. **Networking & Enumeration**
   - TCP/IP fundamentals
   - Nmap mastery (all scan types)
   - Service enumeration tools

3. **Web Application Attacks**
   - SQL injection techniques
   - File upload vulnerabilities
   - Local/Remote file inclusion

4. **Initial Practice**
   - 14 HackTheBox Easy machines
   - First hands-on experience
   - Documentation practice

### Week-by-Week (Detailed in existing guide)
- **Week 1:** Linux Fundamentals + Bash Scripting (2-3 hrs/day)
- **Week 2:** Networking + Nmap Mastery (2-3 hrs/day)
- **Week 3:** Web Application Attacks (3-4 hrs/day)
- **Week 4:** HackTheBox Easy Machines (3-4 hrs/day) - 5 boxes

### Success Metrics
✅ Comfortable in Linux terminal  
✅ Can run comprehensive Nmap scans  
✅ Understand SQL injection, LFI, file uploads  
✅ Have completed 5 HTB Easy machines with writeups  
✅ Ready to begin PWK course

### Resources
- TryHackMe Premium ($10)
- HackTheBox VIP ($14)
- PortSwigger Academy (FREE)
- Bash scripting tutorials (FREE)

---

## PHASE 2: PWK COURSE CONTENT
**February 3 - March 2 (4 weeks, 100 hours, 20-25 hrs/week)**

### Goal
Master the PEN-200 course material (PDF + videos) before hands-on labs.

### Module Breakdown
**Module 1: Information Gathering** (2 weeks)
- Passive reconnaissance (OSINT)
- Active reconnaissance (port scanning)
- Enumeration techniques
- Creating enumeration checklists

**Module 2: Vulnerability Assessment** (1 week)
- Vulnerability scanning (Nessus, OpenVAS)
- Common CVEs and exploits
- Manual verification

**Module 3: Exploitation & Post-Exploitation** (2 weeks)
- Buffer overflow fundamentals
- File transfer techniques
- Privilege escalation (Linux & Windows)
- Maintaining access

**Module 4: Web Applications** (1 week)
- Web app reconnaissance
- SQL injection deep dive
- XSS, CSRF, LFI/RFI exploitation
- Web shell upload and execution

### Week-by-Week Structure
- **Week 5 (Feb 3-9):** Information Gathering (3-4 hrs/day)
  - OSINT techniques
  - Passive vs. active recon
  - 2 HTB Easy boxes
  
- **Week 6 (Feb 10-16):** Vulnerability Assessment (3-4 hrs/day)
  - Vulnerability scanning
  - Buffer overflow intro
  - 2 HTB Easy boxes

- **Week 7 (Feb 17-23):** Exploitation Basics (4-5 hrs/day)
  - Client-side attacks
  - File transfer methods
  - Buffer overflow deep dive
  - 2 HTB Easy boxes

- **Week 8 (Feb 24 - Mar 2):** Post-Exploitation (4-5 hrs/day)
  - Linux privilege escalation
  - Windows privilege escalation
  - 3 HTB Easy boxes

### HTB Boxes Target
- Total Easy machines by end of Feb: 14 completed
- Focus: Understand the "flow" of each machine

### Success Metrics
✅ Completed PWK PDF (1000+ pages)  
✅ Watched all course videos (70+ hours)  
✅ Understand buffer overflows  
✅ Master Linux & Windows privesc  
✅ 14 HTB Easy machines completed  
✅ Ready to start PWK labs with $1,649 enrollment

---

## PHASE 3: PWK LABS - PART 1 (Machines 1-50)
**March 3 - April 6 (5 weeks, 110-130 hours, 25-30 hrs/week)**

### Goal
Enroll in PEN-200, compromise first 50 lab machines, establish methodology.

### What's Happening This Month
1. **Enrollment & Setup**
   - Complete enrollment in PEN-200
   - Receive lab access credentials
   - Setup Kali Linux VM, networking
   - Obtain labs PDF (75 pages, 5 standalone machines)

2. **Lab Machines (50 total)**
   - **Weeks 1-2:** Machines 1-20 (easiest tier)
   - **Week 3:** Machines 21-35 (medium tier)
   - **Week 4:** Machines 36-45 (harder)
   - **Week 5:** Machines 46-50 (most difficult) + 5 standalone lab machines

3. **Developing Methodology**
   - Create enumeration template
   - Develop exploitation workflow
   - Document every machine thoroughly
   - Screenshot-driven writeups

### Key Machines to Focus On
- **10 Point Machines:** Quick wins, build confidence
- **20 Point Machines:** More complex, practice pivoting
- **25 Point Machines:** Real challenges, prepare for exam

### Success Metrics
✅ 50 lab machines compromised  
✅ Methodology refined  
✅ Can enumerate comprehensively  
✅ Comfortable with pivoting between machines  
✅ Detailed documentation for each machine  
✅ Understand machine dependencies/chains

### Study Schedule
- **Daily:** 5-6 hours dedicated lab time
- **Weekly:** 1-2 hours reviewing notes/methodology
- **Fridays:** Documentation/writeup day
- **Sundays:** Review and plan next week

---

## PHASE 4: PWK LABS - PART 2 (Machines 50-100+)
**April 7 - May 4 (4 weeks, 110 hours, 25-30 hrs/week)**

### Goal
Continue labs, deepen skills, reach 70+ machines compromised.

### What's Happening This Month
1. **Lab Continuation**
   - **Weeks 1-2:** Machines 51-75
   - **Weeks 3-4:** Machines 76-100+

2. **Increasing Difficulty**
   - More complex privilege escalations
   - Exploiting multiple services
   - Chaining vulnerabilities together
   - Real Active Directory scenarios

3. **Skills Development**
   - Custom exploit modification
   - Kernel exploit adaptation
   - Advanced pivoting techniques
   - Windows domain enumeration

4. **Practice Exams Option**
   - If available: Take PWK mock exam
   - Identify remaining weak areas

### Success Metrics
✅ 70+ lab machines compromised  
✅ Feeling comfortable with medium-hard machines  
✅ Can chain multiple vulnerabilities  
✅ Windows AD basics understood  
✅ Custom exploit development practiced  
✅ Confidence building toward exam

### Study Schedule
- **Daily:** 5-6 hours lab time
- **Weekly:** 1-2 hours methodology review
- **Midweek:** Practice with Proving Grounds machines
- **Sundays:** Plan next week, review weak areas

---

## PHASE 5: PWK LABS - FINAL PUSH (With Academic Flexibility)
**May 5 - June 1 (4 weeks, 100+ hours, 20-30 hrs/week)**

### Goal
Finish 90-day lab access, maintain momentum through finals/exams.

### Academic Conflicts
- Mid-May: Spring semester finals
- Early June: Some courses may still be running
- **Flexibility:** Adjust daily hours (5-7 hours when possible)

### What's Happening This Month
1. **Lab Completion**
   - Target: 80-100 machines compromised
   - Focus on remaining difficult machines
   - Complete any skipped machines
   - Document everything thoroughly

2. **Exam-Style Practice**
   - Create "exam scenarios" within labs
   - Time-box yourself (4-5 machines in 24 hours)
   - Practice report writing

3. **Finals Balance**
   - Labs: 5-7 hours/day when possible
   - Academic courses: Variable
   - Weekends: Heavy lab focus

### Success Metrics
✅ 80+ lab machines compromised  
✅ All 75-page standalone PDF machines rooted  
✅ 90-day lab access fully utilized  
✅ Comprehensive notes and writeups  
✅ Ready for intensive June preparation

### Study Schedule (Flexible)
- **Weekdays during finals:** 3-5 hours lab time
- **Weekends:** 7-10 hours lab time
- **After finals:** Full intensity 6+ hours/day

---

## PHASE 6: SUMMER INTENSIVE SPRINT
**June 2 - July 6 (5 weeks, 250-300 hours, 40-50+ hrs/week)**

### Goal
Full-time OSCP preparation - no school conflicts, focused exam prep.

### What's Happening This Month
1. **Exam Techniques Practice**
   - Proving Grounds Practice machines
   - Focus on OSCP-like scenarios
   - Time-boxed exploitation sessions
   - Report writing practice

2. **Active Directory Deep Dive**
   - AD enumeration techniques
   - Domain user enumeration
   - Kerberos exploitation
   - BloodHound and SharpHound usage
   - Lateral movement in AD environments

3. **Weak Areas Intensive**
   - Identify remaining gaps from lab work
   - Dedicate entire weeks to weak areas
   - Re-watch relevant PWK modules
   - Practice targeted exploitation

4. **Mock Exams (If Available)**
   - Proving Grounds mock exam
   - Time pressure simulation
   - Report writing under exam conditions
   - Full 24-hour cycle practice

### Weekly Breakdown
**Week 1 (June 2-8):**
- Proving Grounds machines: 3-4 machines
- AD deep dive: 15 hours
- Report writing practice: 5 hours
- Study hours: 40-45

**Week 2 (June 9-15):**
- Proving Grounds: 3-4 machines
- Weak areas focus: 20 hours
- AD exploitation practice: 15 hours
- Study hours: 45-50

**Week 3 (June 16-22):**
- Proving Grounds: 4-5 machines
- Exam simulation: 3 machines in 24 hours
- Buffer overflow review: 10 hours
- Study hours: 45-50

**Week 4 (June 23-29):**
- Proving Grounds: 4-5 machines
- Mock exam attempt (24-hour format)
- Report writing: 8-10 hours
- Weak areas: 15 hours
- Study hours: 50-55

**Week 5 (June 30 - July 6):**
- Proving Grounds: 2-3 machines
- Light review of weak areas
- Exam preparation and confidence building
- Getting mentally ready
- Study hours: 30-40 (wind down)

### Success Metrics
✅ 15+ Proving Grounds machines completed  
✅ Active Directory expertise developed  
✅ Mock exam completed with 70%+ score  
✅ Report writing perfected  
✅ Exam confidence at 90%+  
✅ Mentally prepared for exam  
✅ All weak areas addressed

### Study Schedule
- **Daily:** 8-10 hours dedicated study
- **Weekly exam simulation day:** 24-hour exploitation session
- **Sundays:** Plan next week, light review
- **Rest day:** 1 day per week (Friday or Saturday) for recovery

---

## PHASE 7: FINAL COUNTDOWN & EXAM
**July 7 - August 1 (4 weeks, 50-150 hours)**

### Goal
Final preparation, mock exams, and actual OSCP exam.

### Week-by-Week (Variable)

**Week 1 (July 7-13): Final Weak Areas**
- Light review of remaining weak points
- 1-2 Proving Grounds machines
- Exam format review
- Study hours: 20-30

**Week 2 (July 14-20): Pre-Exam Confidence**
- Final practice (1-2 machines)
- Report writing review
- Exam day preparation
- Mental readiness focus
- Study hours: 15-25

**Week 3 (July 21-27): Rest & Prepare**
- NO HEAVY STUDYING
- Light flashcard review of key concepts
- Ensure sleep schedule is correct for exam
- Prepare equipment/VPN
- Study hours: 5-15

**July 28-31: EXAM WEEK** ⏰
- **July 28:** Exam day setup, confirm credentials, test VPN
- **July 29-30:** OSCP Exam (23h 45m) + Report writing (24h)
- **July 31:** Submit report, wait for results

### Success Criteria
✅ Mock exam scored 70%+ (likely to pass)  
✅ Comfortable with exam format  
✅ Well-rested before exam day  
✅ All equipment tested and ready  
✅ Mental confidence at peak  
✅ OSCP certification achieved! 🏆

---

## 📊 MONTHLY PROGRESS TRACKING

### January (Foundation)
- **Target:** 14 HTB Easy boxes, Linux/Nmap/Web fundamentals
- **Hours:** 80
- **Success indicator:** Comfortable in Linux, can enumerate with Nmap

### February (PWK Content)
- **Target:** Complete course material, 14 HTB Easy boxes total
- **Hours:** 100
- **Success indicator:** Understand buffer overflows, Windows/Linux privesc

### March (PWK Labs Start)
- **Target:** 50 lab machines, methodology established
- **Hours:** 110-130
- **Success indicator:** Can document machines thoroughly

### April (PWK Labs Mid)
- **Target:** 70+ lab machines, increasing difficulty
- **Hours:** 110
- **Success indicator:** Comfortable with medium-hard machines

### May (PWK Labs Final + Finals)
- **Target:** 80-100 lab machines, maintain momentum
- **Hours:** 100+
- **Success indicator:** Deep understanding of exploitation chains

### June (Intensive Sprint)
- **Target:** 15+ Proving Grounds machines, AD mastery, mock exam
- **Hours:** 250-300
- **Success indicator:** Mock exam 70%+, feeling exam-ready

### July (Final Countdown + Exam)
- **Target:** OSCP Exam passage
- **Hours:** 50-150
- **Success indicator:** OSCP Certification achieved!

---

## ⚡ CRITICAL SUCCESS FACTORS

### 1. **Consistency Over Intensity**
- 3.5 hours/day is sustainable
- Burning out 2 months before is dangerous
- Consistent daily practice beats weekend cramming

### 2. **Documentation Discipline**
- Every machine needs a writeup
- This practice is critical for exam report
- Takes 30-60 minutes per machine
- Worth the time investment

### 3. **Methodology Development**
- Create your own enumeration checklist
- Develop exploitation workflow
- Document what works for YOU
- Be reproducible

### 4. **Active Directory Skills**
- Not in PWK course deeply enough
- Must supplement with TryHackMe/HTB
- AD machines worth 40 exam points
- Critical for passing

### 5. **Time Management**
- Don't spend 8 hours on one machine
- Use time-boxing (2-3 hours max per machine)
- Move on, come back later
- Exam is 24 hours, need to manage time

### 6. **Sleep is Performance**
- Sleep > studying at midnight
- Consistent sleep schedule
- Tired brain makes mistakes
- 7-8 hours minimum

### 7. **Report Writing Practice**
- Practice writing reports throughout prep
- Professional screenshots with annotations
- Clear exploitation steps
- Practice writing under time pressure

---

## 🎯 EXAM DAY STRATEGY

### Pre-Exam (1 week before)
- [ ] Confirm exam date/time with Offensive Security
- [ ] Test VPN connection multiple times
- [ ] Prepare equipment (laptop, monitors, etc.)
- [ ] Arrange quiet exam environment
- [ ] Get 8+ hours sleep each night
- [ ] Avoid heavy studying (light review only)

### Exam Day (23h 45m)
**Hours 0-6:** Target 2 standalone machines (40 points)
- Enumerate aggressively
- Flag questions for later
- Get early wins for confidence

**Hours 6-12:** Target 1st AD machine (10-15 points)
- Apply lateral movement techniques
- Document for report
- Build from initial foothold

**Hours 12-18:** Continue AD exploitation
- Compromise additional AD machines
- Document everything
- Take screenshots constantly

**Hours 18-23:** Final exploitation push
- Finish standalone #3 if not done (20 points)
- Complete AD set if possible (40 points)
- Document everything

**Final 45 minutes:** Verification
- Verify all proofs of exploitation
- Screenshots of proof.txt
- Prepare writeup structure

### Report Writing (24 hours after exam)
- Professional documentation
- Screenshots with annotations
- Clear exploitation narrative
- Proof of exploitation
- Professional formatting
- Submit within 24 hours

---

## 💪 YOU CAN DO THIS!

**Why You'll Succeed:**
1. ✅ 6 months is realistic timeline (most take 4-6)
2. ✅ Structured plan removes guesswork
3. ✅ Strong foundation building first (critical!)
4. ✅ 90-day lab access sufficient with good methodology
5. ✅ Summer flexibility allows full-time prep
6. ✅ You have Fidelity goal motivation

**Key to Success:**
- Commit to consistency (3.5 hrs/day average)
- Follow the phases in order
- Document everything
- Don't skip the fundamentals
- Practice active directory specifically
- Get sleep before exam
- Believe you can do it! 🔥

---

**Questions Before You Start?**
- Need clarification on any phase?
- Want to discuss investment strategy?
- Have concerns about timeline?

**You've got 6 months. You've got a detailed plan. Now it's time to execute! 💪**

**Let's get this OSCP! 🎓**
