# Section 1.3 - Change Management
**Date:** November 22, 2025  
**Source:** Professor Messer Security+ SY0-701  
**Section:** General Security Concepts

---

## Change Management Overview

### What is Change Management?

**Common Changes:**
- Upgrade software
- Patch an application
- Change firewall configuration
- Modify switch ports

**Why It's Important:**
- One of the most common risks in the enterprise
- Occurs very frequently
- Often overlooked or ignored
- "Did you feel that bite?"

**Key Requirements:**
- Have clear policies
- Frequency, duration, installation process, rollback procedures
- Sometimes extremely difficult to implement
- It's hard to change corporate culture

---

## Change Approval Process

### Formal Process for Managing Change

**Purpose:**
- Avoid downtime, confusion, and mistakes

**Typical Approval Process Steps:**

1. **Complete process forms**
2. **Determine the purpose of the change**
3. **Identify the scope of the change**
4. **Schedule a date and time of the change**
5. **Determine affected systems and the impact**
6. **Analyze the risk associated with the change**
7. **Get approval from the change control board**
8. **Get end-user acceptance after the change is complete**

---

## Ownership

### Who Owns the Change?

**Owner Responsibilities:**
- An individual or entity needs to make a change
- They own the process
- They don't usually perform the actual change
- The owner manages the process
- Process updates are provided to the owner
- Ensures the process is followed and acceptable

**Example:**
- **Scenario:** Address label printers need to be upgraded
- **Owner:** Shipping and Receiving department owns the process
- **Executor:** IT handles the actual change

---

## Stakeholders

### Who is Impacted by the Change?

**Definition:**
- Who is impacted by the change?
- They'll want to have input on the change management process

**Important Note:**
- This may not be as obvious as you might think
- A single change can include one individual or the entire company

**Example: Upgrade Software for Shipping Labels**

**All Things Affected:**
- Shipping / Receiving
- Accounting reports
- Product delivery timeframes
- Revenue recognition - CEO visibility

---

## Impact Analysis

### Determine a Risk Value

**Risk Levels:**
- High, Medium, Low

**Potential Risks:**
- The risks can be minor or far-reaching:
  - The "fix" doesn't actually fix anything
  - The fix breaks something else
  - Operating system failures
  - Data corruption

**Risks of NOT Making the Change:**
- Security vulnerability
- Application unavailability
- Unexpected downtime to other services

---

## Test Results

### Sandbox Testing Environment

**What is a Sandbox?**
- No connection to the real world or production system
- A technological safe space

**Use Before Production:**
- Try the upgrade, apply the patch
- Test and confirm before deployment

**Confirm the Backout Plan:**
- Move everything back to the original
- A sandbox can't consider every possibility

---

## Backout Plan

### Always Be Ready to Revert

**Reality Check:**
- "The change will work perfectly and nothing bad will ever happen"
- **Reality:** Things always go bad, so get ready buddy

**Requirements:**
- You should ALWAYS have a way to revert the changes
- Prepare for the worst, hope for the best
- This isn't as easy as it sounds
- Some changes are difficult to revert

**Critical Requirement:**
- ✅ **Always have backups**
- ✅ **Always have GOOD backups**

---

## Maintenance Window

### When is the Change Happening?

**Scheduling Challenges:**
- This might be the most difficult part of the process

**Common Timing:**
- Overnights are often a better choice
- Challenging for 24-hour production schedules

**Seasonal Considerations:**
- The time of year may be a consideration
- Example: Retail networks frozen during holiday season

---

## Standard Operating Procedure (SOP)

### Documentation is Critical

**Why It Matters:**
- Change management is critical
- Affects everyone in the organization

**Documentation Requirements:**
- This process must be well documented
- Should be available on the intranet
- Along with standard processes and procedures

**Living Document:**
- Changes to the process are reflected in the standards
- A living document that evolves

---

## Technical Change Management

### Put the Change Management Process into Action

**Execute the Plan:**
- There's no such thing as a simple upgrade
- Can have many moving parts
- Separate events may be required

**Division of Concerns:**
- **Change Management:** Concerned with "WHAT" needs to change
- **Technical Team:** Concerned with "HOW" to change it

---

## Allow / Deny Lists

### Application Control

**The Problem:**
- Any application can be dangerous
- Vulnerabilities, trojan horses, malware

**Security Policy Controls:**
- Security policy can control app execution
- Two approaches: Allow list, Deny/Block list

### Allow List (Whitelist)

**Characteristics:**
- Nothing runs unless it's approved
- Very restrictive
- Most secure approach

### Deny List (Blacklist)

**Characteristics:**
- Nothing on the "bad list" is executed
- Anti-virus, anti-malware approach
- Less restrictive

---

## Restricted Activities

### Scope of Change

**Importance:**
- The scope of a change is important
- Defines exactly which components are covered

**Limitations:**
- A change approval isn't permission to make ANY change
- The change control approval is very specific

**Flexibility:**
- The scope may need to be expanded during the change window
- It's impossible to prepare for all possible outcomes

**Process:**
- The change management process determines the next steps
- There are processes in place to make the change successful

---

## Downtime

### Services Will Eventually Be Unavailable

**Reality:**
- The change process can be disruptive
- Usually scheduled during non-production hours

**Best Practices:**

**Prevent Downtime (If Possible):**
- Switch to secondary system
- Upgrade primary
- Then switch back

**Minimize Downtime:**
- The process should be as automated as possible
- Switch back to secondary if issues appear
- Should be part of the backout plan

**Communication:**
- Send emails and calendar updates

---

## Restarts

### Common Requirement

**Why Restarts Are Needed:**
- It's common to require a restart
- Implement the new configuration
- Reboot the OS, power cycle the switch, bounce the service
- Can the system recover from a huge outage?

### Types of Restarts:

**Services:**
- Stop and restart a daemon
- May take seconds or minutes

**Applications:**
- Close the application completely
- Launch new application instance

---

## Legacy Applications

### Dealing with Old Systems

**Characteristics:**
- Some applications were here before you arrived
- They'll be here when you leave
- Often no longer supported by the developer
- You're now the support team

**Challenges:**
- Fear of the unknown
- Face your fears and document the system
- It may not be as bad as you think

**Special Considerations:**
- May be quirky
- Creates specific processes and procedures
- Become an expert

---

## Dependencies

### Interconnected Systems

**What Are Dependencies?**
- To complete A, you must complete B
- A service will not start without other active services
- An application requires a specific library version

**Challenges:**
- Modifying one component may require changing or restarting other components
- This can be challenging to manage

**Cross-System Dependencies:**
- Dependencies may occur across systems
- Example:
  - Upgrade firewall code first
  - Then upgrade the firewall management software

---

## Documentation

### Keeping Everything Current

**The Challenge:**
- It can be challenging to keep up with the changes
- Documentation can be outdated very quickly
- Required with the change management process

**What to Update:**

**Updating Diagrams:**
- Modifications to network configurations
- Address updates

---

## Version Control

### Track Changes Over Time

**What is Version Control?**
- Track changes to a file or configuration data over time
- Easily revert to a previous setting

**Many Opportunities to Manage Versions:**
- Router configurations
- Windows OS patches
- Application registry entries

**Challenges:**
- Not always straightforward
- Some devices and operating systems provide version control features
- May require additional management software

---

## Key Takeaways for Exam:

✅ **Change Management Process** - Know all steps of the approval process
✅ **Ownership vs Execution** - Owner manages, IT executes
✅ **Stakeholder Analysis** - Changes affect more people than you think
✅ **Impact Analysis** - Assess risk levels (high, medium, low)
✅ **Sandbox Testing** - Test before production deployment
✅ **Backout Plan** - Always have a way to revert changes
✅ **Maintenance Window** - Schedule changes during off-hours
✅ **Allow Lists vs Deny Lists** - Understand both approaches
✅ **Dependencies** - One change may require multiple changes
✅ **Documentation** - Keep everything current and updated
✅ **Version Control** - Track configurations over time

---

## Related Concepts:

- Change Control Board (CCB)
- Standard Operating Procedures (SOP)
- Disaster Recovery Planning
- Business Continuity
- Configuration Management

---

*Notes completed: November 22, 2025*  
*Next: Section 1.4 - Cryptographic Solutions*
