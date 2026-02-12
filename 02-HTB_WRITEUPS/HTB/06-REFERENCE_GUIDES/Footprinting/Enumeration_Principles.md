# Enumeration Principles

## What is Enumeration?

Information gathering using **active** (scans) and **passive** (third-party providers) methods. Not to be confused with OSINT, which is an independent procedure based exclusively on passive information gathering and does not involve active enumeration.

Enumeration is a **loop** -- we repeatedly gather information based on what data we have or have already discovered. Sources include domains, IP addresses, accessible services, and many others.

---

## The Right Approach

When investigating a company's IT security, start by developing a general understanding of:

- How the company is structured
- What services and third-party vendors it uses
- What security measures may be in place

**Common mistake:** Finding authentication services (SSH, RDP, WinRM) and immediately attempting brute-force with common/weak credentials. This is noisy, leads to blacklisting, and makes further testing impossible -- especially when you don't know the company's defensive security measures.

**The goal is not to get at the systems but to find all the ways to get there.**

Think of it like a treasure hunter -- he doesn't grab a shovel and start digging random holes. He studies maps, learns the terrain, and brings the proper tools. Digging holes everywhere causes damage, wastes time and energy, and likely never achieves the goal. The same applies to understanding infrastructure, mapping it out, and carefully formulating a plan of attack.

---

## Core Questions

Focus on what we **can** see AND what we **cannot** see:

### What We Can See

| Question | Purpose |
|----------|---------|
| What can we see? | Identify visible components |
| What reasons can we have for seeing it? | Understand why it's exposed |
| What image does what we see create for us? | Build mental model of infrastructure |
| What do we gain from it? | Assess value of discovered information |
| How can we use it? | Plan next steps |

### What We Cannot See

| Question | Purpose |
|----------|---------|
| What can we not see? | Identify gaps in our knowledge |
| What reasons can there be that we do not see? | Understand filtering, firewalls, segmentation |
| What image results from what we do not see? | Infer hidden infrastructure from absence |

---

## Three Principles of Enumeration

| # | Principle |
|---|-----------|
| 1 | There is more than meets the eye. Consider all points of view. |
| 2 | Distinguish between what we see and what we do not see. |
| 3 | There are always ways to gain more information. Understand the target. |

---

## Key Takeaways

- Enumeration is a loop, not a one-time scan
- OSINT is separate from enumeration (passive only)
- Don't brute-force blindly -- understand the infrastructure first
- What you can't see is just as important as what you can
- The core task is not to exploit machines but to find how they can be exploited
- There are always exceptions to the rules, but the principles do not change
