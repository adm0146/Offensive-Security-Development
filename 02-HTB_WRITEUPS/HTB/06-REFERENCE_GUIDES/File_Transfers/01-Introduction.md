# 01 — File Transfers: Introduction

## Why File Transfers Matter

File transfers are one of the most critical skills in penetration testing. Almost every engagement requires moving tools, scripts, or data between your attack machine and the target. There is almost always something blocking the obvious path.

---

## Real-World Scenario

Imagine this engagement chain:

```
1. Gain RCE on IIS web server (unrestricted file upload)
   ↓
2. Upload web shell → get reverse shell
   ↓
3. Need PowerUp.ps1 for privilege escalation
   ❌ PowerShell BLOCKED by Application Control Policy
   ↓
4. Manual enumeration → find SeImpersonatePrivilege
   ↓
5. Need PrintSpoofer binary on target
   ❌ Certutil blocked — web content filtering blocks GitHub, Dropbox, Google Drive
   ↓
6. Try FTP server
   ❌ Firewall blocks outbound TCP port 21
   ↓
7. Try Impacket smbserver
   ✅ Outbound TCP port 445 (SMB) ALLOWED — transfer succeeds
   ↓
8. Privilege escalation to administrator ✅
```

> **Key Lesson:** You need multiple file transfer methods in your toolkit. The first (and second, and third) method you try may be blocked.

---

## Why Transfers Get Blocked

| Obstacle | What It Blocks | Example |
|----------|---------------|---------|
| **Application Control Policy** | Specific executables/scripts from running | PowerShell, cmd.exe, python |
| **Web Content Filtering** | Access to external sites | GitHub, Dropbox, Google Drive |
| **Firewalls** | Specific outbound/inbound ports | FTP (21), SMB (445), HTTP (80) |
| **AV / EDR** | Known malicious tools and behaviors | Mimikatz, reverse shells, encoded payloads |
| **IDS / IPS** | Suspicious network patterns | Large data transfers, unusual protocols |

---

## The Mindset

- Know multiple transfer methods. If one is blocked, pivot to the next.
- Understand host controls. Application whitelisting and Antivirus/Endpoint Detection and Response (AV/EDR) can block your tools.
- Understand network controls. Firewalls and Intrusion Detection/Prevention Systems (IDS/IPS) monitor or block specific ports and traffic patterns.
- Every operating system has built-in transfer tools. Use what is already on the system.
- Adapt to the environment. The best method depends entirely on what is allowed.

---

## What This Module Covers

- Techniques using tools commonly available on **Windows and Linux**
- Multiple methods for when your primary approach is blocked
- Understanding **why** certain methods work in certain environments
- Building a reference guide for use across all HTB Academy modules and real engagements

---

## Key Takeaways

- File transfer is a core penetration testing skill — it is not optional.
- There is no single universal method. You need a toolkit of techniques.
- Obstacles include host controls (application whitelisting, AV/EDR) and network controls (firewalls, IDS/IPS).
- The scenario above is realistic. Expect to try 3-4 methods before one works.
- Always have a fallback plan for getting files onto a target.
- This module is a reference guide for all future HTB work.
