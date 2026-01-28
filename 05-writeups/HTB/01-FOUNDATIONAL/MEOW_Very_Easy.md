# MEOW - Very Easy

**Date:** January 23, 2026  
**Difficulty:** Very Easy  
**Time Spent:** <20 minutes  
**Status:** ✅ PWNED

---

## Machine Overview

MEOW is an introductory machine designed to teach fundamental penetration testing concepts and tools. It covers VM setup, network connectivity, basic enumeration, and exploitation of a telnet service with default credentials.

---

## Key Concepts Learned

- VM and lab environment navigation
- OpenVPN connection to HTB network
- Connection verification (ping, nmap)
- Service identification and enumeration
- Default credential exploitation
- Basic file navigation and flag capture

---

## Reconnaissance

### Connection Verification
- Used ping to confirm network connectivity to target
- Used nmap to verify target is reachable

### Service Enumeration
```
nmap -p- TARGET_IP
```

**Findings:**
- Port 23: Telnet service (open)
- No other services running
- Clear and simple attack surface

---

## Vulnerabilities Identified

### Vulnerability 1: Telnet with Default Credentials
- **Type:** Weak/Default Authentication
- **Port:** 23
- **Severity:** Critical
- **Impact:** Unauthenticated remote access
- **Discovery Method:** Nmap service enumeration
- **Root Cause:** Telnet service running with default/weak credentials enabled

### Vulnerability 2: No Authentication Required on admin/root accounts
- **Type:** Authentication Bypass
- **Discovery:** Common username iteration (admin, root, user)
- **Finding:** Root account had no password or auto-login enabled

---

## Exploitation Chain

### Phase 1: Initial Access via Telnet

**Step 1: Connect to Telnet Service**
```
telnet TARGET_IP 23
```

**Step 2: Attempt Common Usernames**
- Tried: admin (failed)
- Tried: user (failed)
- Tried: root (SUCCESS - auto-logged in)

**Connection successful without password - default credential vulnerability**

### Phase 2: File Enumeration

**Step 1: List directory contents**
```
ls
```

**Output:** Directory listing with files including flag.txt

### Phase 3: Flag Capture

**Step 1: Read flag file**
```
cat flag.txt
```

**Flag Retrieved:** [flag content]

---

## Attack Summary

1. Verified network connectivity with ping
2. Ran nmap to identify open services
3. Discovered telnet on port 23
4. Connected via telnet client
5. Exploited default/missing root password
6. Enumerated files with ls
7. Retrieved flag with cat

---

## Key Techniques Used

- **Ping:** Network reachability verification
- **Nmap:** Port scanning and service enumeration
- **Telnet:** Remote service connection
- **Username enumeration:** Tried common default usernames
- **File listing:** ls command
- **File reading:** cat command

---

## Tools Used

- Ping (network testing)
- Nmap (port scanning)
- Telnet (remote connection)
- Linux shell commands (ls, cat)

---

## Lessons Learned

1. **Default Credentials are Real Vulnerabilities** - Root with no password = instant compromise
2. **Telnet is Dangerous** - Unencrypted remote access with weak auth is critical
3. **Simple Enumeration Works** - Common usernames often grant access
4. **VM Lab Environment** - OpenVPN + ping + nmap = functional attack framework
5. **Basic Linux Commands are Essential** - ls and cat are fundamental tools

---

## Methodology Confirmation

This machine confirmed the enumeration process:
- Step 1: Reconnaissance ✅ (ping, nmap)
- Step 2: Service Identification ✅ (telnet port 23)
- Step 3: Vulnerability Identification ✅ (default credentials)
- Step 4: Exploitation ✅ (telnet + username iteration)
- Step 5: Access Achieved ✅ (shell access as root)
- Step 6: Flag Capture ✅ (flag.txt found and read)

---

## Speed Optimization Tips

- Nmap can scan specific port ranges if you know what to look for
- Try common usernames immediately (admin, root, user)
- Telnet connects quickly - no complex setup needed
- Simple file operations (ls, cat) for flag capture

---

## What's Next

- Apply same methodology to next Easy box
- Expect slightly more complex vulnerabilities
- Build on telnet knowledge with other remote services
- Continue documenting each box

---

## Box Statistics

- **Difficulty:** Very Easy
- **Attack Complexity:** Minimal
- **Time to Compromise:** ~15-20 minutes (exploitation only)
- **Time to Document:** ~30-45 minutes
- **Total Time:** 1-2 hours
- **Key Skill:** Default credential exploitation

---

## Notes

First box complete! This machine served as the perfect introduction:
- Proved the lab environment works
- Confirmed basic tools and workflow
- Showed how simple vulnerabilities can grant full access
- Built confidence for next machines

**Status:** BOX PWNED ✅
