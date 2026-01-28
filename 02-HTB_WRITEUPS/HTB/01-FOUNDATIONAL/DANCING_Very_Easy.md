# DANCING - Very Easy

**Date:** January 23, 2026  
**Difficulty:** Very Easy  
**Time Spent:** ~45 minutes  
**Status:** ✅ PWNED

---

## Machine Overview

DANCING is an introductory machine focused on SMB (Server Message Block) enumeration and exploitation. It demonstrates null authentication on SMB shares, custom share identification, and lateral file access through basic SMB commands.

---

## Key Concepts Learned

- SMB (Server Message Block) protocol fundamentals
- Port 445 identification and microsoft-ds service
- SMB share enumeration with smbclient flags (-L, -N)
- Custom shares vs system shares ($ suffix differentiation)
- Null authentication exploitation (no password required)
- Directory traversal across multiple user shares
- File exfiltration via SMB get command

---

## Reconnaissance

### Connection Verification
- Used ping to confirm OpenVPN connection to target
- Connection stable and responsive

### Service Enumeration
```
nmap -sV -sS TARGET_IP
```

**Findings:**
- Port 445: SMB service (microsoft-ds)
- Service: Server Message Block
- Authentication: Potentially null/anonymous
- No additional ports initially critical

---

## Service Information

**SMB (Server Message Block)**
- **Port:** 445 (also legacy port 139 for older systems)
- **Service Name:** microsoft-ds (Microsoft Directory Services)
- **Protocol:** File sharing, printer sharing, network access
- **Authentication:** Can support anonymous/null sessions
- **Share Types:** System shares ($) vs Custom shares

**Share Naming Convention:**
- Shares ending in `$` = System shares (hidden from normal browsing)
- Shares without `$` = Custom shares (user-created, often misconfigured)

---

## Vulnerabilities Identified

### Vulnerability 1: Null Authentication on SMB Shares
- **Type:** Authentication Bypass
- **Port:** 445
- **Severity:** High
- **Impact:** Unauthenticated access to shared files
- **Discovery Method:** SMB enumeration with -N flag
- **Root Cause:** Shares configured to allow null/anonymous access
- **Exploitation:** smbclient with -N (no password) flag

### Vulnerability 2: Custom Shares Without Access Controls
- **Type:** Improper Access Control / Information Disclosure
- **Finding:** WorkShares custom share accessible without authentication
- **Pattern:** Custom shares (no $) often indicate misconfiguration
- **Impact:** Direct access to user directories (Amy J., James.P)

### Vulnerability 3: Sensitive Files in Shared Directories
- **Type:** Information Disclosure
- **Finding:** flag.txt stored in user-accessible share
- **Location:** James.P directory within WorkShares
- **Impact:** Direct flag retrieval without privilege escalation

---

## Exploitation Chain

### Phase 1: SMB Share Enumeration

**Step 1: List all available shares**
```
smbclient -L TARGET_IP
```

**Output:** List of all shares on target

**Key Observation:** WorkShares (no $) identified as custom share

### Phase 2: Null Authentication Access

**Step 1: Connect to WorkShares with null authentication**
```
smbclient //TARGET_IP/WorkShares -N
```

**Flag Explanation:**
- `-N` = Null authentication (no password prompt)
- Success indicates share allows anonymous access
- Prompt changes to `smb: \>`

### Phase 3: Directory Enumeration

**Step 1: List contents of WorkShares**
```
smb: \> ls
```

**Output:** 
- Amy.J directory
- James.P directory

**Step 2: Navigate to James.P directory**
```
smb: \> cd James.P
```

**Step 3: List contents**
```
smb: \> ls
```

**Finding:** flag.txt file located

### Phase 4: File Exfiltration

**Step 1: Download flag file**
```
smb: \> get flag.txt
```

**Step 2: Exit SMB share**
```
smb: \> quit
```

### Phase 5: Flag Capture

**Step 1: Read exfiltrated file on local machine**
```
cat flag.txt
```

**Flag Retrieved:** [flag content]

---

## Attack Summary

1. Verified network connectivity with ping
2. Ran nmap -sV to detect SMB service on port 445
3. Enumerated available shares with smbclient -L
4. Identified custom share "WorkShares" (no $ suffix)
5. Exploited null authentication with -N flag
6. Navigated to James.P user directory
7. Located flag.txt file
8. Exfiltrated flag.txt using get command
9. Retrieved flag with cat command on local system

---

## Key Techniques Used

- **Nmap -sV:** Service version detection
- **Nmap -sS:** TCP SYN scan
- **smbclient -L:** List SMB shares
- **smbclient -N:** Null authentication connection
- **SMB ls:** Directory enumeration
- **SMB cd:** Directory traversal
- **SMB get:** File exfiltration
- **Cat:** Local file reading

---

## Tools Used

- Ping (network testing)
- Nmap with -sV and -sS flags (service detection)
- smbclient (SMB client connection and enumeration)
- Linux shell commands (cat)

---

## SMB Command Reference

**smbclient Flags:**
```
-L          # List shares on target
-N          # Null authentication (no password)
-U          # Specify username
```

**SMB Share Commands:**
```
ls          # List directory contents
cd          # Change directory
pwd         # Print working directory
get         # Download file
put         # Upload file
quit        # Exit SMB share
```

---

## Lessons Learned

1. **SMB Null Authentication is Critical Vulnerability** - Many systems misconfigured to allow anonymous access
2. **Custom Shares are Suspicious** - Shares without $ suffix often indicate weak security
3. **Share Enumeration is Essential** - List all available shares before targeting specific ones
4. **Directory Traversal Across Shares** - User directories often stored in accessible shares
5. **-N Flag is Powerful** - Null authentication flag immediately tests for this vulnerability
6. **Sensitive Files in Shares** - Flags, credentials, documents often stored in accessible locations
7. **SMB Lateral Access** - Can move between user directories without privilege escalation

---

## Methodology Confirmation

This machine confirmed the enumeration process for network file services:
- Step 1: Reconnaissance ✅ (ping, nmap -sV -sS)
- Step 2: Service Identification ✅ (SMB port 445, microsoft-ds)
- Step 3: Share Enumeration ✅ (smbclient -L, identify custom shares)
- Step 4: Vulnerability Identification ✅ (null authentication on WorkShares)
- Step 5: Exploitation ✅ (smbclient -N connection)
- Step 6: Directory Traversal ✅ (navigate to James.P)
- Step 7: File Enumeration ✅ (ls within share)
- Step 8: Data Exfiltration ✅ (get flag.txt)
- Step 9: Flag Capture ✅ (cat flag.txt)

---

## Speed Optimization

**What Worked:**
- Nmap -sV identified SMB immediately
- smbclient -L provided instant share list
- Custom share (WorkShares) stood out without $ suffix
- Null authentication (-N) worked on first attempt
- Quick directory navigation with cd
- Direct get command for exfiltration

**Time Breakdown:**
- Reconnaissance: 5 minutes (ping, nmap)
- Share Enumeration: 5 minutes (smbclient -L)
- Null Auth Exploitation: 3 minutes (smbclient -N)
- Directory Traversal: 7 minutes (navigating user folders)
- File Enumeration: 5 minutes (finding flag.txt)
- Exfiltration: 3 minutes (get, cat)
- Total: ~45 minutes

---

## Comparison to Previous Boxes

| Aspect | MEOW | FAWN | DANCING |
|--------|------|------|---------|
| Service | Telnet | FTP | SMB |
| Port | 23 | 21 | 445 |
| Auth Bypass | Default password | Anonymous | Null authentication |
| Time | <20 mins | 32 mins | 45 mins |
| Complexity | Minimal | Low | Low-Medium |
| Access Type | Shell | File transfer | Network shares |
| Key Technique | Shell login | FTP get | SMB navigation |

**Pattern Observation:** Time increasing slightly due to more complex enumeration (share discovery, directory traversal) but speed improving with each protocol variation

---

## SMB Enumeration Methodology

**Standard SMB Attack Pattern:**
1. Identify SMB on port 445 (nmap -sV)
2. List all shares (smbclient -L)
3. Identify interesting shares (custom shares, writable shares)
4. Attempt null authentication (smbclient -N)
5. Try default credentials if null fails
6. Enumerate directories and files
7. Identify sensitive files or escalation paths
8. Extract or exploit as needed

---

## Real-World Context

**Why SMB Matters:**
- Windows file sharing protocol (ubiquitous in corporate networks)
- Null authentication = common real-world vulnerability
- Often misconfigured in mixed networks
- Lateral movement vector after initial access
- Common entry point for ransomware and worms

---

## Notes

Third box complete! Momentum building:

- Three different protocols conquered (Telnet, FTP, SMB)
- Pattern emerging: Enumerate → Identify → Exploit → Extract
- Each box introduces new concepts while reinforcing fundamentals
- Time slightly increased due to directory traversal, but efficiency improving
- Successfully navigated SMB share hierarchy without getting lost

**Status:** BOX PWNED ✅

---

## What's Next

- Continue Easy boxes (3 of 6-8 complete)
- Next boxes may combine multiple services or introduce privilege escalation
- Speed should improve as enumeration patterns become automatic
- Start seeing post-exploitation requirements
- Build confidence for Medium machines (early February)
