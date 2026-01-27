# Explosion - Very Easy

**Date Completed:** January 27, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE  
**Focus Areas:** RDP (Remote Desktop Protocol) & CLI (Command Line Interface)

---

## Phase 1: Initial Reconnaissance

### Step 1: RDP Port Detection
```
nmap -sS -sV -p 3389 TARGET_IP
```

**Scan Explanation:**
- `-sS`: TCP SYN stealth scan
- `-sV`: Service version detection
- `-p 3389`: Target specific RDP port (default RDP port)

**Findings:**

| Port | Service | Full Name | Status |
|------|---------|-----------|--------|
| 3389 | ms-wbt-server | Microsoft RDP (Remote Desktop Protocol) | Open |

**Critical Information:** RDP (Remote Desktop Protocol) is Microsoft's remote access solution, allowing graphical GUI access to Windows systems

---

## Key Concepts: RDP vs CLI vs GUI

### RDP (Remote Desktop Protocol)
- **Purpose:** Microsoft's remote desktop access protocol
- **Default Port:** 3389
- **Access Type:** Full graphical user interface (GUI)
- **Use Case:** Complete desktop environment access, file management, GUI applications

### CLI (Command Line Interface)
- **Purpose:** Text-based command execution
- **Access Type:** Terminal/command prompt
- **Use Case:** Server administration, scripting, network troubleshooting

### GUI (Graphical User Interface)
- **Purpose:** Visual desktop environment
- **Components:** Windows, icons, menus, mouse support
- **Use Case:** User-friendly interaction with system resources

---

## Phase 2: RDP Connection

### Step 1: Initial RDP Connection Attempt
```
xfreerdp3 /v:TARGET_IP /u:Administrator /cert:ignore
```

**Command Flags Explanation:**
- `xfreerdp3`: RDP client (Linux/Unix tool for connecting to RDP)
- `/v:TARGET_IP`: Target hostname or IP address (CRITICAL flag)
- `/u:Administrator`: Target username to authenticate as
- `/cert:ignore`: Ignore SSL/TLS certificate warnings (common on HTB labs)

**Result:** Connection established to RDP login screen

### Step 2: Authentication
Upon connection, RDP login screen appeared with username field pre-populated as "Administrator"

**Authentication Attempt:**
- Username: Administrator
- Password: (pressed Enter - blank/empty password accepted)

**Result:** Successfully authenticated with no password required

### Step 3: GUI Desktop Access
Upon successful login, full Windows GUI desktop environment loaded

**Desktop Contents:**
- Standard Windows desktop interface
- Taskbar at bottom
- File visible on desktop: `flag.txt`

### Step 4: Flag Retrieval
Located `flag.txt` on desktop and opened to view contents

**Result:** Flag captured ✅

---

## RDP Connection Optimization

### Creating RDP Alias
Manually typing full xfreerdp3 command with all flags is tedious. Created bash alias for faster connections:

**Alias Definition:**
```bash
alias rdp='xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression'
```

**Additional Flags in Alias:**
- `/cert:ignore`: Ignore certificate warnings
- `/dynamic-resolution`: Adjust resolution dynamically when window is resized
- `+clipboard`: Enable clipboard sharing between attack machine and RDP session
- `/compression`: Enable compression for faster network performance

**Usage After Alias:**
Instead of full command:
```bash
xfreerdp3 /v:TARGET_IP /u:Administrator /cert:ignore /dynamic-resolution +clipboard /compression
```

Simply type:
```bash
rdp /v:TARGET_IP /u:Administrator
```

**Implementation:**
Add to `~/.bashrc` or `~/.zshrc`:
```bash
alias rdp='xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression'
```

Then reload shell configuration:
```bash
source ~/.bashrc
# or
source ~/.zshrc
```

---

## Exploitation Chain Summary

1. **Reconnaissance** → Nmap detected RDP on port 3389 (ms-wbt-server)
2. **Connection** → Connected via xfreerdp3 client
3. **Authentication** → Default/empty password accepted for Administrator
4. **GUI Access** → Full Windows desktop environment loaded
5. **Flag Discovery** → Found flag.txt on desktop
6. **Flag Retrieval** → Opened file and captured flag

---

## Key Techniques & Tools

| Technique | Tool/Command | Purpose |
|-----------|--------------|---------|
| Port Scanning | nmap -sS -sV -p 3389 | Detect RDP service |
| RDP Connection | xfreerdp3 | Linux RDP client for Windows access |
| GUI Access | xfreerdp3 parameters | Remote desktop GUI interaction |
| File Access | Windows File Explorer | Locate and access flag file |
| Efficiency | bash alias | Streamline repetitive commands |

---

## Critical Lessons Learned

### RDP Fundamentals
1. **RDP Default Port** - Port 3389 is standard RDP port on Windows systems
2. **xfreerdp3 Client** - Primary Linux tool for RDP connections to Windows targets
3. **Certificate Warnings** - `/cert:ignore` flag bypasses SSL warnings common in lab environments
4. **Credential Options** - RDP can accept blank passwords, default credentials, or compromised creds
5. **GUI Access** - RDP provides full graphical interface unlike SSH (which is CLI by default)

### Operational Efficiency
1. **Bash Aliases** - Creating aliases for commonly used commands saves time and reduces typing errors
2. **Clipboard Sharing** - `/clipboard` flag enables copy/paste between machines (very useful for passwords, commands)
3. **Dynamic Resolution** - `/dynamic-resolution` automatically adjusts to window size for better UX
4. **Compression** - `/compression` reduces bandwidth usage for faster responsiveness

### Windows vs Linux Mindset
- Windows systems use RDP (graphical) by default
- Linux systems use SSH (command line) by default
- Both can be exploited, but with different tools and methodologies
- Understanding both platforms is critical for pentesting

---

## Windows-Specific Observations

1. **No SSH by Default** - Windows doesn't run SSH natively (though newer versions support it)
2. **RDP Standard** - RDP is the primary remote access method for Windows
3. **Default Credentials** - Windows systems sometimes have weak/default credentials on lab machines
4. **Flag Location** - Desktop is accessible GUI location for CTF flags
5. **File Explorer** - Used instead of command line for file navigation in GUI mode

---

## Comparison to Previous Boxes

| Aspect | Explosion | Previous Linux Boxes |
|--------|-----------|----------------------|
| OS | Windows | Linux |
| Primary Protocol | RDP (port 3389) | SSH (port 22) / HTTP (port 80) |
| Access Type | GUI (Graphical) | CLI (Command Line) |
| Authentication | Basic RDP login | SSH keys or credentials |
| Tools | xfreerdp3 | SSH, nmap, curl |
| Complexity | Very Easy - straightforward | Easy - requires enumeration |
| Flag Location | Desktop | Home directory / root |

---

## Key Takeaway

This box demonstrated:
- ✅ Port-specific nmap scanning
- ✅ Understanding different remote access protocols (RDP vs SSH)
- ✅ Using appropriate tools for target OS (xfreerdp3 for Windows)
- ✅ Recognizing weak/default credentials
- ✅ Efficiency through automation (bash aliases)

**Important Realization:** Not all HTB boxes are Linux-based. Windows systems require different tools and methodologies. Mastering both is essential for comprehensive penetration testing skills.

---

## Status

✅ **BOX PWNED**
- Flag: Retrieved ✓
- RDP connection successful ✓
- Bash alias created for future use ✓

**Speed:** Fastest box yet - Very Easy classification accurate (simple default credentials, GUI-based flag)

**New Skill:** Introduction to Windows RDP exploitation and cross-platform penetration testing methodologies
