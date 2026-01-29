# SYNCED - Very Easy

**Date Completed:** January 29, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE  
**Focus Areas:** Rsync Exploitation & File Transfer Protocol

---

## Phase 1: Initial Reconnaissance

### Step 1: Port Scanning for Rsync
```
nmap-port 873 TARGET_IP
```

**Alias Definition:**
```bash
alias nmap-port='nmap -sS -sV -p'
```

**Findings:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 873 | Rsync | Protocol 31 | Open |

**Critical Finding:** Rsync (Protocol 31) running on default port 873 - only service exposed

---

## Rsync Fundamentals

### What is Rsync?
- **Purpose:** Remote file synchronization and backup tool
- **Protocol:** Custom binary protocol for efficient file transfers
- **Default Port:** 873 (TCP)
- **Use Case:** Backup automation, file synchronization, data transfer
- **Authentication:** Can operate with or without credentials

### Rsync Architecture
```
Rsync Client (us)
    ↓
    └─→ Rsync Server (Target:873)
         ├── Module 1 (Share)
         ├── Module 2 (Share)  ← public
         └── Module 3 (Share)
              ├── flag.txt
              ├── data.txt
              └── [files]
```

### Rsync Protocol Versions
- **Protocol 31:** Older version (target running this)
- **Modern versions:** 32+
- **Compatibility:** Older clients can connect to newer servers

---

## Phase 2: Rsync Anonymous Access & Enumeration

### Step 1: List Available Rsync Modules (Shares)
```
rsync --list-only TARGET_IP::
```

**Command Breakdown:**
- `rsync`: Invoke rsync client
- `--list-only`: List available modules/shares (do not transfer)
- `TARGET_IP::`: Double colon indicates rsync protocol on remote server
- No username/password: Anonymous authentication

**Output:** Lists available shares/modules on rsync server
```
public
private
backup
```

**Key Finding:** `public` module discovered as accessible share

### Step 2: Enumerate Contents of Public Module
```
rsync --list-only TARGET_IP::public
```

**Result:** Lists all files and directories in `public` module
```
-rw-r--r--        1024  Jan 29 10:30  flag.txt
-rw-r--r--        2048  Jan 29 10:25  readme.txt
drwxr-xr-x        4096  Jan 29 10:20  subfolder
```

**Key Finding:** `flag.txt` identified in public module - target located!

---

## Phase 3: File Transfer via Rsync

### Step 1: Critical Understanding - File Transfer Syntax

**WRONG Approach (Common Mistake):**
```
rsync TARGET_IP::public/flag.txt
```
**Result:** FAILS - Only lists filename, doesn't transfer file to local machine

**CORRECT Approach:**
```
rsync TARGET_IP::public/flag.txt flag.txt
```
**Breakdown:**
- `rsync`: Invoke rsync
- `TARGET_IP::public/flag.txt`: Remote file path (source)
- `flag.txt`: Local destination path (where to save)
- **Two arguments required:** source AND destination

**Why This Matters:**
- **Single argument:** Rsync interprets as list-only mode
- **Two arguments:** Rsync interprets as actual file transfer
- File paths on both sides must be specified for transfer to occur

### Step 2: Transfer Flag File to Local Machine
```
rsync TARGET_IP::public/flag.txt flag.txt
```

**Result:** `flag.txt` downloaded to current directory on attack machine

**Verification:**
```
ls -la flag.txt
```
Shows file exists locally with proper size and permissions

---

## Phase 4: Flag Retrieval

### Step 1: Display Flag Contents
```
cat flag.txt
```

**Result:** Flag displayed to terminal ✅

---

## Rsync Command Reference

| Command | Purpose | Result |
|---------|---------|--------|
| `rsync --list-only TARGET::` | List all modules | Shows available shares |
| `rsync --list-only TARGET::module` | List module contents | Shows files in share |
| `rsync TARGET::module/file local.txt` | Download file | Transfers file locally |
| `rsync local.txt TARGET::module/` | Upload file | Sends file to remote |
| `rsync -r TARGET::module/ local/` | Download directory | Transfers entire folder |
| `rsync -v TARGET::module/file local.txt` | Verbose transfer | Shows transfer progress |
| `rsync --dry-run TARGET::module/file local.txt` | Test transfer | Simulates without transferring |

---

## Exploitation Chain Summary

1. **Reconnaissance** → Detected rsync on port 873 (Protocol 31)
2. **Service Identification** → Identified rsync service and version
3. **Module Enumeration** → Listed available rsync shares with `--list-only`
4. **Module Contents** → Enumerated `public` module contents
5. **File Discovery** → Located `flag.txt` in public module
6. **File Transfer** → Downloaded flag.txt to local machine
7. **Flag Extraction** → Displayed flag with `cat flag.txt`
8. **Success** → Flag captured ✅

---

## Key Techniques & Tools

| Technique | Tool/Command | Purpose |
|-----------|--------------|---------|
| Port Scanning | nmap -sS -sV -p 873 | Detect rsync service |
| Module Enumeration | rsync --list-only | Discover available shares |
| Directory Listing | rsync --list-only module | Browse remote directory |
| File Download | rsync source destination | Transfer files locally |
| File Verification | ls, file command | Confirm local file transfer |
| Content Display | cat | View flag contents |

---

## Critical Lessons Learned

### Rsync-Specific Knowledge
1. **Default Port 873** - Standard rsync port (often overlooked)
2. **Double Colon Syntax** - `TARGET::module` indicates rsync protocol
3. **Anonymous Access** - Rsync often allows unauthenticated connections
4. **List-Only Mode** - `--list-only` for safe enumeration without transfer
5. **Two-Argument Transfer** - Both source AND destination required for file transfer

### Common Mistake: Single Argument
```bash
# WRONG - Only lists, doesn't transfer
rsync TARGET::public/flag.txt

# CORRECT - Actually transfers file
rsync TARGET::public/flag.txt flag.txt
```

**Why This Matters:**
- Easy to miss the second argument requirement
- Flag still retrievable with single argument (via stdout redirection)
- Understanding syntax is critical for effective file exfiltration

### File Exfiltration Patterns
1. **Enumeration First** - Always list contents before transfer
2. **Target Identification** - Know what files exist
3. **Careful Paths** - Specify exact remote and local paths
4. **Verification** - Confirm files transferred correctly
5. **Content Validation** - Check file contents after transfer

### Rsync Security Implications
**Why Rsync Port 873 is Dangerous:**
- ❌ Anonymous access enabled by default
- ❌ No authentication required
- ❌ Directory listing allows reconnaissance
- ❌ File transfer without credentials
- ❌ Often overlooked in security audits

**Real-World Risks:**
- Sensitive file exfiltration
- Backup data exposure
- Configuration file discovery
- Source code repository access
- Unnoticed data breaches

---

## Comparison to Previous Boxes

| Aspect | SYNCED | Previous Boxes |
|--------|--------|-----------------|
| Protocol | Rsync (873) | HTTP (80), RDP (3389), Mongo (27017) |
| Complexity | Low - straightforward file transfer | Varies |
| Exploitation | Anonymous access | Default credentials / RCE |
| Main Challenge | Understanding rsync syntax | Privilege escalation / code injection |
| Data Source | File system | Web applications / databases |
| Difficulty | Very Easy | Very Easy to Easy |

---

## Rsync vs Other Transfer Methods

| Method | Protocol | Port | Auth | Use Case |
|--------|----------|------|------|----------|
| **Rsync** | Custom | 873 | Optional | Efficient sync/backup |
| **FTP** | FTP | 21 | Optional | Legacy file transfer |
| **SFTP** | SSH | 22 | Required | Secure file transfer |
| **HTTP** | HTTP | 80 | Optional | Web-based transfer |
| **SCP** | SSH | 22 | Required | Secure copy protocol |

---

## Status

✅ **BOX PWNED**
- Flag: Retrieved ✓
- Rsync enumeration successful ✓
- File transfer executed ✓

**Speed:** Very Easy classification accurate - straightforward enumeration and file transfer

**Key Achievement:** Learned rsync exploitation and file transfer syntax nuances

---

## Important Notes

**The Two-Argument Lesson:**
This box highlights why syntax understanding is critical:
- Single argument = listing/enumeration mode
- Two arguments = actual data transfer
- Missing second argument = incomplete exploitation

**Real-World Application:**
Rsync is commonly used for:
- Automated backups (vulnerable if exposed)
- Data synchronization (potential data leakage)
- Disaster recovery (sensitive information at risk)
- Mirror sites (accessible without authentication)

**Security Takeaway:**
Rsync is often overlooked in security assessments but represents a genuine data exfiltration risk when:
- Exposed on network
- Anonymous access enabled
- Sensitive files in accessible modules
- Backup systems misconfigured

**Takeaway:** Understanding less common protocols like rsync expands exploitation opportunities! 🎯
