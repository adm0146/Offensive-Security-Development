# TACTICS - Very Easy

**Date Started:** February 3, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE

---

## Phase 1: Initial Reconnaissance

### Step 1: Initial Service Enumeration Scan

**Challenge:** Windows firewall blocks ICMP ping packets (traditional connectivity test)

**Solution:** Use nmap with `-Pn` flag to skip host discovery

**Command:**
```bash
nmap -Pn TARGET_IP
```

**Explanation:**
- `-Pn`: Skip ICMP ping check (treats host as up regardless)
- Allows scanning even when ICMP is blocked by firewall
- Proceeds directly to port scanning

**Key Finding:** Port 445 (SMB) is open

| Port | Service | Protocol | Status |
|------|---------|----------|--------|
| 445 | SMB | Server Message Block | Open |

**Technology Identified:** Windows file sharing protocol (SMB/CIFS)

---

## Phase 2: SMB Enumeration & Share Discovery

### Step 1: Display SMB Client Help Menu

**Command:**
```bash
smbclient -h
```

**Purpose:** Review available switches and connection options

**Key Switches Learned:**
- `-L`: List available shares
- `-U`: Specify username for authentication
- `-N`: Suppress password prompt (null session)

### Step 2: List Available SMB Shares

**Command:**
```bash
smbclient -L TARGET_IP -U Administrator
```

**Explanation:**
- `-L TARGET_IP`: List shares on target machine
- `-U Administrator`: Attempt connection as Administrator user
- **Note:** No password specified → attempts null authentication or prompts for password

**Expected Shares on Windows System:**

| Share | Type | Symbol | Purpose | Accessibility |
|-------|------|--------|---------|----------------|
| C$ | Admin Share | $ | Full C: drive access | Restricted to admins |
| ADMIN$ | Admin Share | $ | Windows admin directory | Restricted to admins |
| IPC$ | Admin Share | $ | Inter-process communication | Special |

**Key Discovery:** Admin shares (indicated by `$` suffix) are visible and potentially accessible

### Step 3: Explore ADMIN$ Share

**Command:**
```bash
smbclient \\\\TARGET_IP\\ADMIN$ -U Administrator
```

**Explanation:**
- Connect to the ADMIN$ share
- `\\\\` (four backslashes) required in bash (escaped for shell)
- `-U Administrator`: Authenticate as Administrator

**Result:** Connected but limited file access - ADMIN$ share contains only system files

**Finding:** No useful flag or data in ADMIN$ share

---

## Phase 3: Access C$ Share (Full Filesystem)

### Step 1: Connect to C$ Share

**Command:**
```bash
smbclient \\\\TARGET_IP\\C$ -U Administrator
```

**Explanation:**
- Connect to C$ share (full C: drive)
- Provides access to entire Windows filesystem
- Administrator privileges required

**Result:** ✅ Successfully connected to C$ share

### Step 2: List Directory Contents

**SMB Command (at `smb: \>` prompt):**
```
dir
```

**Response:** Directory listing of C: drive root

**Directories Found:**
- Users/
- Windows/
- Program Files/
- Desktop/

### Step 3: Navigate to Administrator Desktop

**SMB Command:**
```
cd Users/Administrator/Desktop
```

**Explanation:**
- Navigate through SMB filesystem hierarchy
- Moves to Administrator user's Desktop directory

### Step 4: List Desktop Contents

**SMB Command:**
```
dir
```

**Response:** Desktop directory listing

**File Found:**
```
flag.txt
```

### Step 5: Download Flag File

**SMB Command:**
```
get flag.txt
```

**Explanation:**
- Downloads `flag.txt` from SMB share to attacker machine
- File is transferred via SMB protocol
- Saved in current local working directory

**Result:** ✅ Flag file successfully downloaded

### Step 6: Read Flag

**Local Command (on attacker machine):**
```bash
cat flag.txt
```

**Result:** Flag content displayed successfully!

---

## Key Findings

| Item | Details |
|------|---------|
| **Vulnerability Type** | Excessive file share permissions / Admin share exposure |
| **Attack Vector** | SMB protocol (port 445) |
| **Access Required** | Administrator credentials (or null session if available) |
| **Privilege Level** | Full system access via C$ share |
| **Root Cause** | Admin shares enabled and accessible |
| **Data Exposure** | Entire C: drive accessible |

### Exploitation Chain Summary

1. **Reconnaissance** → Identify SMB on port 445 using `-Pn` flag (bypass ICMP)
2. **SMB Enumeration** → List available shares with smbclient
3. **Share Discovery** → Identify admin shares (ADMIN$, C$)
4. **Authentication** → Connect as Administrator user
5. **Filesystem Access** → Navigate C$ share to Users/Administrator/Desktop
6. **File Retrieval** → Download flag.txt via SMB
7. **Flag Capture** → Read flag on attacker machine

### Security Issues Identified

- **Admin Shares Exposed:** C$ and ADMIN$ shares publicly visible/accessible
- **Weak Access Controls:** Admin shares shouldn't be accessible to unauthorized users
- **Excessive Privileges:** Administrator credentials not properly restricted
- **No Network Segmentation:** SMB exposed to entire network
- **Shared Filesystem Access:** Entire C: drive accessible via single share
- **No Encryption:** SMB communications potentially unencrypted (SMBv1)

---

## Quick Reference: SMB Exploitation

### When You Find SMB (Port 445):

1. **Check Connectivity:**
   ```bash
   nmap -Pn -p445 TARGET_IP  # -Pn skips ICMP ping
   ```

2. **List Available Shares:**
   ```bash
   smbclient -L TARGET_IP -U USERNAME
   smbclient -L TARGET_IP -N  # Null session attempt
   ```

3. **Connect to Specific Share:**
   ```bash
   smbclient \\\\TARGET_IP\\SHARENAME -U USERNAME
   ```

4. **Common Admin Shares (marked with $):**
   - `C$` - Full C: drive access
   - `ADMIN$` - Windows admin directory
   - `IPC$` - Inter-process communication
   - `D$`, `E$`, etc. - Other drive letters

5. **SMB Interactive Commands:**

   | Command | Purpose |
   |---------|---------|
   | `dir` | List directory contents |
   | `cd DIRECTORY` | Change directory |
   | `get FILENAME` | Download file to attacker |
   | `put FILENAME` | Upload file to share |
   | `ls -la` | Detailed listing |
   | `pwd` | Print working directory |
   | `exit` | Disconnect from share |

6. **Alternative Tools:**
   - `smbmap` - Map all available shares
   - `psexec.py` - Execute commands remotely (Impacket)
   - `impacket-psexec` - Modern syntax for psexec
   - `crackmapexec` - Advanced SMB enumeration and exploitation

### Impacket Collection Tools:

**psexec.py Usage:**
```bash
python3 psexec.py DOMAIN/USERNAME:PASSWORD@TARGET_IP
```
- Execute commands remotely
- Requires valid credentials
- Full system access if credentials are admin

### Defensive Recommendations

- **Disable Admin Shares:** If not required, disable C$, ADMIN$, IPC$ shares
- **Network Segmentation:** Restrict SMB to internal networks only
- **Access Controls:** Limit who can access SMB shares
- **Strong Credentials:** Use complex, unique passwords for admin accounts
- **SMBv3 Only:** Disable SMBv1 and SMBv2 (use SMBv3 with encryption)
- **Firewall Rules:** Block port 445 from untrusted networks
- **Audit Logging:** Monitor SMB access and share enumeration
- **Principle of Least Privilege:** Don't share entire drives unnecessarily
- **VPN/Zero Trust:** Require VPN for remote SMB access

### Port 445 vs Port 139 (SMB)

| Port | Protocol | Advantages | Disadvantages |
|------|----------|-----------|---------------|
| 445 | Direct SMB over TCP | Faster, more reliable | Less firewall filtering historically |
| 139 | SMB over NetBIOS | Older standard | Slower, less reliable |

Both carry same risks - restrict both if possible.

---

**Status:** ✅ FLAG CAPTURED - FULL FILESYSTEM ACCESS ACHIEVED

