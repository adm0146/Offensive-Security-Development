# Host and Port Scanning

---

## 🚀 Quick Reference - Copy/Paste Commands

### Host Discovery Scans

**Scan Network Range**
```bash
sudo nmap 10.129.2.0/24 -sn -oA network_scan
```
Discovers all active hosts on a network subnet using ping sweep (ICMP echo requests).

**Scan IP List**
```bash
sudo nmap -sn -oA ip_list_scan -iL hosts.txt
```
Scans multiple targets from a file list and identifies which hosts are online.

**Scan Multiple Individual IPs**
```bash
sudo nmap -sn -oA individual_ips 10.129.2.18-20
```
Discovers active hosts in a specific range using consecutive IP notation for quick reconnaissance.

**Scan Single IP**
```bash
sudo nmap 10.129.2.18 -sn -oA single_host_scan
```
Determines if a single target host is alive before conducting deeper port and service scans.

---

### Port Scanning Scans

**Quick Port Scan (Top 1000)**
```bash
sudo nmap 10.129.2.28 -sS -oA quick_port_scan
```
Scans the 1000 most common TCP ports using SYN scan (stealth method) for fast reconnaissance.

**Fast Port Scan (Top 100)**
```bash
sudo nmap 10.129.2.28 -F -oA fast_scan
```
Scans only the top 100 most common ports for rapid target assessment.

**Top N Ports**
```bash
sudo nmap 10.129.2.28 --top-ports=20 -oA top20_ports
```
Scans the N most frequently used ports from Nmap database (customize number as needed).

**All Ports Scan**
```bash
sudo nmap 10.129.2.28 -p- -oA all_ports
```
Scans all 65,535 TCP ports for comprehensive target mapping (slow but thorough).

**Specific Port Range**
```bash
sudo nmap 10.129.2.28 -p 20-25,80,443,3306 -oA custom_ports
```
Scans custom port selection combining ranges and individual ports for targeted reconnaissance.

**TCP Connect Scan (Non-root)**
```bash
sudo nmap 10.129.2.28 -sT -oA tcp_connect
```
Performs full TCP three-way handshake for accurate port detection (completes connection, easily logged).

**TCP SYN Scan (Default - Root)**
```bash
sudo nmap 10.129.2.28 -sS -oA syn_scan
```
Half-open SYN scan that doesn't complete handshake (stealthier, faster, requires root privileges).

**UDP Port Scan**
```bash
sudo nmap 10.129.2.28 -sU -F -oA udp_scan
```
Scans UDP ports for stateless protocols (DNS, SNMP, DHCP); much slower than TCP scanning.

---

### Service Detection & Analysis

**Service Version Detection**
```bash
sudo nmap 10.129.2.28 -sV -oA service_detection
```
Identifies service names, versions, and configurations on open ports using probe matching.

**Detailed Service Scan**
```bash
sudo nmap 10.129.2.28 -sV -sC -oA detailed_scan
```
Combines service detection with default NSE scripts for deeper service enumeration and vulnerability checks.

**Service Detection on Specific Port**
```bash
sudo nmap 10.129.2.28 -p 445 -sV -oA smb_detection
```
Detects and fingerprints service version on a specific port (useful for targeted service identification).

---

### Packet-Level Analysis

**Packet Trace - Host Discovery**
```bash
sudo nmap 10.129.2.28 -sn -Pn -n --disable-arp-ping --packet-trace -oA packet_trace_host
```
Shows every packet sent and received during host discovery (reveals ARP vs ICMP behavior).

**Packet Trace - Port Scan**
```bash
sudo nmap 10.129.2.28 -p 445 -Pn -n --disable-arp-ping --packet-trace --reason -oA packet_trace_port
```
Displays detailed packet exchange during port scan with reason explanations (SYN/RST analysis).

**Packet Trace - Service Detection**
```bash
sudo nmap 10.129.2.28 -p 445 -sV -Pn -n --disable-arp-ping --packet-trace -oA packet_trace_service
```
Shows probes sent and responses received during service version detection and fingerprinting.

---

### Advanced Options for All Scans

**Add These to Any Command for More Info:**
```bash
-Pn              # Skip ping (assume host is up)
-n               # Disable DNS resolution (faster)
--disable-arp-ping   # Disable ARP ping, force ICMP/TCP
--packet-trace   # Show all packets sent/received
--reason         # Display why port is in current state
-oA filename     # Save all formats (.nmap, .xml, .gnmap)
-v               # Verbose output
-vv              # Very verbose output
```

**Example with All Options:**
```bash
sudo nmap 10.129.2.28 -p 445 -sV -Pn -n --disable-arp-ping --packet-trace --reason -oA comprehensive_scan
```
Complete scan showing packet details, service versions, reasons for port states, and saved results.

---

---

## Overview

After confirming a target is alive, the next step is to obtain accurate information about the system:
- Open ports and their services
- Service versions
- Information about services provided
- Operating system details

Understanding how Nmap performs its scanning is critical to interpreting results correctly. This section explores port states, scanning methods, and packet-level analysis.

---

## Port States

Nmap identifies **6 different port states** during scanning. Understanding these is essential for accurate target assessment.

| Port State | Description | Meaning |
|-----------|-------------|---------|
| **open** | Connection successfully established to the port | TCP connection, UDP datagram, or SCTP association established |
| **closed** | TCP packet received with RST flag set | Port is accessible but no service listening; can indicate host is alive |
| **filtered** | Cannot determine if port is open/closed | No response received OR error code from target; likely blocked by firewall |
| **unfiltered** | Port is accessible (TCP-ACK scan only) | Cannot determine if port is open or closed behind filtering |
| **open\|filtered** | No response received for specific port | Firewall or packet filter likely protecting the port |
| **closed\|filtered** | IP ID idle scan only | Cannot determine if port is closed or filtered by firewall |

---

## TCP Port Scanning

### Default Scanning Behavior

**SYN Scan (-sS)** is the default when running Nmap as **root**:
- Requires raw socket permissions to create TCP packets
- Faster and stealthier than full connection
- Default scans top 1000 TCP ports

**TCP Connect Scan (-sT)** is the default when running as **non-root**:
- Performs complete TCP handshake
- Slower but works without special permissions
- Default scans top 1000 TCP ports

### Port Selection Options

Control which ports Nmap scans using these options:

| Option | Example | Purpose |
|--------|---------|---------|
| Individual ports | `-p 22,25,80` | Scan specific ports |
| Port range | `-p 22-445` | Scan sequential port range |
| Top ports | `--top-ports=10` | Scan most common N ports from Nmap database |
| All ports | `-p-` | Scan all 65,535 ports |
| Fast scan | `-F` | Scan top 100 most common ports |

### Scanning Top TCP Ports

**Purpose:** Quick reconnaissance of common services

**Command:**
```bash
sudo nmap 10.129.2.28 --top-ports=10
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `10.129.2.28` | Target IP address |
| `--top-ports=10` | Scan the 10 most common TCP ports from Nmap database |

**Expected Output:**
- Nmap displays open/closed status for top 10 ports
- Common ports scanned: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445

---

## Deep Dive: SYN Scan Analysis

### Understanding Packet Flow

To see exactly what Nmap sends and receives, use packet tracing and disable ICMP/DNS/ARP:

**Command:**
```bash
sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `-p 21` | Scan only port 21 |
| `--packet-trace` | Display all packets sent and received |
| `-Pn` | Skip ping (assume host is up) |
| `-n` | Disable DNS resolution |
| `--disable-arp-ping` | Disable ARP ping (force ICMP/TCP) |

### SYN Scan Packet Breakdown

#### SENT Packet (Outgoing)

```
SENT (0.0429s) TCP 10.10.14.2:63090 > 10.129.2.28:21 S ttl=56 id=57322 iplen=44 seq=1699105818 win=1024 mss 1460
```

**SENT Message Breakdown:**

| Field | Meaning |
|-------|---------|
| `SENT (0.0429s)` | Time when Nmap sent the packet |
| `TCP` | Protocol used (TCP in this case) |
| `10.10.14.2:63090 >` | Our source IP and ephemeral source port |
| `10.129.2.28:21` | Target IP and target port |
| `S` | **SYN flag** - initiating TCP connection |
| `ttl=56` | Time-To-Live value (hops before expiration) |
| `id=57322` | IP packet identification number |
| `iplen=44` | IP packet length in bytes |
| `seq=1699105818` | TCP sequence number (random start) |
| `win=1024` | TCP window size (receive buffer) |
| `mss 1460` | Maximum Segment Size (bytes per packet) |

#### RCVD Packet (Incoming)

```
RCVD (0.0573s) TCP 10.129.2.28:21 > 10.10.14.2:63090 RA ttl=64 id=0 iplen=40 seq=0 win=0
```

**RCVD Message Breakdown:**

| Field | Meaning |
|-------|---------|
| `RCVD (0.0573s)` | Time when Nmap received the packet |
| `TCP` | Protocol used (TCP) |
| `10.129.2.28:21 >` | Target source IP and port replying |
| `10.10.14.2:63090` | Our destination IP and port being replied to |
| `RA` | **RST + ACK flags** - connection rejected |
| `ttl=64` | Target's TTL value |
| `id=0` | Target's IP packet ID |
| `iplen=40` | Response packet length |
| `seq=0` | TCP sequence number in response |
| `win=0` | Target's window size (connection closing) |

### Interpreting the Handshake

**Three-way handshake attempt (SYN scan):**

1. **We send SYN** → `S` flag to target port 21
2. **Target responds with RST+ACK** → `RA` flags
   - RST (Reset): Connection rejected
   - ACK (Acknowledge): Acknowledges receipt of our SYN
3. **Port is CLOSED** → If port had service, would respond with SYN+ACK

**Key Insight:** Closed ports reply faster with RST, helping us identify they're accessible but not listening.

---

## Port Scanning Patterns

### Identifying Service Availability

**When port is OPEN (service listening):**
- Target would respond: `SYN+ACK (SA)` flags
- Nmap continues 3-way handshake completion
- Indicates service is actively listening

**When port is CLOSED (no service):**
- Target responds: `RST+ACK (RA)` flags
- Nmap immediately marks as closed
- Indicates host is reachable but port has no service

**When port is FILTERED (firewall blocking):**
- No response received (timeout)
- Target may send ICMP "Destination Unreachable"
- Indicates firewall/filter protection

---

## Scanning Strategy

### Quick Assessment (Common Ports)

```bash
sudo nmap 10.129.2.28 --top-ports=20
```
- Fast reconnaissance of most likely services
- Takes seconds to complete
- Identifies web servers, SSH, databases

### Comprehensive Assessment (Common + Custom)

```bash
sudo nmap 10.129.2.28 --top-ports=100
```
- Scans 100 most common ports
- Takes 1-2 minutes
- Better coverage of services

### Complete Assessment (All Ports)

```bash
sudo nmap 10.129.2.28 -p-
```
- Scans all 65,535 TCP ports
- Takes 5-15 minutes (depends on network)
- No stone left unturned

### Fast Scan (Limited Scope)

```bash
sudo nmap 10.129.2.28 -F
```
- Scans top 100 ports (faster version of --top-ports=100)
- Quick check before deeper scan

---

## Key Takeaways

✅ **Port states matter** - open/closed/filtered tells different stories  
✅ **SYN scan default** - use -sS as root (default)  
✅ **TCP connect scan** - use -sT as non-root user  
✅ **Choose ports wisely** - --top-ports for quick, -p- for thorough  
✅ **Packet tracing reveals truth** - --packet-trace shows exactly what's happening  
✅ **TTL values vary** - Linux ~64, Windows ~128 (helps identify OS)  
✅ **Closed ≠ Filtered** - Closed means accessible; Filtered means blocked  

---

## TCP Connect Scan (-sT)

### Overview

The TCP Connect Scan uses the **complete three-way handshake** to determine port state. It's more accurate but less stealthy than SYN scans.

### How It Works

1. **Sends SYN** to target port
2. **Waits for response:**
   - **SYN-ACK** → Port is OPEN
   - **RST** → Port is CLOSED
3. **Completes handshake** if port is open
4. **Properly closes connection** (not abrupt)

### Advantages

✅ **Highly Accurate** - Complete handshake confirms exact port state  
✅ **Polite** - Behaves like normal client connection  
✅ **Less Service Disruption** - Proper TCP handling, minimal errors  
✅ **Widely Compatible** - Works as non-root user  

### Disadvantages

❌ **Easily Detected** - Full connection creates logs on systems  
❌ **IDS/IPS Triggering** - Modern security solutions alert on Connect scans  
❌ **Slow** - Three-way handshake takes longer than SYN scan  
❌ **Not Stealthy** - Every connection is logged  

### When to Use Connect Scan

- Accuracy is priority over stealth
- Network mapping without service disruption
- Situations where SYN scan not available (non-root user)
- Testing from networks with extensive logging

### Connect Scan on TCP Port 443

**Command:**
```bash
sudo nmap 10.129.2.28 -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `-p 443` | Scan only port 443 (HTTPS) |
| `--packet-trace` | Show all packets sent/received |
| `--disable-arp-ping` | Force ICMP/TCP (disable ARP) |
| `-Pn` | Skip ping scan |
| `-n` | Disable DNS resolution |
| `--reason` | Show why port is in that state |
| `-sT` | TCP Connect scan |

**Expected Packet Sequence:**
- SENT: SYN packet to port 443
- RCVD: SYN-ACK packet (port is open)
- Port marked as OPEN (connection established)

---

## Filtered Ports

### Understanding Filtered State

When Nmap shows a port as **filtered**, it indicates uncertainty about the port state due to firewall rules. The firewall can handle packets in two ways:

| Action | Result | Meaning |
|--------|--------|---------|
| **Drops** | No response received | Firewall silently discards packet |
| **Rejects** | ICMP error response | Firewall actively rejects connection |

### Retry Mechanism

When packets are dropped:
- **Default retries:** `--max-retries 10`
- Nmap resends request up to 10 times
- Confirms if packet was lost or truly filtered
- Increases scan time for filtered ports (~2+ seconds)

### Dropped Packets (Silent Filtering)

**Example: Scanning TCP Port 139 (Dropped)**

**Command:**
```bash
sudo nmap 10.129.2.28 -p 139 --packet-trace -n --disable-arp-ping -Pn
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `-p 139` | Scan only port 139 (NetBIOS) |
| `--packet-trace` | Show all packets sent/received |
| `-n` | Disable DNS resolution |
| `--disable-arp-ping` | Disable ARP ping |
| `-Pn` | Skip ping scan |

**Expected Behavior:**
- Nmap sends multiple SYN packets
- **No response** received from target
- Scan duration: **~2+ seconds** (retries happening)
- Port marked as **filtered** (uncertain state)
- Firewall is silently dropping packets

**Why Longer Duration?** Nmap retries 10 times by default, waiting for response each time.

### Rejected Packets (Active Rejection)

**Example: Scanning TCP Port 445 (Rejected)**

**Command:**
```bash
sudo nmap 10.129.2.28 -p 445 --packet-trace -n --disable-arp-ping -Pn
```

**Sample Output:**
```
SENT (0.0388s) TCP 10.129.2.28:52472 > 10.129.2.28:445 S ttl=49 id=21763 iplen=44 seq=1418633433 win=1024 <mss 1460>
RCVD (0.0487s) ICMP [10.129.2.28 > 10.129.2.28 Port 445 unreachable (type=3/code=3)] IP [ttl=64 id=20998 iplen=72]

PORT    STATE    SERVICE
445/tcp filtered microsoft-ds
```

**Analysis:**

| Component | Meaning |
|-----------|---------|
| `SENT ... S` | Nmap sends SYN to port 445 |
| `RCVD ... ICMP type=3/code=3` | ICMP "Port Unreachable" response |
| `STATE filtered` | Port marked filtered (firewall rejection) |
| `Duration ~0.05s` | Fast response (active rejection) |

**ICMP Error Code Reference:**
- **Type 3, Code 3** = "Port Unreachable" → Firewall actively rejecting
- **Type 3, Code 1** = "Host Unreachable" → Different network unreachable
- **Type 3, Code 13** = "Administratively Prohibited" → Explicit firewall rule

### Dropped vs Rejected (Comparison)

| Behavior | Dropped | Rejected |
|----------|---------|----------|
| **Packet Handling** | Silently discarded | Active ICMP response |
| **Scan Duration** | ~2+ seconds (retries) | ~0.05 seconds (fast) |
| **Nmap State** | filtered | filtered |
| **Firewall Type** | Stealth-mode firewall | Standard firewall |
| **Assumption** | Port likely filtered | Firewall definitely present |

### Handling Filtered Ports

**Next Steps When Port is Filtered:**

1. **Note the port** - May be important service behind firewall
2. **Try firewall evasion** - Adjust scan timing, fragmentation, decoys
3. **Use service detection** - If can bypass, identify service with -sV
4. **Document for reporting** - Indicate firewall presence and strictness
5. **Schedule for phase 2** - May need alternative approach (social engineering, internal access)

---

## Scan Duration Analysis

### Quick Scans (Open/Closed Ports)
- **Duration:** ~0.05 seconds per port
- **Reason:** Immediate response from target
- **Example:** Port 443 responds with SYN-ACK immediately

### Slow Scans (Filtered Ports - Dropped)
- **Duration:** ~2+ seconds per port
- **Reason:** Nmap retries 10 times waiting for response
- **Example:** Port 139 gets no response, retries occur

### Impact on Full Scans
- **10 open ports:** ~0.5 seconds total
- **10 filtered ports:** ~20+ seconds total
- **Mixed network:** Varies by ratio of open/filtered

---

## Key Takeaways

✅ **Connect scans (-sT) are accurate but loud**  
✅ **Dropped packets = silence; Rejected = ICMP error**  
✅ **Filtered status means firewall presence**  
✅ **Scan duration reveals packet handling** (fast = rejection, slow = dropped)  
✅ **Default retries = 10** (can adjust with --max-retries)  
✅ **Know the difference:** open ≠ filtered ≠ closed  
✅ **ICMP errors help identify firewall behavior**  

---

## UDP Port Scanning (-sU)

### Overview

UDP is a **stateless protocol** that doesn't require a three-way handshake like TCP. This fundamental difference makes UDP scanning very different from TCP scanning.

### Key Differences: UDP vs TCP Scanning

| Aspect | TCP | UDP |
|--------|-----|-----|
| **Handshake** | 3-way (SYN, SYN-ACK, ACK) | Connectionless (no handshake) |
| **Acknowledgment** | Explicit ACK received | No acknowledgment |
| **Timeout** | Fast (~0.05s per port) | Much longer (1-2s per port) |
| **Speed** | Quick scans | Very slow scans |
| **Response** | Always expected | Often no response |
| **Reliability** | Reliable delivery | Best-effort delivery |

### Why UDP Scans are Slow

1. **No acknowledgment** - Can't confirm packet arrival
2. **Longer timeouts** - Wait longer for potential responses
3. **Unreliable protocol** - Packets may be silently dropped
4. **Application-dependent** - Only get response if app is configured to respond

### Full UDP Fast Scan

**Command:**
```bash
sudo nmap 10.129.2.28 -F -sU
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `-F` | Fast scan (top 100 ports) |
| `-sU` | UDP scan |

**Sample Output:**
```
Not shown: 95 closed ports
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
137/udp  open          netbios-ns
138/udp  open|filtered netbios-dgm
631/udp  open|filtered ipp
5353/udp open          zeroconf

Nmap done: 1 IP address (1 host up) scanned in 98.07 seconds.
```

**Key Observation:** Scan took **98 seconds** for only 100 ports (very slow!)

### UDP Port States and Responses

#### Open UDP Port (Response Received)

**Command:**
```bash
sudo nmap 10.129.2.28 -sU -Pn -n --disable-arp-ping --packet-trace -p 137 --reason
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `-sU` | UDP scan |
| `-Pn` | Skip ping |
| `-n` | No DNS resolution |
| `--disable-arp-ping` | Disable ARP ping |
| `--packet-trace` | Show packets |
| `-p 137` | Scan port 137 (NetBIOS) |
| `--reason` | Show detection reason |

**Packet Trace:**
```
SENT (0.0367s) UDP 10.10.14.2:55478 > 10.129.2.28:137 ttl=57 id=9122 iplen=78
RCVD (0.0398s) UDP 10.129.2.28:137 > 10.10.14.2:55478 ttl=64 id=13222 iplen=257
```

**Output:**
```
PORT    STATE SERVICE    REASON
137/udp open  netbios-ns udp-response ttl 64
```

**Analysis:**
- ✅ Nmap sends UDP packet (empty datagram)
- ✅ Application responds with data
- ✅ Port marked as **OPEN**
- ✅ **REASON:** `udp-response` (got UDP response back)

---

#### Closed UDP Port (ICMP Error)

**Command:**
```bash
sudo nmap 10.129.2.28 -sU -Pn -n --disable-arp-ping --packet-trace -p 100 --reason
```

**Packet Trace:**
```
SENT (0.0445s) UDP 10.10.14.2:63825 > 10.129.2.28:100 ttl=57 id=29925 iplen=28
RCVD (0.1498s) ICMP [10.129.2.28 > 10.10.14.2 Port unreachable (type=3/code=3)] IP [ttl=64 id=11903 iplen=56]
```

**Output:**
```
PORT    STATE  SERVICE REASON
100/udp closed unknown port-unreach ttl 64
```

**Analysis:**
- Nmap sends UDP packet to port 100
- Receives **ICMP type 3, code 3** (Port Unreachable)
- Port marked as **CLOSED**
- **REASON:** `port-unreach` (ICMP error received)

---

#### Open|Filtered UDP Port (No Response)

**Command:**
```bash
sudo nmap 10.129.2.28 -sU -Pn -n --disable-arp-ping --packet-trace -p 138 --reason
```

**Packet Trace:**
```
SENT (0.0380s) UDP 10.10.14.2:52341 > 10.129.2.28:138 ttl=50 id=65159 iplen=28
SENT (1.0392s) UDP 10.10.14.2:52342 > 10.129.2.28:138 ttl=40 id=24444 iplen=28
```

**Output:**
```
PORT    STATE         SERVICE     REASON
138/udp open|filtered netbios-dgm no-response
```

**Analysis:**
- Nmap sends UDP packet to port 138
- **No response** received (silence)
- Retries after ~1 second
- Port marked as **OPEN|FILTERED**
- **REASON:** `no-response` (firewall or no app listening)
- **Scan duration:** ~2.06 seconds (includes retry timeout)

### UDP Port State Summary

| State | Trigger | Meaning |
|-------|---------|---------|
| **open** | UDP response received | Application is listening and responds |
| **closed** | ICMP type 3 error | Port accessible but no service |
| **open\|filtered** | No response (timeout) | Either filtered by firewall OR no app response |

### Why UDP Scans are Problematic

❌ **Can't distinguish between:** Open port with silent app vs. Filtered port  
❌ **Very slow** - Default timeout ~1 second per port  
❌ **Empty datagrams** - Often no response even if port open  
❌ **App-dependent** - Only responds if configured to do so  
❌ **Firewall bypass needed** - Many firewalls drop UDP silently  

### When to Use UDP Scanning

✅ Looking for DNS (port 53)  
✅ Looking for SNMP (port 161)  
✅ Looking for DHCP (port 67/68)  
✅ Looking for NTP (port 123)  
✅ Looking for specific UDP services  

---

## Service Detection Scanning (-sV)

### Overview

The `-sV` option performs **service version detection** on open ports. It sends application-specific probes and analyzes responses to identify:
- Service names
- Service versions
- Configuration details
- Operating system

### How Service Detection Works

1. **Connects** to open port (establishes TCP connection)
2. **Sends probes** - Application-specific payloads (e.g., SMB, SSH, HTTP)
3. **Analyzes response** - Matches against service signatures database
4. **Identifies service** - Returns service name, version, details

### Service Detection Example

**Command:**
```bash
sudo nmap 10.129.2.28 -Pn -n --disable-arp-ping --packet-trace -p 445 --reason -sV
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `-Pn` | Skip ping |
| `-n` | No DNS |
| `--disable-arp-ping` | Disable ARP |
| `--packet-trace` | Show packets |
| `-p 445` | Port 445 only |
| `--reason` | Show reason |
| `-sV` | Service version detection |

### Service Detection Packet Sequence

**Phase 1: TCP Connection**
```
SENT (0.3426s) TCP 10.10.14.2:44641 > 10.129.2.28:445 S ...
RCVD (0.3556s) TCP 10.129.2.28:445 > 10.10.14.2:44641 SA ...
```
- Establishes connection with SYN-ACK

**Phase 2: Probe Sending**
```
NSOCK INFO [0.5130s] nsock_connect_tcp(): TCP connection requested to 10.129.2.28:445
NSOCK INFO [0.5130s] Service scan sending probe NULL to 10.129.2.28:445 (tcp)
NSOCK INFO [6.5190s] Service scan sending probe SMBProgNeg to 10.129.2.28:445 (tcp)
```
- Sends NULL probe (waits for response)
- Sends SMBProgNeg probe (SMB-specific)

**Phase 3: Response Analysis**
```
NSOCK INFO [6.5320s] Service scan match (Probe SMBProgNeg matched with SMBProgNeg line 13836): 
10.129.2.28:445 is netbios-ssn
Version: |Samba smbd|3.X - 4.X|workgroup: WORKGROUP|
```
- Identifies SMB response
- Determines Samba version 3.X - 4.X

### Service Detection Output

```
PORT    STATE SERVICE     REASON         VERSION
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: Ubuntu

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
```

**Key Information Extracted:**
- **Port:** 445/tcp
- **State:** open
- **Service:** netbios-ssn (SMB)
- **Version:** Samba 3.X - 4.X
- **Workgroup:** WORKGROUP
- **OS Hint:** Ubuntu

### Service Detection Timing

- **Fast scans** (open ports): ~6-10 seconds
- **Probe matching**: Varies by service complexity
- **Multiple probes**: Several attempts per port
- **Full scan** (20 ports): ~30-60 seconds

### Common Service Probes

| Service | Port | Probe Type | Information |
|---------|------|-----------|-------------|
| SSH | 22 | Banner grab | SSH version, OS |
| HTTP | 80 | HTTP request | Web server, version |
| HTTPS | 443 | TLS handshake | Certificate, server |
| SMTP | 25 | SMTP commands | Mail server, version |
| SMB | 445 | SMB negotiation | Samba/Windows version |
| DNS | 53 | DNS query | DNS server version |
| FTP | 21 | FTP banner | FTP server, version |

---

## Combining Scans: Full Reconnaissance

**Command:**
```bash
sudo nmap 10.129.2.28 -p- -sV -sC -O
```

**Options:**
| Option | Purpose |
|--------|---------|
| `-p-` | All ports |
| `-sV` | Service version detection |
| `-sC` | NSE scripts (default safe) |
| `-O` | OS detection |

**What This Does:**
1. Scans all 65,535 TCP ports
2. Detects services and versions on open ports
3. Runs safe default NSE scripts
4. Attempts OS fingerprinting
5. Provides comprehensive target profile

---

## Key Takeaways

✅ **UDP scans are SLOW** - Expect 1+ second per port  
✅ **No responses don't mean closed** - Could be filtered or silent app  
✅ **Service detection (-sV) is powerful** - Reveals version info for exploitation  
✅ **Probe matching** - Nmap has signature database for services  
✅ **Scan duration scales** - More ports = exponentially longer (especially UDP)  
✅ **UDP useful for specific services** - DNS, SNMP, DHCP, NTP  
✅ **Combine techniques** - Use TCP for broad scan, UDP for specific services  

---

## Next Steps

- [NSE Scripts](NSE_Scripts.md) - Automate service enumeration with scripts
- [Firewall/IDS Evasion](Firewall_IDS_Evasion.md) - Bypass filtering to discover hidden ports

