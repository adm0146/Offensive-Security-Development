# Port Scanning

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

## Next Steps

- [Service Detection](Service_Detection.md) - Determine service versions on open ports
- [NSE Scripts](NSE_Scripts.md) - Automate service enumeration with scripts
- [Firewall/IDS Evasion](Firewall_IDS_Evasion.md) - Bypass filtering to discover hidden ports

