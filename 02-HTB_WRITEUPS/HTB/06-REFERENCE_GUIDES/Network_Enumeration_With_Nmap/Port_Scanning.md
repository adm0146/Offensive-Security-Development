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

## Next Steps

- [Service Detection](Service_Detection.md) - Determine service versions on open ports
- [NSE Scripts](NSE_Scripts.md) - Automate service enumeration with scripts
- [Firewall/IDS Evasion](Firewall_IDS_Evasion.md) - Bypass filtering to discover hidden ports

