# Firewall and IDS/IPS Evasion

## Overview

**Firewalls, IDS (Intrusion Detection Systems), and IPS (Intrusion Prevention Systems)** are critical security components that protect networks. Nmap provides multiple evasion techniques to bypass or work around these defenses while performing legitimate reconnaissance.

This section covers:
- Understanding firewall and IDS/IPS mechanisms
- Detecting firewall filtering behavior
- Evasion techniques and their applications
- Real-world examples comparing detection methods

---

## Quick Reference Commands

| Command | Purpose |
|---------|---------|
| `-sA` | ACK scan (harder to filter than SYN) |
| `-f` | Fragment packets (defeat packet filters) |
| `--mtu <size>` | Set MTU size for fragmentation |
| `-D <decoy1,decoy2>` | Use decoys to obscure source |
| `--source-port <port>` | Spoof source port |
| `--data-length <size>` | Add random data to packets |
| `-T paranoid` or `-T sneaky` | Slow timing for IDS evasion |
| `--scan-delay <time>` | Delay between probes |
| `--badsum` | Send packets with invalid checksums |

---

## Firewall Fundamentals

### What is a Firewall?

A **firewall** is a security measure that:

1. **Monitors network traffic** - Inspects packets between external and internal networks
2. **Applies rules** - Determines how to handle each connection based on configured policies
3. **Enforces policies** - Passes, ignores, or blocks individual packets
4. **Prevents unauthorized access** - Stops potentially dangerous connections from reaching internal systems

**How It Works:**
```
External Network → [Firewall Rules Check] → Internal Network
                   ↓
            Pass / Ignore / Block
```

### Firewall Response Types

Firewalls handle packets in two primary ways:

#### 1. Dropped Packets
- **Action:** Firewall silently discards the packet
- **Response:** No response sent to the sender
- **Detection:** Appears as timeout/no response
- **Indication:** Often used to hide that a service exists

#### 2. Rejected Packets
- **Action:** Firewall explicitly denies the connection
- **Response:** Sends error message back to sender
- **TCP Response:** RST (Reset) flag
- **ICMP Response:** Error codes indicating reason

**ICMP Error Codes:**
```
Type 3 (Destination Unreachable):
  Code 0: Net Unreachable
  Code 1: Host Unreachable
  Code 9: Net Prohibited
  Code 10: Host Prohibited
  Code 13: Port Unreachable
  Code 11: Protocol Unreachable
```

---

## IDS/IPS Fundamentals

### Intrusion Detection System (IDS)

An **IDS** is a software-based security component that:

1. **Scans network traffic** - Monitors all packets on the network
2. **Analyzes patterns** - Compares traffic against known attack signatures
3. **Detects anomalies** - Identifies suspicious patterns or behaviors
4. **Reports attacks** - Alerts security team of detected threats

**Key Characteristic:** Passive monitoring only (no intervention)

### Intrusion Prevention System (IPS)

An **IPS** complements IDS by:

1. **Monitors traffic** - Like IDS, scans for attacks
2. **Detects attacks** - Uses pattern matching and signatures
3. **Takes action** - Actively blocks detected attacks
4. **Prevents exploitation** - Stops attacks before they succeed

**Key Difference from IDS:** Active defense (blocks traffic)

### Detection Method: Pattern Matching

Both IDS and IPS use **signature-based detection:**

```
Incoming Traffic → Pattern Matching → Signature Database
                        ↓
                   Match Found?
                   /        \
                Yes          No
                |            |
              Block      Allow Through
```

**What Triggers Detection:**
- Service enumeration scans (version detection probes)
- SYN floods or unusual connection patterns
- Known exploit signatures
- Suspicious port combinations
- Rapid sequential connection attempts

---

## Determining Firewall Behavior

### Port States and Their Meanings

When Nmap reports a port state, it reveals firewall behavior:

| Port State | Meaning | Firewall Action | Implication |
|-----------|---------|-----------------|-------------|
| **open** | Service responding | Port allowed | Can connect directly |
| **closed** | RST received | Port not filtered | Firewall allows probe |
| **filtered** | No response or ICMP error | Packet dropped/rejected | Firewall is blocking |
| **unfiltered** | RST received (ACK scan) | Port response varies | Firewall allows probe through |

### TCP ACK Scan (-sA) Advantage

The **ACK scan** is significantly harder to filter than SYN scans because:

**Why SYN Scans Are Filtered:**
- SYN packets initiate new connections
- Firewalls block most outbound SYN attempts
- Makes sense from a security perspective

**Why ACK Scans Bypass Filters:**
- ACK packets are part of established connections
- Firewall can't easily distinguish if connection originated internally or externally
- Commonly allowed through because they appear to be responses to established connections
- IDS/IPS less likely to trigger on ACK packets alone

---

## Real-World Comparison: SYN vs ACK Scan

### Scenario: Firewall Filtering Ports 21 and 25

**Target:** 10.129.2.28  
**Ports:** 21 (FTP), 22 (SSH), 25 (SMTP)  
**Firewall:** Blocks ports 21 and 25, allows port 22

### Method 1: SYN Scan (-sS)

**Command:**
```bash
sudo nmap 10.129.2.28 -p 21,22,25 -sS -Pn -n --disable-arp-ping --packet-trace
```

**Packet Exchange:**
```
SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:22 S ttl=53 id=22412...
SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:25 S ttl=50 id=62291...
SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:21 S ttl=58 id=38696...

RCVD (0.0329s) ICMP [10.129.2.28 > 10.10.14.2 Port 21 unreachable (type=3/code=3)]
RCVD (0.0341s) TCP 10.129.2.28:22 > 10.10.14.2:57347 SA ttl=64 id=0...
RCVD (1.0386s) TCP 10.129.2.28:22 > 10.10.14.2:57347 SA ttl=64 id=0...
SENT (1.1366s) TCP 10.10.14.2:57348 > 10.129.2.28:25 S ttl=44 id=6796...
```

**Results:**
```
PORT   STATE    SERVICE
21/tcp filtered ftp      ← ICMP Port Unreachable (dropped)
22/tcp open     ssh      ← SYN-ACK received (established)
25/tcp filtered smtp     ← No response (dropped)
```

**Analysis:**
- **Port 21:** ICMP error received (firewall explicitly rejecting)
- **Port 22:** SYN-ACK received (port open and accessible)
- **Port 25:** No response (firewall dropping packets silently)

### Method 2: ACK Scan (-sA)

**Command:**
```bash
sudo nmap 10.129.2.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping --packet-trace
```

**Packet Exchange:**
```
SENT (0.0422s) TCP 10.10.14.2:49343 > 10.129.2.28:21 A ttl=49 id=12381...
SENT (0.0423s) TCP 10.10.14.2:49343 > 10.129.2.28:22 A ttl=41 id=5146...
SENT (0.0423s) TCP 10.10.14.2:49343 > 10.129.2.28:25 A ttl=49 id=5800...

RCVD (0.1252s) ICMP [10.129.2.28 > 10.10.14.2 Port 21 unreachable (type=3/code=3)]
RCVD (0.1268s) TCP 10.129.2.28:22 > 10.10.14.2:49343 R ttl=64 id=0...
SENT (1.3837s) TCP 10.10.14.2:49344 > 10.129.2.28:25 A ttl=59 id=21915...
```

**Results:**
```
PORT   STATE      SERVICE
21/tcp filtered   ftp      ← ICMP Port Unreachable (dropped)
22/tcp unfiltered ssh      ← RST received (port responds)
25/tcp filtered   smtp     ← No response (dropped)
```

**Analysis:**
- **Port 21:** ICMP error received (firewall rejecting)
- **Port 22:** RST received (port exists, firewall allows probe through!)
- **Port 25:** No response (firewall dropping packets silently)

### Key Difference: Port 22 Results

| Scan Method | Response | Port State | Interpretation |
|------------|----------|-----------|-----------------|
| **SYN (-sS)** | SYN-ACK | **open** | Connection successful, service responding |
| **ACK (-sA)** | RST | **unfiltered** | Firewall allows probe, but doesn't confirm if service is open |

**Critical Insight:**
- **SYN scan blocked** by firewall on port 22 initially (connection refused)
- **ACK scan succeeded** on port 22 (firewall allowed the probe through)
- ACK scan's "unfiltered" state reveals the port responds, even if we can't establish a full connection

---

## Firewall Evasion Techniques

### 1. ACK Scan (-sA)

**When to Use:**
- Firewall blocks standard SYN scans
- Need to map firewall rules
- Want to determine if ports are unfiltered

**Command:**
```bash
nmap -p <ports> -sA <target>
```

**Advantage:** Bypasses basic firewall filtering of connection initiations

---

### 2. Packet Fragmentation (-f)

**Concept:** Split TCP packets into smaller fragments to evade packet inspection

**Command:**
```bash
sudo nmap -p 80 -sS -f <target>
```

**How It Works:**
```
Original Packet: [TCP SYN Header + Data]
                        ↓
            Fragmentation Applied
                        ↓
Fragment 1: [Part of TCP Header]
Fragment 2: [Rest of Header + Data]
            
→ Reassembled by target, but may bypass IDS inspection
```

**Note:** Many modern systems reassemble fragments immediately, reducing effectiveness

---

### 3. Custom MTU (--mtu)

**Concept:** Set Maximum Transmission Unit to control fragment size

**Command:**
```bash
sudo nmap -p 80 -sS --mtu 8 <target>
```

**Effect:** Fragments packets into 8-byte chunks (very small, aggressive evasion)

---

### 4. Decoys (-D)

**Concept:** Send spoofed packets from decoy IP addresses alongside real scan

**Command:**
```bash
sudo nmap -p 80 -sS -D 10.10.1.1,10.10.1.2,ME <target>
```

**Effect:**
```
Real Source (ME): 10.10.14.2
Decoy 1:          10.10.1.1
Decoy 2:          10.10.1.2

All appear to scan target simultaneously
→ IDS logs multiple sources
→ Real attacker obscured in noise
```

**Limitation:** Target logs show multiple IPs (may trigger enhanced investigation)

---

### 5. Source Port Spoofing (--source-port)

**Concept:** Spoof scan source port as trusted service port

**Command:**
```bash
sudo nmap -p 80,443 -sS --source-port 53 <target>
```

**Why It Works:**
- Port 53 = DNS (often allowed through firewalls)
- Firewall rules may whitelist DNS traffic
- Appears as DNS response traffic to IDS

**Risk:** Easy for administrators to detect if they review source ports

---

### 6. Data Length Padding (--data-length)

**Concept:** Add random data to packets to evade signature-based detection

**Command:**
```bash
sudo nmap -p 80 -sS --data-length 50 <target>
```

**Effect:**
- Nmap appends 50 bytes of random data
- Changes packet signature
- May bypass IDS patterns

---

### 7. Slow Timing for IDS Evasion

**Concept:** Reduce scan speed to avoid triggering IDS thresholds

**Commands:**
```bash
# Very slow, stealthy
sudo nmap <target> -T 1

# Paranoid (slowest)
sudo nmap <target> -T 0

# With additional delays
sudo nmap <target> -T 2 --scan-delay 1s
```

**Effect:**
- Spread scans over longer time period
- Below IDS alert thresholds
- Less likely to trigger rapid-connection detection

---

### 8. Invalid Checksums (--badsum)

**Concept:** Send packets with intentionally invalid checksums

**Command:**
```bash
sudo nmap -p 80 -sS --badsum <target>
```

**Effect:**
- Normal systems discard invalid checksum packets
- Some IDS systems may also skip them
- Real targets typically won't respond (filtering behavior)

---

## Evasion Strategy Decision Tree

```
Firewall Detected?
    |
    ├─ Aggressive Filtering (blocks SYN)?
    │   └─ Try: ACK scan (-sA) or slow timing (-T 1)
    │
    ├─ Signatures Detected (IDS alert)?
    │   └─ Try: Fragmentation (-f) or data padding (--data-length)
    │
    ├─ Multiple port scans detected?
    │   └─ Try: Decoys (-D) or source port spoofing (--source-port)
    │
    ├─ Need stealth/silence?
    │   └─ Try: Paranoid timing (-T 0) + scan delays
    │
    └─ Unknown firewall type?
        └─ Try: ACK scan first, then adjust based on results
```

---

## Best Practices for Evasion

✅ **Use ACK scans first** - Reveals firewall rules without being aggressive  
✅ **Know your authorization** - Evasion techniques may violate authorization scope  
✅ **Understand your target network** - Tailor techniques to network architecture  
✅ **Use slow timing for IDS evasion** - More reliable than other techniques  
✅ **Combine techniques** - Multiple evasion methods together are more effective  
✅ **Document evasion attempts** - Track what works against specific systems  
✅ **Test on authorized systems first** - Understand effectiveness before real assessment  
✅ **Be prepared for blocked access** - Some networks filter all reconnaissance  
✅ **Know when to escalate** - If evasion fails, may need alternative approach  
✅ **Respect authorization limits** - Only evade within scope of authorized testing  

---

## Important Legal and Ethical Considerations

⚠️ **Authorization is Critical**

Evasion techniques should ONLY be used when:
- ✅ You have explicit written authorization
- ✅ You're within the defined scope
- ✅ You've documented the testing plan
- ✅ All stakeholders are informed

❌ **Never use evasion:**
- ❌ On systems you don't have permission to test
- ❌ Outside the scope of engagement
- ❌ To hide your activities from authorized parties
- ❌ To avoid accountability for your actions

---

## Real-World Context

In legitimate pentests:

1. **White-Box Testing:** Usually no need for evasion (pre-approved)
2. **Grey-Box Testing:** May use light evasion with client approval
3. **Black-Box Testing:** May use advanced evasion (but within scope)
4. **Red Team Exercises:** Evasion expected and authorized

**Always consult with your client first before using these techniques.**

---

## Part 2: Detecting and Evading IDS/IPS Systems

### Understanding IDS/IPS Detection Challenges

Unlike firewalls with fixed rules, **IDS/IPS systems are passive and behavioral-based:**

1. **Passive Monitoring** - Monitor all traffic continuously
2. **Pattern Matching** - Compare against signature databases
3. **Threshold-Based Detection** - Alert on suspicious patterns
4. **Automatic Response** - IPS actively blocks detected threats

**Key Difference:** Firewalls block by rules; IDS/IPS learns and adapts to threats

---

### Detecting IDS/IPS Presence

#### Method 1: Single VPS Scanning

**Strategy:** Use a single VPS to scan aggressively and observe admin response.

**Process:**
1. Perform aggressive scans from single VPS IP
2. Monitor for access loss
3. If IP gets blocked = IPS system detected
4. If no response = Lighter security or misconfigured

**Indicators IPS is Present:**
- IP suddenly blocked from all network access
- ISP contacts you about suspicious activity
- Scans timeout/no responses after initial activity
- Immediate firewall rule changes

**Response:**
- Switch to different VPS immediately
- Reduce scan aggressiveness significantly
- Use stealth techniques
- Consider timing evasion

#### Method 2: Aggressive Port Scanning Trigger

**Strategy:** Scan single port/service aggressively and observe reaction

**Command:**
```bash
sudo nmap <target> -p 22 -sS -T 5 -r
```

**Observation Points:**
- Does response time increase?
- Do subsequent scans timeout?
- Does firewall block your IP?

**Analysis:**
- Immediate blocking = Active IPS
- Degraded performance = Detection but not blocking
- No change = Minimal IDS/IPS

---

## Decoy Scanning Deep Dive

### Concept: Obscuring Real Source

Decoy scanning sends packets from multiple spoofed IP addresses alongside your real IP, obscuring which one is the actual attacker.

### Syntax

**Command:**
```bash
nmap <target> -D RND:<number> <target>
```

**Options:**
- `RND` - Generate random IP addresses
- `<number>` - How many random IPs to generate
- `ME` - Include your real IP (randomized position)

### Decoy Scanning Example

**Command:**
```bash
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```

**Packet Trace Output:**
```
SENT (0.0378s) TCP 102.52.161.59:59289 > 10.129.2.28:80 S ttl=42 id=29822...
SENT (0.0378s) TCP 10.10.14.2:59289 > 10.129.2.28:80 S ttl=59 id=29822...    ← Real IP
SENT (0.0379s) TCP 210.120.38.29:59289 > 10.129.2.28:80 S ttl=37 id=29822...
SENT (0.0379s) TCP 191.6.64.171:59289 > 10.129.2.28:80 S ttl=38 id=29822...
SENT (0.0379s) TCP 184.178.194.209:59289 > 10.129.2.28:80 S ttl=39 id=29822...
SENT (0.0379s) TCP 43.21.121.33:59289 > 10.129.2.28:80 S ttl=55 id=29822...

RCVD (0.1370s) TCP 10.129.2.28:80 > 10.10.14.2:59289 SA ttl=64 id=0...    ← Response to real IP
```

**Result:**
```
PORT   STATE SERVICE
80/tcp open  http
```

**Analysis:**
- 6 SYN packets sent (1 real + 5 spoofed decoys)
- Target responds only to real IP (10.10.14.2)
- IDS logs show 6 different source IPs attempting scan
- Real attacker obscured in noise

### Decoy Limitations

⚠️ **Important Considerations:**

1. **ISP Filtering** - Spoofed packets often filtered at ISP level
2. **Network Range** - Decoys should be from similar network ranges to appear legitimate
3. **Alive Check** - If decoy IPs are dead/unreachable, service may reject as SYN flood
4. **Target Logging** - Target logs show multiple IPs (may trigger investigation)
5. **Response Detection** - Real response reveals your actual IP

### Using Real VPS as Decoys

**Better Approach:** Use your own VPS servers instead of random IPs

**Command:**
```bash
sudo nmap 10.129.2.28 -p 80 -sS -D 10.20.1.5,10.20.1.6,ME <target>
```

**Advantages:**
- Decoy IPs actually exist (won't trigger SYN-flood protection)
- Appear as legitimate network traffic
- You control all decoy sources
- Better evasion of automated defenses

---

## Source IP Spoofing (-S)

### Concept: Scan from Different Network Source

Use source IP from internal network range to bypass network-based restrictions.

### Syntax

**Command:**
```bash
sudo nmap <target> -S <source-ip> -e <interface>
```

**Parameters:**
- `-S` - Specify source IP address
- `-e` - Specify network interface to send packets through

### Real-World Example: Firewall Rule Bypass

**Scenario:** SMB port (445) is filtered when scanned normally, but accessible from internal network

**Initial Scan (Filtered):**
```bash
sudo nmap 10.129.2.28 -n -Pn -p 445 -O
```

**Result:**
```
PORT    STATE    SERVICE
445/tcp filtered microsoft-ds
```

**Issue:** Too many fingerprints match (can't determine OS)

**Scan with Source IP Spoofing:**
```bash
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```

**Result:**
```
PORT    STATE SERVICE
445/tcp open  microsoft-ds

Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%)...
```

**Analysis:**
- Port now shows as **open** (instead of filtered)
- Spoofed source IP (10.129.2.200) appears to be internal
- Firewall allows traffic from internal subnet
- Full OS detection successful

### Why This Works

```
Firewall Rules:
├─ External traffic to port 445: BLOCK
└─ Internal traffic to port 445: ALLOW (trusted)

When we spoof source IP 10.129.2.200 (internal range):
→ Firewall treats packets as internal
→ Allows traffic through
→ Reveals open ports and services
```

---

## DNS Proxying and Port 53 Abuse

### DNS Port Characteristics

**Default DNS Behavior:**
- UDP port 53 - Standard DNS queries
- TCP port 53 - Zone transfers or large responses
- Usually **trusted and allowed** through firewalls
- Often **whitelisted** in IDS/IPS rules

### Why DNS Port 53 is Effective for Evasion

**Trust Factor:**
```
Firewall Trust Hierarchy:
├─ Random ports: Heavily scrutinized
├─ Standard services (22, 80, 443): Monitored
└─ DNS (port 53): Usually trusted (needed for normal operation)
```

**IDS/IPS Consideration:**
- DNS requests are so common they're often ignored
- Misconfigured filters may skip DNS traffic
- Appears as legitimate network functionality

### Using Port 53 as Source Port

**Concept:** Spoof scan source port as 53 to appear as DNS traffic

**Command:**
```bash
sudo nmap 10.129.2.28 -p <target-port> -sS --source-port 53
```

### Real-World Example: Firewall Rule Bypass via DNS

**Scenario:** Port 50000 is filtered, but firewall allows DNS traffic

**Standard SYN Scan (Filtered):**
```bash
sudo nmap 10.129.2.28 -p 50000 -sS -Pn -n --disable-arp-ping --packet-trace
```

**Packet Trace:**
```
SENT (0.0417s) TCP 10.10.14.2:33436 > 10.129.2.28:50000 S ttl=41...
SENT (1.0481s) TCP 10.10.14.2:33437 > 10.129.2.28:50000 S ttl=46...

[No response]
```

**Result:**
```
PORT      STATE    SERVICE
50000/tcp filtered ibm-db2
```

**SYN Scan from DNS Port (Port 53):**
```bash
sudo nmap 10.129.2.28 -p 50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```

**Packet Trace:**
```
SENT (0.0482s) TCP 10.10.14.2:53 > 10.129.2.28:50000 S ttl=58...

RCVD (0.0608s) TCP 10.129.2.28:50000 > 10.10.14.2:53 SA ttl=64...    ← Response!
```

**Result:**
```
PORT      STATE SERVICE
50000/tcp open  ibm-db2
```

**Analysis:**
- Source port changed from ephemeral (33436) to 53 (DNS)
- Port now shows as **open** (previously filtered)
- Firewall allows port 53 traffic
- IDS/IPS may ignore DNS-sourced packets

### Verification with Netcat

**Command:**
```bash
ncat -nv --source-port 53 10.129.2.28 50000
```

**Output:**
```
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.129.2.28:50000.
220 ProFTPd
```

**Confirmation:** Service responds and even sends banner (ProFTPd)

---

## DNS Server Specification (--dns-server)

### Use Case: DMZ or Restricted Networks

When inside a demilitarized zone (DMZ), internal DNS servers may have better access to internal resources than external DNS.

**Command:**
```bash
nmap <target> --dns-server <internal-dns-ip>
```

**Example:**
```bash
nmap 10.10.10.10 --dns-server 192.168.1.1
```

**Effect:**
- Queries use internal DNS resolver
- May get different responses than external DNS
- Can access internal network aliases/records
- Appears as legitimate internal traffic

---

## Comprehensive Evasion Workflow

### Phase 1: Reconnaissance
```bash
# Detect firewall filtering
sudo nmap <target> -p <ports> -sS
```

### Phase 2: Identify Bypasses
- ACK scan to check for unfiltered ports
- Standard ports often more open
- Check if IPS is actively blocking

### Phase 3: Apply Evasion
```bash
# Option 1: Decoys
sudo nmap <target> -D RND:5 -p <ports>

# Option 2: Source IP spoofing
sudo nmap <target> -S 10.129.x.x -e tun0

# Option 3: DNS port abuse
sudo nmap <target> --source-port 53

# Option 4: Combination approach
sudo nmap <target> -D 10.20.1.5,ME --source-port 53 -T 1
```

### Phase 4: Verification
```bash
# Confirm with manual tools
ncat -nv --source-port 53 <target> <port>
```

---

## Complete Evasion Decision Tree

```
Port appears FILTERED?
    |
    ├─ Try: ACK scan (-sA)
    │   └─ Shows "unfiltered"? → Firewall allows probes
    │
    ├─ Try: Source port 53 (--source-port 53)
    │   └─ Works? → DNS traffic is trusted
    │
    ├─ Try: Source IP spoofing (-S)
    │   └─ Works? → Internal network has better access
    │
    ├─ Try: Decoys (-D RND:5)
    │   └─ Works? → Can obscure real source
    │
    └─ IP getting blocked?
        └─ Switch VPS immediately
        └─ Reduce scan rate to -T 1
        └─ Use longer delays (--scan-delay 5s)
```

---

## Best Practices for IDS/IPS Evasion

✅ **Test single VPS first** - Determine if IPS is blocking  
✅ **Use trusted ports strategically** - DNS (53), NTP (123), HTTP (80)  
✅ **Combine multiple techniques** - Decoys + slow timing is more effective than either alone  
✅ **Monitor for blocking** - Watch for sudden response timeouts  
✅ **Have backup VPS ready** - Switch immediately if primary IP is blocked  
✅ **Use slow timing** - `-T 1` or `-T 2` is most reliable evasion  
✅ **Document what works** - Track which techniques bypass specific networks  
✅ **Spoof from realistic ranges** - Use internal network ranges for source IPs  
✅ **Verify discoveries** - Use manual tools (ncat) to confirm findings  
✅ **Know when to stop** - Multiple blocked IPs signals aggressive defense  

---

## Critical Security and Legal Notes

⚠️ **Authorization is Absolutely Critical**

These Part 2 techniques (IP spoofing, decoys, port manipulation) are **more aggressive** and require:

- ✅ **Explicit written authorization** - Must be in scope of engagement
- ✅ **Client awareness** - Stakeholders must know techniques being used
- ✅ **Documented testing plan** - All evasion methods must be pre-approved
- ✅ **Legal review** - May violate laws without proper authorization

❌ **Never use these techniques:**
- ❌ Without explicit written permission
- ❌ Outside agreed-upon scope
- ❌ Against systems you don't own/manage
- ❌ To hide activities from authorized parties
- ❌ In ways that damage systems or services

---

## Real-World Context

**When IDS/IPS Evasion is Appropriate:**
1. **Authorized Red Team Exercise** - Defined threat simulation
2. **Penetration Test** - Client has approved evasion techniques
3. **Security Research Lab** - Controlled environment you own
4. **Security Team Tuning** - Testing your own defensive systems

**When to Escalate:**
- If blocked multiple times, you're likely detected
- Heavy IPS presence suggests security-conscious organization
- May need to switch to alternative assessment approach
- Document findings and communicate with client

---

## Lab Practice: UDP DNS Enumeration (Medium Nmap Lab)

**Lesson Learned:** TCP scans alone miss critical UDP services. DNS on port 53 primarily uses UDP, so a TCP SYN scan will identify the port but fail to extract version/banner information.

**Problem:** Port 53 detected as open via TCP `-sS`, but version detection returned only `NLnet Labs NSD` with no flag.

**Solution:** Switch to UDP scan with version detection:

```bash
sudo nmap 10.129.1.139 -p 53 -sU -sV -Pn -vv -oA Working_Medium_Scan
```

**Flags Used:**
- `-sU` — UDP scan (required for DNS version probes)
- `-sV` — Version detection (triggers DNSVersionBindReq probe)
- `-Pn` — Skip host discovery (already know host is up)
- `-vv` — Extra verbosity

**Result:** Nmap sent a `DNSVersionBindReq` probe over UDP, and the DNS server responded with its version string containing the flag embedded in the TXT record response.

**Key Takeaway:** When you see DNS (port 53) open on a TCP scan but can't extract version info, always follow up with `-sU` on port 53. DNS version bind requests only work reliably over UDP.

---

## Next Steps

- Continue with additional Nmap modules
- Practice evasion techniques in lab environments
- Understand firewall/IDS configurations
- Learn IDS evasion detection methods
