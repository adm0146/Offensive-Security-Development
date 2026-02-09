# Service Enumeration

## Overview

Determining the **application and its version accurately** is essential for effective penetration testing. Version information allows us to:

- Search for known vulnerabilities (CVEs) affecting that specific version
- Analyze source code for that version if available
- Craft precise exploits that fit the service and target OS
- Understand security configurations and potential weaknesses

Service version detection is a critical step that bridges port discovery and exploitation.

---

## Quick Reference Commands

| Command | Purpose |
|---------|---------|
| `nmap -p- -sV <target>` | Full port scan with service version detection |
| `nmap -p- -sV -v <target>` | Full scan with verbosity (show open ports as discovered) |
| `nmap -p- -sV --stats-every=5s <target>` | Full scan with status updates every 5 seconds |
| `nmap -p- -sV -Pn -n --disable-arp-ping --packet-trace <target>` | Full scan with packet tracing (debug mode) |

---

## Service Version Detection Strategy

### Step 1: Quick Port Scan First

**Why:** Reduce traffic and avoid detection by security mechanisms.

**Command:**
```bash
nmap 10.129.2.28
```

**Advantage:**
- Significantly less network traffic
- Lower chance of triggering IDS/IPS alerts
- Quick overview of available services before deeper analysis

### Step 2: Full Port Scan with Version Detection

**Command:**
```bash
sudo nmap 10.129.2.28 -p- -sV
```

**Parameters:**
- `-p-` - Scan all 65,535 TCP ports
- `-sV` - Perform service version detection on discovered ports

**Duration:** Full port scans can take considerable time (several minutes to hours depending on network and filtering).

---

## Monitoring Long-Running Scans

### Option 1: Space Bar Status Check

Press the **space bar** during a scan to display current progress.

**Command:**
```bash
sudo nmap 10.129.2.28 -p- -sV
[Press Space Bar]
```

**Output:**
```
Stats: 0:00:03 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 3.64% done; ETC: 19:45 (0:00:53 remaining)
```

**Information Provided:**
- Elapsed time
- Completion status
- Percentage progress
- Estimated time to completion (ETC)

### Option 2: Automatic Status Updates

Use `--stats-every` to display status at regular intervals.

**Command:**
```bash
sudo nmap 10.129.2.28 -p- -sV --stats-every=5s
```

**Parameters:**
- `--stats-every=5s` - Show status every 5 seconds
- Use `m` for minutes: `--stats-every=2m`

**Output:**
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 19:46 CEST
Stats: 0:00:05 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 13.91% done; ETC: 19:49 (0:00:31 remaining)
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 39.57% done; ETC: 19:48 (0:00:15 remaining)
```

### Option 3: Increase Verbosity

Use `-v` or `-vv` to show open ports as they are discovered in real-time.

**Command:**
```bash
sudo nmap 10.129.2.28 -p- -sV -v
```

**Output:**
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 20:03 CEST
NSE: Loaded 45 scripts for scanning.
Initiating ARP Ping Scan at 20:03
Scanning 10.129.2.28 [1 port]
Completed ARP Ping Scan at 20:03, 0.03s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:03
Completed Parallel DNS resolution of 1 host. at 20:03, 0.02s elapsed
Initiating SYN Stealth Scan at 20:03
Scanning 10.129.2.28 [65535 ports]
Discovered open port 995/tcp on 10.129.2.28
Discovered open port 80/tcp on 10.129.2.28
Discovered open port 993/tcp on 10.129.2.28
Discovered open port 143/tcp on 10.129.2.28
Discovered open port 25/tcp on 10.129.2.28
Discovered open port 110/tcp on 10.129.2.28
Discovered open port 22/tcp on 10.129.2.28
```

**Advantage:** Provides real-time feedback on discovered services.

---

## How Nmap Detects Service Versions

### Banner Grabbing (Primary Method)

**Process:**
1. Nmap connects to the open port
2. Server sends a banner identifying the service and version
3. Nmap parses and displays the version information

**Example Banner:**
```
220 inlane ESMTP Postfix (Ubuntu)
```

**Advantages:**
- Quick and reliable
- Minimal network overhead
- Works for most common services

### Signature-Based Matching (Secondary Method)

**Process:**
1. If banner is unavailable or unclear, Nmap uses signature-based detection
2. Nmap matches service responses against known signatures
3. Attempts to identify version through response patterns

**Trade-off:** Significantly increases scan duration but improves accuracy for services without clear banners.

---

## Service Detection Limitations

### Missed Information

Nmap's automatic scan can miss information because:

1. **Incomplete Banners** - Some services send minimal banner information
2. **Delayed Responses** - Services may not send banners immediately
3. **Banner Manipulation** - Administrators can modify or remove service banners
4. **Non-Standard Responses** - Custom service implementations may confuse Nmap

### Example: Postfix SMTP Service

When running a full port scan with packet tracing, you may discover additional information that Nmap doesn't automatically report:

**Nmap Output:**
```
PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
```

**But the actual banner shows:**
```
220 inlane ESMTP Postfix (Ubuntu)
```

The **Ubuntu OS information** was present in the banner but not fully captured in Nmap's report.

---

## Deep Packet Inspection with tcpdump and nc

### Capturing Raw Banner Information

**Step 1: Start tcpdump to capture traffic**
```bash
sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28
```

**Output:**
```
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
```

**Step 2: Connect with netcat to grab banner**
```bash
nc -nv 10.129.2.28 25
```

**Output:**
```
Connection to 10.129.2.28 port 25 [tcp/*] succeeded!
220 inlane ESMTP Postfix (Ubuntu)
```

### Analyzing Network Packets

The three-way handshake and service banner exchange:

```
18:28:07.128564 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [S], seq 1798872233, win 65535...
[SYN] Client initiates connection

18:28:07.255151 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [S.], seq 1130574379, ack 1798872234...
[SYN-ACK] Server responds and acknowledges

18:28:07.255281 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 1, win 2058...
[ACK] Client acknowledges (handshake complete)

18:28:07.319306 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [P.], seq 1:36, ack 1, win 510...
[PSH-ACK] Server sends banner with data (35 bytes)
Payload: SMTP: 220 inlane ESMTP Postfix (Ubuntu)

18:28:07.319426 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 36, win 2058...
[ACK] Client confirms receipt of data
```

### TCP Flags Explained

| Flag | Name | Meaning |
|------|------|---------|
| **S** | SYN | Synchronize - initiate connection |
| **S.** | SYN-ACK | Synchronize-Acknowledge - respond to connection |
| **.** | ACK | Acknowledge - confirm receipt |
| **P** | PSH | Push - send data immediately |
| **P.** | PSH-ACK | Push-Acknowledge - send data and confirm |

### The Banner Exchange Process

1. **Three-Way Handshake** - Establish TCP connection (3 packets)
2. **Server Sends Banner** - PSH flag indicates data push with banner information
3. **Client Confirms** - ACK flag confirms receipt
4. **Connection Established** - Ready for further communication

---

## Full Scan with Packet Tracing Example

**Command:**
```bash
sudo nmap 10.129.2.28 -p- -sV -Pn -n --disable-arp-ping --packet-trace
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-p-` | Scan all 65,535 ports |
| `-sV` | Service version detection |
| `-Pn` | Treat target as online (skip ping) |
| `-n` | Skip DNS resolution |
| `--disable-arp-ping` | Don't use ARP ping for host discovery |
| `--packet-trace` | Display all packets sent and received |

**Output (Relevant Section):**
```
NSOCK INFO [0.4200s] nsock_trace_handler_callback(): Callback: READ SUCCESS for EID 18 [10.129.2.28:25] (35 bytes): 220 inlane ESMTP Postfix (Ubuntu)..
Service scan match (Probe NULL matched with NULL line 3104): 10.129.2.28:25 is smtp.  Version: |Postfix smtpd|||
NSOCK INFO [0.4200s] nsock_iod_delete(): nsock_iod_delete (IOD #1)
Nmap scan report for 10.129.2.28
Host is up (0.076s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Service Info: Host:  inlane

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.47 seconds
```

**Analysis:**
- **NSOCK INFO** - Shows the actual banner received (35 bytes)
- **Service scan match** - Nmap's signature matching confirmation
- **Final report** - Cleaned-up version information for easy reading

---

## Real-World Example: Banner Discovery on Non-Standard Port

### Discovering Hidden Services with Packet Tracing and Verbosity

When scanning non-standard ports with unknown services, using both packet tracing (`--packet-trace`) and high verbosity (`-vv`) helps capture actual banner information that Nmap might not automatically identify.

**Command:**
```bash
nmap -p 31337 -sV -Pn -n --disable-arp-ping --packet-trace -vv -oA banner_discovery 10.129.34.51
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-p 31337` | Scan only port 31337 (Elite port) |
| `-sV` | Service version detection |
| `-Pn` | Skip host discovery ping |
| `-n` | Skip DNS resolution |
| `--disable-arp-ping` | Disable ARP ping |
| `--packet-trace` | Show all packets sent/received |
| `-vv` | Very verbose (show detailed probe information) |
| `-oA banner_discovery` | Save all output formats |

**Output - Packet Exchange:**
```
SENT (0.0704s) TCP 10.10.17.128:58910 > 10.129.34.51:31337 S ttl=42 id=19765 iplen=44  seq=3824143361 win=1024 <mss 1460>
RCVD (0.1143s) TCP 10.129.34.51:31337 > 10.10.17.128:58910 SA ttl=63 id=0 iplen=44  seq=3688044430 win=64240 <mss 1346>
Service scan sending probe NULL to 10.129.34.51:31337 (tcp)
Service scan sending probe GetRequest to 10.129.34.51:31337 (tcp)
Service scan sending probe SIPOptions to 10.129.34.51:31337 (tcp)
Service scan sending probe GenericLines to 10.129.34.51:31337 (tcp)
Service scan sending probe HTTPOptions to 10.129.34.51:31337 (tcp)
Service scan sending probe RTSPRequest to 10.129.34.51:31337 (tcp)
Service scan sending probe RPCCheck to 10.129.34.51:31337 (tcp)
Service scan sending probe DNSVersionBindReqTCP to 10.129.34.51:31337 (tcp)
Service scan sending probe DNSStatusRequestTCP to 10.129.34.51:31337 (tcp)
Service scan sending probe Help to 10.129.34.51:31337 (tcp)
Service scan sending probe SSLSessionReq to 10.129.34.51:31337 (tcp)
Service scan sending probe TerminalServerCookie to 10.129.34.51:31337 (tcp)
Service scan sending probe TLSSessionReq to 10.129.34.51:31337 (tcp)
Service scan sending probe Kerberos to 10.129.34.51:31337 (tcp)
Service scan sending probe SMBProgNeg to 10.129.34.51:31337 (tcp)
Service scan sending probe X11Probe to 10.129.34.51:31337 (tcp)
Service scan sending probe FourOhFourRequest to 10.129.34.51:31337 (tcp)
Service scan sending probe LPDString to 10.129.34.51:31337 (tcp)
Service scan sending probe LDAPSearchReq to 10.129.34.51:31337 (tcp)
Service scan sending probe LDAPBindReq to 10.129.34.51:31337 (tcp)
Service scan sending probe LANDesk-RC to 10.129.34.51:31337 (tcp)
Service scan sending probe TerminalServer to 10.129.34.51:31337 (tcp)
Service scan sending probe NCP to 10.129.34.51:31337 (tcp)
Service scan sending probe NotesRPC to 10.129.34.51:31337 (tcp)
Service scan sending probe JavaRMI to 10.129.34.51:31337 (tcp)
Service scan sending probe WMSRequest to 10.129.34.51:31337 (tcp)
Service scan sending probe oracle-tns to 10.129.34.51:31337 (tcp)
Service scan sending probe ms-sql-s to 10.129.34.51:31337 (tcp)
Service scan sending probe afp to 10.129.34.51:31337 (tcp)
Service scan sending probe giop to 10.129.34.51:31337 (tcp)
```

**Scan Result:**
```
Nmap scan report for 10.129.34.51
Host is up, received user-set (0.044s latency).
Scanned at 2026-02-09 17:25:51 CST for 156s

PORT      STATE SERVICE REASON         VERSION
31337/tcp open  Elite?  syn-ack ttl 63
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.98%I=7%D=2/9%Time=698A6D07%P=aarch64-unknown-linux-gn
SF:u%r(GetRequest,1F,"220\x20HTB{pr0F7pDv3r510nb4nn3r}\r\n");
```

### Analysis of Results

**Key Observations:**

1. **Multiple Probe Attempts** - Nmap tries 29+ different service probes to identify the service
2. **GetRequest Probe Success** - The `GetRequest` probe received a response with actual data
3. **Unrecognized Service** - Nmap couldn't match it to a known service, marked as "Elite?"
4. **Service Fingerprint** - Shows the raw response: `220\x20HTB{pr0F7pDv3r510nb4nn3r}\r\n`

### Decoding the Banner

The hex-encoded response `220\x20HTB{pr0F7pDv3r510nb4nn3r}\r\n` decodes to:
```
220 HTB{pr0F7pDv3r510nb4nn3r}
```

**Result:** Flag captured! `HTB{pr0F7pDv3r510nb4nn3r}`

### When to Use This Technique

✅ **Unknown services on non-standard ports** - Elite, custom, or obscured services  
✅ **Flag/challenge discovery** - CTF environments often hide flags in banners  
✅ **Detailed service analysis** - Understand exactly what the service is sending  
✅ **Security research** - Analyze service implementations at the protocol level  
✅ **Verification** - Confirm manual banner grabbing matches Nmap findings

---

## Best Practices for Service Enumeration

✅ **Start with quick scan** - Get port overview before full version detection  
✅ **Use `-sV` for version detection** - Essential for CVE research  
✅ **Monitor progress on long scans** - Use `--stats-every` or `-v`  
✅ **Use packet tracing for manual verification** - `--packet-trace` shows actual banners  
✅ **Combine tcpdump and nc** - Capture raw banners for verification  
✅ **Document all findings** - Save XML output for later analysis  
✅ **Follow up with NSE scripts** - Use version info to run targeted scripts  
✅ **Research CVEs** - Cross-reference versions with vulnerability databases  

---

## Next Steps

- [NSE Scripts](NSE_Scripts.md) - Automate enumeration using Nmap Scripting Engine
- [Firewall/IDS Evasion](Firewall_IDS_Evasion.md) - Techniques to bypass network defenses
