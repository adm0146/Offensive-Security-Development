# SNMP (Simple Network Management Protocol)

> Protocol for monitoring and managing network devices, handling configuration tasks, and changing settings remotely.

---

## Overview

**Simple Network Management Protocol (SNMP)** was created to monitor network devices. SNMP-enabled hardware includes:
- Routers
- Switches
- Servers
- IoT devices
- Many other network devices

SNMP transmits control commands using **agents over UDP port 161**. The client can set specific values, change options, and modify settings on devices.

---

## Default Ports

| Port | Protocol | Description |
|------|----------|-------------|
| **UDP 161** | SNMP | Standard SNMP queries and commands |
| **UDP 162** | SNMP Trap | Unsolicited notifications from server to client |

---

## SNMP Traps

Unlike classical client-server communication where the client requests information, SNMP enables **traps** - data packets sent from the SNMP server to the client **without being explicitly requested**.

- Sent over **UDP port 162**
- Triggered when specific events occur on the server
- Device must be configured to send traps

---

## MIB (Management Information Base)

The **MIB** ensures SNMP access works across manufacturers and different client-server combinations.

| Aspect | Description |
|--------|-------------|
| **Format** | Independent format for storing device information |
| **Structure** | Text file with queryable SNMP objects in standardized tree hierarchy |
| **Syntax** | Written in Abstract Syntax Notation One (ASN.1) based ASCII text format |
| **Content** | Does NOT contain data - explains where to find information and what format it uses |

### MIB Contains:
- **Object Identifier (OID)** - Unique address
- **Name** - Object name
- **Type** - Data type information
- **Access Rights** - Read/write permissions
- **Description** - Object description

---

## OID (Object Identifier)

An **OID** represents a node in a hierarchical namespace.

- Sequence of numbers uniquely identifies each node
- Allows determining the node's position in the tree
- **Longer chain = more specific information**
- Consists of integers concatenated by dot notation
- Many nodes only contain references to nodes below them

📚 **OID Registry:** [https://www.alvestrand.no/objectid/](https://www.alvestrand.no/objectid/)

---

## SNMP Versions

| Version | Authentication | Encryption | Notes |
|---------|---------------|------------|-------|
| **SNMPv1** | ❌ None | ❌ None | First version, still used in small networks. Anyone can read/modify network data |
| **SNMPv2c** | ❌ Community string only | ❌ None | Community-based SNMP. Community string transmitted in plaintext |
| **SNMPv3** | ✅ Username/Password | ✅ Pre-shared key | Significant security improvements but increased complexity |

### SNMPv1
- Used for network management and monitoring
- Supports retrieval of information, device configuration, and traps
- **No built-in authentication** - anyone on network can read/modify data
- **No encryption** - all data in plaintext, easily intercepted

### SNMPv2c
- "c" means community-based SNMP
- Extended with additional functions
- Security on par with SNMPv1
- **Community string transmitted in plaintext**

### SNMPv3
- Authentication using username and password
- Transmission encryption via pre-shared key
- Significantly more configuration options
- **Increased complexity** makes transition from v2c difficult

---

## Community Strings

**Community strings** act as passwords that determine whether requested information can be viewed.

| Risk | Detail |
|------|--------|
| **Plaintext Transmission** | Community strings sent over network can be intercepted and read |
| **Legacy Usage** | Many organizations still use SNMPv2 due to complex transition to SNMPv3 |
| **No Encryption** | Data sent without encryption exposes community strings |

> ⚠️ **Security Note:** The lack of encryption means every time community strings are sent over the network, they can be intercepted and read by attackers.

---

## Default Configuration

The default configuration defines basic settings including IP addresses, ports, MIB, OIDs, authentication, and community strings.

### View SNMP Daemon Config

```bash
cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'
```

```
sysLocation    Sitting on the Dock of the Bay
sysContact     Me <me@example.org>
sysServices    72
master  agentx
agentaddress  127.0.0.1,[::1]
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
rouser authPrivUser authpriv -V systemonly
```

---

## Dangerous Settings

| Setting | Description |
|---------|-------------|
| `rwuser noauth` | Provides access to full OID tree **without authentication** |
| `rwcommunity <community string> <IPv4 address>` | Provides access to full OID tree regardless of request source |
| `rwcommunity6 <community string> <IPv6 address>` | Same as rwcommunity but for IPv6 |

---

## Footprinting the Service

### Tools

| Tool | Purpose |
|------|---------|
| **snmpwalk** | Query OIDs with their information |
| **onesixtyone** | Brute-force community string names |
| **braa** | Brute-force individual OIDs and enumerate information |

---

### SNMPwalk

```bash
snmpwalk -v2c -c public 10.129.14.128
```

```
iso.3.6.1.2.1.1.1.0 = STRING: "Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (5134) 0:00:51.34
iso.3.6.1.2.1.1.4.0 = STRING: "mrb3n@inlanefreight.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "htb"
iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
...SNIP...
iso.3.6.1.2.1.25.6.3.1.2.1232 = STRING: "printer-driver-sag-gdi_0.1-7_all"
iso.3.6.1.2.1.25.6.3.1.2.1243 = STRING: "python3_3.8.2-0ubuntu2_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1244 = STRING: "python3-acme_1.1.0-1_all"
iso.3.6.1.2.1.25.6.3.1.2.1245 = STRING: "python3-apport_2.20.11-0ubuntu27.21_all"
iso.3.6.1.2.1.25.6.3.1.2.1246 = STRING: "python3-apt_2.0.0ubuntu0.20.04.6_amd64"
...SNIP...
```

> 💡 **Key Info Extracted:** OS version, contact email, hostname, location, installed packages

---

### OneSixtyOne - Community String Brute Force

```bash
sudo apt install onesixtyone
```

```bash
onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
```

```
Scanning 1 hosts, 3220 communities
10.129.14.128 [public] Linux htb 5.11.0-37-generic #41~20.04.2-Ubuntu SMP Fri Sep 24 09:06:38 UTC 2021 x86_64
```

> 💡 **Tip:** Community strings are often named with hostname patterns or symbols. Use **crunch** to create custom wordlists based on observed patterns.

📚 **Resources:**
- [Crunch Advanced Usage](https://secf00tprint.github.io/blog/passwords/crunch/advanced/en)
- [HTB Academy - Cracking Passwords with Hashcat](https://academy.hackthebox.com/course/preview/cracking-passwords-with-hashcat)

---

### Braa - OID Brute Force

```bash
sudo apt install braa
```

**Syntax:**
```bash
braa <community string>@<IP>:.1.3.6.*
```

**Example:**
```bash
braa public@10.129.14.128:.1.3.6.*
```

```
10.129.14.128:20ms:.1.3.6.1.2.1.1.1.0:Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64
10.129.14.128:20ms:.1.3.6.1.2.1.1.2.0:.1.3.6.1.4.1.8072.3.2.10
10.129.14.128:20ms:.1.3.6.1.2.1.1.3.0:548
10.129.14.128:20ms:.1.3.6.1.2.1.1.4.0:mrb3n@inlanefreight.htb
10.129.14.128:20ms:.1.3.6.1.2.1.1.5.0:htb
10.129.14.128:20ms:.1.3.6.1.2.1.1.6.0:US
10.129.14.128:20ms:.1.3.6.1.2.1.1.7.0:78
...SNIP...
```

---

## Quick Reference

| Task | Command |
|------|---------|
| SNMPwalk query | `snmpwalk -v2c -c <community> <IP>` |
| Community string brute force | `onesixtyone -c <wordlist> <IP>` |
| OID brute force | `braa <community>@<IP>:.1.3.6.*` |
| View SNMP config | `cat /etc/snmp/snmpd.conf \| grep -v "#" \| sed -r '/^\s*$/d'` |

---

## Practical Enumeration Lab

### Lab Setup

| Component | Details |
|-----------|---------|
| **Attacker** | Kali Linux (Parallels) |
| **Target** | Ubuntu Server 24.04 (Parallels, host-only network) |
| **Target IP** | 10.211.55.4 |

### Configuring a Vulnerable Target

```bash
# Install SNMP daemon
sudo apt install snmpd -y

# Key config changes in /etc/snmp/snmpd.conf
agentaddress udp:161              # listen on all interfaces
rocommunity public 0.0.0.0/0      # allow public community from anywhere

sudo systemctl restart snmpd
```

### Enumeration Commands

```bash
# Basic SNMPwalk
snmpwalk -c public -v1 10.211.55.4

# SNMP-check for detailed enumeration
snmp-check 10.211.55.4 -c public

# Filter for interesting services/credentials
snmp-check 10.211.55.4 -c public | grep -iE "apache|nginx|ssh|ftp|root|sudo|python|bash|password"

# Find user information
snmp-check 10.211.55.4 -c public | grep -A2 "user"
```

### Key Findings

| Category | Discovery |
|----------|-----------|
| **OS** | Ubuntu 24.04, kernel 6.17, aarch64 |
| **Active User** | UID 1000 session active |
| **Credential Store** | gnome-keyring-daemon running (unlocked) |
| **SSH Agent** | gcr-ssh-agent active at `/run/user/1000/gcr` (SSH keys potentially loaded) |
| **FTP** | ftp_20230507, tnftp_20230507 installed |
| **Sudo** | Version 1.9.15p5 |
| **Shell** | Interactive bash session open (PID 3191) |

### Why This Is Dangerous

> ⚠️ **SNMP v1/v2c has NO encryption and NO real authentication.**

The community string `public` is the **default on nearly every device**. A single UDP port enumeration revealed:

- ✅ Full OS info
- ✅ Network topology
- ✅ Running processes
- ✅ Installed software versions
- ✅ Active credential stores

**All without authentication.**

---
