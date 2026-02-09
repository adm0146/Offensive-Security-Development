# Network Enumeration with Nmap

---

## Section 1: Host Discovery

### Overview
When conducting internal penetration tests for entire networks, the first step is to discover which systems are online and available. Host discovery identifies active targets before deeper enumeration. Nmap provides multiple methods to determine if hosts are alive, with ICMP echo requests being one of the most effective approaches.

**Best Practice:** Always store every scan in multiple formats for comparison, documentation, and reporting. Different tools may produce different results, so documenting which tool produced which results is critical for professional reporting.

---

## Host Discovery Methods

### Scan Network Range

**Purpose:** Discover all active hosts within a network subnet

**Command:**
```bash
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `10.129.2.0/24` | Target network range (CIDR notation) |
| `-sn` | Disable port scanning (ping scan only) |
| `-oA tnet` | Store results in all formats (nmap, xml, greppable) with filename 'tnet' |
| `grep for \| cut -d" " -f5` | Parse output to show only IP addresses |

**Limitation:** This method only works if target host firewalls allow ICMP echo requests. Hosts with strict firewall rules may not respond, appearing as "down" despite being active.

---

### Scan IP List

**Purpose:** Scan multiple targets from a provided list file

**Command:**
```bash
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `-sn` | Disable port scanning (ping scan only) |
| `-oA tnet` | Store results in all formats with filename 'tnet' |
| `-iL hosts.lst` | Input list - reads target hosts from 'hosts.lst' file |
| `grep for \| cut -d" " -f5` | Parse output to show only IP addresses |

**Expected Result:** Scans each IP in the list. Typically, only a portion of listed hosts will respond (e.g., 3 of 7). Non-responsive hosts may be:
- Actually offline
- Blocking ICMP echo requests via firewall
- Behind network filtering

---

### Scan Multiple Individual IPs

**Purpose:** Discover hosts when scanning specific, non-consecutive IP addresses

**Command:**
```bash
sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20 | grep for | cut -d" " -f5
```

**For Consecutive IPs - Use Range Notation:**
```bash
sudo nmap -sn -oA tnet 10.129.2.18-20 | grep for | cut -d" " -f5
```

**Advantages:**
- Precise targeting of specific hosts
- Faster than full subnet scans
- Reduces network traffic

---

### Scan Single IP

**Purpose:** Determine if a specific target host is alive before port scanning

**Command:**
```bash
sudo nmap 10.129.2.18 -sn -oA host
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `10.129.2.18` | Target IP address |
| `-sn` | Disable port scanning |
| `-oA host` | Store results in all formats with filename 'host' |

**How It Works:** When `-sn` is used, Nmap automatically performs a ping scan using ICMP Echo Requests (`-PE`). However, on local networks, Nmap typically sends ARP pings first, which may receive an ARP reply before ICMP requests are sent.

---

## Advanced Host Discovery Techniques

### ICMP Echo Request Verification

**Purpose:** Confirm ICMP echo requests are being sent (not just ARP)

**Command:**
```bash
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `-PE` | Ping scan using ICMP Echo requests |
| `--packet-trace` | Show all packets sent and received (detailed view) |

**Key Insight:** Without `--disable-arp-ping`, Nmap may use ARP pings on local networks, which are faster and don't require ICMP. The `--packet-trace` option reveals which discovery method Nmap actually used.

---

### Understanding Discovery Reasons

**Purpose:** Identify why Nmap marked a host as "alive"

**Command:**
```bash
sudo nmap 10.129.2.18 -sn -oA host -PE --reason
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `--reason` | Display the reason Nmap determined the host is alive |

**Output Example:** Shows whether the host was detected as alive through:
- ARP request/reply
- ICMP echo request/reply
- Other discovery methods

---

### Disable ARP Ping (Force ICMP)

**Purpose:** Bypass ARP and force pure ICMP echo request scanning

**Command:**
```bash
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping
```

**Options Explained:**
| Option | Purpose |
|--------|---------|
| `-PE` | Use ICMP Echo requests |
| `--packet-trace` | Show all packets sent and received |
| `--disable-arp-ping` | Disable ARP ping (force ICMP only) |

**When to Use:** 
- Testing network segmentation
- Bypassing ARP-based discovery filters
- Verifying ICMP connectivity specifically
- Documenting ICMP-based discovery for reporting

---

## Host Discovery Comparison Table

| Method | Command | Best For | Limitations |
|--------|---------|----------|------------|
| **Network Range** | `nmap 10.129.2.0/24 -sn` | Discovering entire subnets | Firewall filtering, slow on large networks |
| **IP List** | `nmap -sn -iL hosts.lst` | Scanning provided target lists | Depends on firewall config, list must exist |
| **Multiple IPs** | `nmap -sn 10.129.2.18-20` | Small groups of targets | Less efficient than ranges |
| **Single IP** | `nmap 10.129.2.18 -sn` | Pre-scan verification | Only discovers one host |
| **ICMP Forced** | `nmap 10.129.2.18 -PE --disable-arp-ping` | ICMP-specific testing | Slower, may timeout on ARP-only networks |

---

## Output Storage Options

**Always use `-oA` for comprehensive documentation:**

```bash
-oA tnet    # Stores in three formats:
            # - tnet.nmap (normal output)
            # - tnet.xml (XML format for parsing)
            # - tnet.gnmap (greppable format for filtering)
```

**Parsing Output Examples:**

Extract only IPs from greppable output:
```bash
nmap -sn -oA tnet 10.129.2.0/24
cat tnet.gnmap | grep "Status: Up" | cut -d' ' -f2
```

Convert XML for further analysis:
```bash
# XML can be imported into:
# - Metasploit (msfconsole)
# - Other security tools
# - Custom scripts
```

---

## Key Takeaways

✅ **Always store scans** in multiple formats (`-oA`) for documentation and comparison  
✅ **Understand your network** - ARP vs ICMP behavior differs on local vs remote targets  
✅ **Document discovery methods** - `--reason` and `--packet-trace` provide transparency  
✅ **Firewall awareness** - Failed pings don't mean hosts are offline  
✅ **Start simple** - Begin with basic scans, add complexity as needed  

---

## Additional Resources

- Complete host discovery strategies: https://nmap.org/book/host-discovery-strategies.html
- Nmap man page: `man nmap`
- Firewall evasion techniques: See "Firewall and IDS Evasion" section in CPTS curriculum

