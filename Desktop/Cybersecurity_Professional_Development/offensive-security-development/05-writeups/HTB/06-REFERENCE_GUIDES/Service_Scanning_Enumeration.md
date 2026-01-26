# Service Scanning & Enumeration Cheat Sheet

---

## NMAP - Network Mapping & Port Scanning

### Basic Scans

| Command | Purpose |
|---------|---------|
| `nmap -p- target` | Scan all 65535 ports |
| `nmap -p 1-1000 target` | Scan specific port range |
| `nmap -p 22,80,443 target` | Scan specific ports |
| `nmap -sV target` | Detect service versions |
| `nmap -O target` | Detect OS |
| `nmap -A target` | Aggressive scan (OS, versions, scripts, traceroute) |
| `nmap -Pn target` | Skip ping, assume host is up |
| `nmap -sS target` | TCP SYN stealth scan |
| `nmap -sU target` | UDP scan |
| `nmap -sT target` | TCP connect scan |

### Output Formats

| Command | Purpose |
|---------|---------|
| `nmap -oN output.txt target` | Normal output to file |
| `nmap -oX output.xml target` | XML output to file |
| `nmap -oG output.greppable target` | Greppable output to file |
| `nmap -oA output target` | All formats (nmap, xml, greppable) |

### Timing & Performance

| Command | Purpose |
|---------|---------|
| `nmap -T1 target` | Paranoid (very slow) |
| `nmap -T3 target` | Normal speed |
| `nmap -T5 target` | Insane (very fast) |
| `nmap --min-rate 1000 target` | Minimum 1000 packets per second |

### Common Port Mappings

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 445 | SMB |
| 3306 | MySQL |
| 3389 | RDP |
| 5432 | PostgreSQL |
| 8080 | HTTP Alternate |

---

## NMAP Scripts (NSE - Nmap Scripting Engine)

### Script Locations
- Location: `/usr/share/nmap/scripts/`
- Update: `nmap --script-updatedb`

### Common Service Enumeration Scripts

| Command | Purpose |
|---------|---------|
| `nmap --script=smb-enum-shares -p 445 target` | Enumerate SMB shares |
| `nmap --script=smb-os-discovery -p 445 target` | Detect SMB OS |
| `nmap --script=ftp-anon -p 21 target` | Check FTP anonymous access |
| `nmap --script=http-title -p 80,443 target` | Grab HTTP page titles |
| `nmap --script=ssh-hostkey -p 22 target` | Get SSH host key |
| `nmap --script=dns-brute target` | DNS brute force |
| `nmap --script=snmp-sysdescr -p 161 target` | SNMP system description |

### Running Multiple Scripts

| Command | Purpose |
|---------|---------|
| `nmap --script=default -p 445 target` | Run default scripts |
| `nmap --script=smb-* -p 445 target` | Run all SMB scripts |
| `nmap --script=*-enum* -p- target` | Run all enumeration scripts |

---

## FTP - File Transfer Protocol (Port 21)

### Connection

| Command | Purpose |
|---------|---------|
| `ftp target.com` | Connect to FTP server |
| `ftp -p target.com` | Passive mode connection |
| `ftp anonymous@target.com` | Anonymous login |

### Common FTP Commands

| Command | Purpose |
|---------|---------|
| `ls` or `dir` | List directory contents |
| `pwd` | Print working directory |
| `cd directory` | Change directory |
| `get filename` | Download file |
| `put filename` | Upload file |
| `binary` | Set binary mode |
| `ascii` | Set ASCII mode |
| `help` | Show available commands |
| `quit` or `bye` | Exit FTP |

### NMAP FTP Enumeration

| Command | Purpose |
|---------|---------|
| `nmap --script=ftp-anon -p 21 target` | Check anonymous access |
| `nmap --script=ftp-bounce -p 21 target` | Check FTP bounce vulnerability |
| `nmap -sV -p 21 target` | Detect FTP version |

---

## SMB - Server Message Block (Port 445, 139)

### Connection Tools

| Command | Purpose |
|---------|---------|
| `smbclient -L target` | List SMB shares |
| `smbclient -L //target/share -U username` | List share contents |
| `smbclient //target/share -U username` | Connect to SMB share |
| `smb -N //target/share` | Null session SMB connection |

### NMAP SMB Enumeration

| Command | Purpose |
|---------|---------|
| `nmap --script=smb-enum-shares -p 445 target` | Enumerate shares |
| `nmap --script=smb-enum-users -p 445 target` | Enumerate users |
| `nmap --script=smb-os-discovery -p 445 target` | Detect OS information |
| `nmap --script=smb-protocols -p 445 target` | Detect SMB protocols |
| `nmap --script=smb-security-mode -p 445 target` | Detect security mode |

### SMB Tools

| Tool | Purpose |
|------|---------|
| `enum4linux` | Linux SMB enumeration tool |
| `crackmapexec` | SMB credential and host enumeration |
| `impacket` | Network protocol suite (includes SMB tools) |

### Common SMB Shares

| Share | Purpose |
|-------|---------|
| `C$` | System drive (admin only) |
| `D$, E$, etc.` | Additional drives (admin only) |
| `IPC$` | Inter-process communication (null access possible) |
| `ADMIN$` | Remote administration (admin only) |
| `PRINT$` | Printer driver repository |

---

## SHARES - Network Share Enumeration

### Identifying Shares

| Command | Purpose |
|---------|---------|
| `nmap --script=smb-enum-shares -p 445 target` | NMAP SMB share enumeration |
| `smbclient -L -N //target` | List shares null session |
| `smbclient -L //target -U username` | List shares with credentials |

### Mounting Shares (Linux)

| Command | Purpose |
|---------|---------|
| `mount -t cifs //target/share /mnt/share -o username=user` | Mount SMB share |
| `umount /mnt/share` | Unmount share |

### Accessing Shares

| Command | Purpose |
|---------|---------|
| `smbclient //target/share` | Interactive share access |
| `smbget -R smb://target/share` | Recursive download share |

---

## SNMP - Simple Network Management Protocol (Port 161)

### SNMP Basics

- Protocol: UDP port 161
- Community strings: Default often public/private
- Versions: SNMPv1, SNMPv2c, SNMPv3

### SNMP Enumeration Tools

| Command | Purpose |
|---------|---------|
| `snmpwalk -c public -v1 target` | SNMP v1 walk (public community) |
| `snmpwalk -c public -v2c target` | SNMP v2c walk |
| `snmpenum target public` | SNMP enumeration tool |
| `snmp-check -c public target` | SNMP info check |

### Common OIDs (Object Identifiers)

| OID | Information |
|-----|-------------|
| 1.3.6.1.2.1.1.1.0 | System description |
| 1.3.6.1.2.1.1.3.0 | System uptime |
| 1.3.6.1.2.1.25.3.2.1.5.1 | Running processes |
| 1.3.6.1.2.1.25.4.2.1.2 | Process names |
| 1.3.6.1.4.1.77.1.2.25 | User accounts |

### NMAP SNMP Scripts

| Command | Purpose |
|---------|---------|
| `nmap --script=snmp-sysdescr -p 161 target` | SNMP system description |
| `nmap --script=snmp-* -p 161 target` | All SNMP scripts |
| `nmap --script=snmp-interfaces -p 161 target` | Network interfaces |

---

## Methodology - Service Scanning Workflow

### Step 1: Port Discovery
- Run aggressive nmap scan: `nmap -A -p- target`
- Identify open ports and services
- Note version information

### Step 2: Service Enumeration
- Run NMAP scripts for detected services
- Use service-specific tools (smbclient, ftp, snmpwalk)
- Document shares, users, configurations

### Step 3: Vulnerability Assessment
- Research service versions for known vulnerabilities
- Test default credentials
- Check for misconfigurations

### Step 4: Documentation
- Record all services, versions, findings
- Note potential attack vectors
- Prioritize exploitation targets

---

## Quick Reference - Scanning Commands

```
nmap -sV -p- -A target > nmap_results.txt
nmap --script=smb-enum-shares -p 445 target
smbclient -L //target -U username
snmpwalk -c public -v1 target
ftp target
```

---

## Notes & Tips

- Always use -Pn when ping might be blocked
- Passive mode for FTP when having issues
- Try null sessions for SMB (username: "", password: "")
- Common default SNMP community: public, private
- Save all nmap output for reference
- Use -A flag for comprehensive information gathering
- Run scripts appropriate to detected services
