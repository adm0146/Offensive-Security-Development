# Kali Linux Docker Container - Quick Reference Guide
**Container Name:** `kali-security-plus`  
**Created:** November 22, 2025  
**Purpose:** Security+ SY0-701 hands-on practice

---

## 🚀 Quick Commands

### Access Your Kali Container
```bash
# Enter the Kali Linux container (interactive terminal)
docker exec -it kali-security-plus /bin/bash

# Run a single command without entering the container
docker exec kali-security-plus <command>
```

### Container Management
```bash
# Start the container (if stopped)
docker start kali-security-plus

# Stop the container
docker stop kali-security-plus

# Check if container is running
docker ps

# View all containers (including stopped)
docker ps -a

# Remove the container (if you need to start fresh)
docker rm kali-security-plus
```

---

## 🛠️ Installed Tools

### Network Scanning & Reconnaissance
- **nmap** - Network mapper and port scanner
- **netcat-traditional** - Network utility for reading/writing network connections
- **dnsutils** - DNS utilities (dig, nslookup)
- **net-tools** - Network tools (ifconfig, netstat, route)
- **iputils-ping** - Ping utility

### Network Analysis
- **wireshark** - Network protocol analyzer (command-line: tshark)
- **tcpdump** - Packet analyzer

### Top 10 Kali Tools Package
The container includes **kali-tools-top10** which provides:
- **Metasploit Framework** - Penetration testing framework
- **Aircrack-ng** - Wireless security auditing
- **Hydra** - Network logon cracker
- **John the Ripper** - Password cracker
- **SQLmap** - SQL injection tool
- **Nmap** - Network scanner
- **Wireshark** - Protocol analyzer
- **Netexec** - Network execution tool
- **Responder** - LLMNR/NBT-NS/mDNS poisoner
- **Bloodhound.py** - Active Directory reconnaissance

---

## 📚 Security+ Practice Examples

### Example 1: Port Scanning with Nmap
```bash
# Enter the container
docker exec -it kali-security-plus /bin/bash

# Scan a target (use only on networks you own!)
nmap -sV scanme.nmap.org

# Scan common ports
nmap -F scanme.nmap.org

# Exit the container
exit
```

### Example 2: DNS Lookup
```bash
# Check DNS records
docker exec kali-security-plus dig google.com

# Reverse DNS lookup
docker exec kali-security-plus nslookup 8.8.8.8
```

### Example 3: Network Connectivity Test
```bash
# Ping test
docker exec kali-security-plus ping -c 4 google.com

# Traceroute
docker exec kali-security-plus traceroute google.com
```

### Example 4: Packet Capture with tcpdump
```bash
# Capture network traffic (requires special permissions)
docker exec kali-security-plus tcpdump -i any -c 10
```

---

## 🎯 Security+ Relevant Topics

### Tools Map to Exam Objectives:

**Section 1.4 - Cryptographic Solutions:**
- Use `openssl` commands for certificate inspection
- Practice hashing with various algorithms

**Section 2.1 - Threat Actors:**
- Understand tool capabilities (covered by Metasploit, Hydra)

**Section 2.4 - Vulnerabilities:**
- Use Nmap for vulnerability discovery
- SQLmap for database vulnerabilities

**Section 3.3 - Security Assessment:**
- Network scanning (Nmap)
- Packet analysis (Wireshark, tcpdump)
- Password cracking concepts (John the Ripper)

**Section 4.1 - Security Monitoring:**
- Network monitoring (tcpdump, Wireshark)
- Log analysis concepts

---

## ⚠️ Important Notes

### Legal & Ethical Usage
- **ONLY** use these tools on:
  - Your own systems
  - Lab environments you created
  - Systems where you have explicit written permission
- **NEVER** scan or attack systems you don't own
- Unauthorized use is illegal and unethical

### Practice Targets
Safe places to practice:
- **scanme.nmap.org** - Nmap's official test server
- **testphp.vulnweb.com** - Web security testing
- Your own local VMs
- TryHackMe.com or HackTheBox practice labs

### Container Limitations
- Docker containers are isolated from your Mac's network by default
- Some tools require elevated privileges (may not work in container)
- For full functionality, consider using UTM or Parallels for a full Kali VM

---

## 🔧 Useful Commands Inside Kali

### Update Package List
```bash
docker exec kali-security-plus apt-get update
```

### Install Additional Tools
```bash
docker exec kali-security-plus apt-get install -y <package-name>
```

### Check Installed Tool Version
```bash
docker exec kali-security-plus nmap --version
docker exec kali-security-plus msfconsole --version
```

---

## 📖 Learning Resources

### Nmap
- `man nmap` (inside container)
- https://nmap.org/book/

### Wireshark
- https://www.wireshark.org/docs/
- Use `tshark` for command-line packet analysis

### Metasploit
- https://docs.metasploit.com/
- Start with: `msfconsole`

---

## 🎓 For Security+ Exam

**Remember:** Security+ is NOT a hands-on penetration testing exam!

**You need to know:**
- ✅ What these tools DO (conceptually)
- ✅ When to use each tool
- ✅ What results they provide
- ✅ How they fit into security workflows

**You DON'T need to:**
- ❌ Master every command-line option
- ❌ Write exploits
- ❌ Perform actual penetration tests

**Best Use:** Play with tools to understand concepts, then focus on practice questions!

---

## 💡 Pro Tips

1. **Start Simple:** Begin with basic `nmap` and `ping` commands
2. **Read Help:** Most tools have `--help` or `-h` options
3. **Practice Ethically:** Only scan systems you own
4. **Focus on Concepts:** Understand what tools do, not just syntax
5. **Time Management:** Don't spend too long on labs - prioritize video learning and practice questions for Security+

---

## 🆘 Troubleshooting

### Container Won't Start
```bash
docker start kali-security-plus
docker ps  # Check if running
```

### Need to Reset Everything
```bash
docker stop kali-security-plus
docker rm kali-security-plus
# Then re-run the setup commands
```

### Need More Tools
```bash
docker exec -it kali-security-plus /bin/bash
apt-get update
apt-cache search <tool-name>
apt-get install -y <tool-name>
```

---

**Created:** November 22, 2025  
**For:** Security+ SY0-701 Certification Study  
**Next Steps:** Complete 75 practice questions on Sections 1.1-1.3!
