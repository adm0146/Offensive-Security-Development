# SMB (Server Message Block)

> Client-server protocol for accessing files, directories, and network resources (printers, routers, interfaces).

---

## Overview

SMB regulates access to:
- Files and directories
- Printers
- Routers
- Network interfaces

**Key Feature:** Enables information exchange between different system processes.

---

## History & Platform Support

| Platform | Implementation |
|----------|----------------|
| **Windows** | Native support since OS/2 LAN Manager/LAN Server |
| **Linux/Unix** | Samba (free software project) |

### Windows Backward Compatibility
- Newer Windows editions can communicate with older Microsoft operating systems
- Downward-compatible network services

### Cross-Platform Communication
- **Samba** enables SMB on Linux and Unix distributions
- Allows cross-platform file sharing and communication

---

## How SMB Works

### Connection Process

```
1. Client wants to access shared files/services
2. Both parties exchange messages to establish connection
3. Three-way TCP handshake occurs
4. Connection established
5. Data transport governed by TCP protocol specs
```

**Protocol Layer:** SMB uses TCP in IP networks

### Requirements
- Both systems must implement SMB protocol
- Server must have SMB server application running
- Server receives and processes client requests

📚 SMB2 Protocol Specification: [MS-SMB2 Documentation](https://web.archive.org/web/20240815212710/https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SMB2/%5BMS-SMB2%5D.pdf)

---

## Shares & Access Control

### File System Shares
- SMB server provides arbitrary parts of local file system as **shares**
- Client view is partially independent of server's actual structure
- Hierarchy visible to client ≠ physical server structure

### Access Control Lists (ACLs)

| Attribute | Description |
|-----------|-------------|
| **Execute** | Run files/programs |
| **Read** | View file contents |
| **Full Access** | Complete control |

**ACL Scope:**
- Defined per share (not per local file)
- Can target individual users OR user groups
- Fine-grained control over access

⚠️ **Important:** Share ACLs do NOT correspond to local server permissions

---

## Quick Reference

```bash
# Default port
TCP 445 (Direct SMB over TCP)
TCP 139 (SMB over NetBIOS)

# Protocol
Uses TCP for reliable data transfer
Three-way handshake before connection
```

---

## Security Considerations

| Risk | Detail |
|------|--------|
| **Share Permissions** | ACLs may expose sensitive data |
| **Anonymous Access** | Misconfigured shares allow unauthenticated access |
| **Version Vulnerabilities** | Older SMB versions (SMBv1) have known exploits |

---

## Samba

> Alternative SMB server implementation for Unix-based operating systems.

### CIFS (Common Internet File System)

- Samba implements CIFS network protocol
- **CIFS is a dialect of SMB** — specific implementation originally created by Microsoft
- Allows Samba to communicate with newer Windows systems
- Often referred to as **SMB/CIFS**
- CIFS primarily aligns with **SMB version 1**

### Ports

| Protocol | Ports | Description |
|----------|-------|-------------|
| **NetBIOS** | TCP 137, 138, 139 | SMB commands via older NetBIOS service |
| **CIFS** | TCP 445 | Direct SMB over TCP (exclusively) |

---

## SMB Versions

| SMB Version | Supported | Features |
|-------------|-----------|----------|
| **CIFS** | Windows NT 4.0 | Communication via NetBIOS interface |
| **SMB 1.0** | Windows 2000 | Direct connection via TCP |
| **SMB 2.0** | Windows Vista, Server 2008 | Performance upgrades, improved message signing, caching |
| **SMB 2.1** | Windows 7, Server 2008 R2 | Locking mechanisms |
| **SMB 3.0** | Windows 8, Server 2012 | Multichannel connections, end-to-end encryption, remote storage access |
| **SMB 3.0.2** | Windows 8.1, Server 2012 R2 | — |
| **SMB 3.1.1** | Windows 10, Server 2016 | Integrity checking, AES-128 encryption |

⚠️ **Note:** SMB 1 (CIFS) is outdated but may still be used in specific environments. Modern infrastructure prefers SMB 2/3.

---

## Samba Capabilities

### Version 3+
- Full member of an **Active Directory domain**

### Version 4
- Can act as an **Active Directory domain controller**

### Samba Daemons

| Daemon | Description |
|--------|-------------|
| **smbd** | SMB server daemon - provides file sharing and printer services |
| **nmbd** | NetBIOS name server daemon - handles name registration |

**Note:** The SMB service controls these background programs (Unix daemons).

---

## Workgroups & NetBIOS

### Workgroups
- Group name identifying an arbitrary collection of computers and resources
- Multiple workgroups can exist on a network simultaneously
- Each host participates in the same workgroup

### NetBIOS (Network Basic Input/Output System)

- API developed by IBM for networking computers
- Provides blueprint for applications to connect and share data
- When a machine goes online, it needs a name (**name registration procedure**)

### Name Registration Methods

| Method | Description |
|--------|-------------|
| **Host Reservation** | Each host reserves its hostname on the network |
| **NBNS** | NetBIOS Name Server handles name registration |
| **WINS** | Windows Internet Name Service (enhanced NBNS) |

---

## Default Configuration

Config file: `/etc/samba/smb.conf`

```bash
# View active settings (exclude comments)
cat /etc/samba/smb.conf | grep -v "#\|\;"
```

### Example Configuration

```ini
[global]
   workgroup = DEV.INFREIGHT.HTB
   server string = DEVSMB
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   panic action = /usr/share/samba/panic-action %d

   server role = standalone server
   obey pam restrictions = yes
   unix password sync = yes

   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .

   pam password change = yes
   map to guest = bad user
   usershare allow guests = yes

[printers]
   comment = All Printers
   browseable = no
   path = /var/spool/samba
   printable = yes
   guest ok = no
   read only = yes
   create mask = 0700

[print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
   browseable = yes
   read only = yes
   guest ok = no
```

**Note:** Global settings apply to all shares. Individual shares can overwrite global settings.

---

## Key Settings

| Setting | Description |
|---------|-------------|
| `[sharename]` | The name of the network share |
| `workgroup = WORKGROUP/DOMAIN` | Workgroup that appears when clients query |
| `path = /path/here/` | Directory to which user is given access |
| `server string = STRING` | String shown when connection is initiated |
| `unix password sync = yes` | Synchronize UNIX password with SMB password |
| `usershare allow guests = yes` | Allow non-authenticated users to access share |
| `map to guest = bad user` | Action when login doesn't match valid UNIX user |
| `browseable = yes` | Show share in list of available shares |
| `guest ok = yes` | Allow connecting without password |
| `read only = yes` | Allow users to read files only |
| `create mask = 0700` | Permissions for newly created files |

---

## Dangerous Settings (Pentester's Focus)

| Setting | Description |
|---------|-------------|
| `browseable = yes` | Allow listing available shares in current share |
| `read only = no` | Allow creation and modification of files |
| `writable = yes` | Allow users to create and modify files |
| `guest ok = yes` | Allow connecting without password |
| `enable privileges = yes` | Honor privileges assigned to specific SID |
| `create mask = 0777` | World-writable permissions on new files |
| `directory mask = 0777` | World-writable permissions on new directories |
| `logon script = script.sh` | Script executed on user login |
| `magic script = script.sh` | Script executed when script gets closed |
| `magic output = script.out` | Where magic script output is stored |

### Example Vulnerable Share

```ini
[notes]
    comment = CheckIT
    path = /mnt/notes/

    browseable = yes
    read only = no
    writable = yes
    guest ok = yes

    enable privileges = yes
    create mask = 0777
    directory mask = 0777
```

⚠️ **Risk:** Often applied for testing, then forgotten — allows anonymous browsing, reading, and writing.

---

## Samba Management

### Restart Service
```bash
sudo systemctl restart smbd
```

---

## SMB Enumeration with smbclient

### List Shares (Null Session)
```bash
smbclient -N -L //10.129.14.128
```

| Flag | Description |
|------|-------------|
| `-N` | Null session (anonymous access, no password) |
| `-L` | List shares on server |

**Example Output:**
```
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
home            Disk      INFREIGHT Samba
dev             Disk      DEVenv
notes           Disk      CheckIT
IPC$            IPC       IPC Service (DEVSM)
SMB1 disabled -- no workgroup available
```

**Note:** `print$` and `IPC$` are included by default.

### Connect to Share
```bash
smbclient //10.129.14.128/notes
```

**Example Session:**
```
Enter WORKGROUP\<username>'s password: 
Anonymous login successful
Try "help" to get a list of possible commands.

smb: \> ls
  .                                   D        0  Wed Sep 22 18:17:51 2021
  ..                                  D        0  Wed Sep 22 12:03:59 2021
  prep-prod.txt                       N       71  Sun Sep 19 15:45:21 2021

                30313412 blocks of size 1024. 16480084 blocks available
```

### smbclient Commands

```
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!
```

### Key Commands

| Command | Description |
|---------|-------------|
| `help` | List all available commands |
| `ls` | List directory contents |
| `get <file>` | Download file |
| `put <file>` | Upload file |
| `cd <dir>` | Change directory |
| `!<cmd>` | Execute local system command without disconnecting |

### Download Files

```bash
smb: \> get prep-prod.txt 
getting file \prep-prod.txt of size 71 as prep-prod.txt (8,7 KiloBytes/sec) 
(average 8,7 KiloBytes/sec)

smb: \> !ls
prep-prod.txt

smb: \> !cat prep-prod.txt
[] check your code with the templates
[] run code-assessment.py
[] …
```

---

## Samba Status (Admin View)

Check active connections from the server side:

```bash
root@samba:~# smbstatus
```

**Example Output:**
```
Samba version 4.11.6-Ubuntu
PID     Username     Group        Machine                                   Protocol Version  Encryption           Signing              
----------------------------------------------------------------------------------------------------------------------------------------
75691   sambauser    samba        10.10.14.4 (ipv4:10.10.14.4:45564)      SMB3_11           -                    -                    

Service      pid     Machine       Connected at                     Encryption   Signing     
---------------------------------------------------------------------------------------------
notes        75691   10.10.14.4   Do Sep 23 00:12:06 2021 CEST     -            -           

No locked files
```

**Shows:** Samba version, who is connected, from which host, which share, protocol version

### Domain-Level Security
- Samba server acts as member of Windows domain
- Domain controller (usually Windows NT server) provides password authentication
- Domain controllers track users/passwords in **NTDS.dit** and **SAM**
- Authenticates users on first login when accessing another machine's share

---

## Footprinting with Nmap

```bash
sudo nmap 10.129.14.128 -sV -sC -p139,445
```

**Example Output:**
```
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
MAC Address: 00:00:00:00:00:00 (VMware)

Host script results:
|_nbstat: NetBIOS name: HTB, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-19T13:16:04
|_  start_date: N/A
```

**Note:** Nmap provides limited info. Use manual tools for deeper enumeration.

---

## RPCclient Enumeration

> Tool for MS-RPC functions — Remote Procedure Call for client-server communication.

### Connect (Null Session)
```bash
rpcclient -U "" 10.129.14.128
Enter WORKGROUP\'s password:
rpcclient $>
```

### RPC Queries

| Query | Description |
|-------|-------------|
| `srvinfo` | Server information |
| `enumdomains` | Enumerate all domains deployed in network |
| `querydominfo` | Domain, server, and user information |
| `netshareenumall` | Enumerate all available shares |
| `netsharegetinfo <share>` | Information about specific share |
| `enumdomusers` | Enumerate all domain users |
| `queryuser <RID>` | Information about specific user |
| `querygroup <RID>` | Information about specific group |

### Server Information
```bash
rpcclient $> srvinfo
        DEVSMB         Wk Sv PrQ Unx NT SNT DEVSM
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03
```

### Enumerate Domains
```bash
rpcclient $> enumdomains
name:[DEVSMB] idx:[0x0]
name:[Builtin] idx:[0x1]

rpcclient $> querydominfo
Domain:         DEVOPS
Server:         DEVSMB
Comment:        DEVSM
Total Users:    2
Total Groups:   0
Total Aliases:  0
Sequence No:    1632361158
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1
```

### Enumerate Shares
```bash
rpcclient $> netshareenumall
netname: print$
        remark: Printer Drivers
        path:   C:\var\lib\samba\printers
        password:
netname: home
        remark: INFREIGHT Samba
        path:   C:\home\
        password:
netname: dev
        remark: DEVenv
        path:   C:\home\sambauser\dev\
        password:
netname: notes
        remark: CheckIT
        path:   C:\mnt\notes\
        password:
netname: IPC$
        remark: IPC Service (DEVSM)
        path:   C:\tmp
        password:
```

### Share Details with ACL Info
```bash
rpcclient $> netsharegetinfo notes
netname: notes
        remark: CheckIT
        path:   C:\mnt\notes\
        password:
        type:   0x0
        perms:  0
        max_uses:       -1
        num_uses:       1
revision: 1
type: 0x8004: SEC_DESC_DACL_PRESENT SEC_DESC_SELF_RELATIVE 
DACL
        ACL     Num ACEs:       1       revision:       2
        ---
        ACE
                type: ACCESS ALLOWED (0) flags: 0x00 
                Specific bits: 0x1ff
                Permissions: 0x101f01ff: Generic all access SYNCHRONIZE_ACCESS WRITE_OWNER_ACCESS WRITE_DAC_ACCESS READ_CONTROL_ACCESS DELETE_ACCESS 
                SID: S-1-1-0
```

---

## User Enumeration

### List Domain Users
```bash
rpcclient $> enumdomusers
user:[mrb3n] rid:[0x3e8]
user:[cry0l1t3] rid:[0x3e9]
```

### Query Specific User by RID
```bash
rpcclient $> queryuser 0x3e9
        User Name   :   cry0l1t3
        Full Name   :   cry0l1t3
        Home Drive  :   \\devsmb\cry0l1t3
        Dir Drive   :
        Profile Path:   \\devsmb\cry0l1t3\profile
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Do, 01 Jan 1970 01:00:00 CET
        Logoff Time              :      Mi, 06 Feb 2036 16:06:39 CET
        Kickoff Time             :      Mi, 06 Feb 2036 16:06:39 CET
        Password last set Time   :      Mi, 22 Sep 2021 17:50:56 CEST
        Password can change Time :      Mi, 22 Sep 2021 17:50:56 CEST
        Password must change Time:      Do, 14 Sep 30828 04:48:05 CEST
        user_rid :      0x3e9
        group_rid:      0x201
        acb_info :      0x00000014
        bad_password_count:     0x00000000
        logon_count:    0x00000000
```

### Query Group Information
```bash
rpcclient $> querygroup 0x201
        Group Name:     None
        Description:    Ordinary Users
        Group Attribute:7
        Num Members:2
```

---

## RID Brute Force

> When `enumdomusers` is restricted, brute force RIDs to discover users.

### Bash Loop Method
```bash
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```

**Output:**
```
User Name   :   sambauser
        user_rid :      0x1f5
        group_rid:      0x201
		
User Name   :   mrb3n
        user_rid :      0x3e8
        group_rid:      0x201
		
User Name   :   cry0l1t3
        user_rid :      0x3e9
        group_rid:      0x201
```

### Alternative: Impacket samrdump.py
```bash
samrdump.py 10.129.14.128
```

**Output:**
```
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Retrieving endpoint list from 10.129.14.128
Found domain(s):
 . DEVSMB
 . Builtin
[*] Looking up users in domain DEVSMB
Found user: mrb3n, uid = 1000
Found user: cry0l1t3, uid = 1001
mrb3n (1000)/FullName: 
mrb3n (1000)/UserComment: 
mrb3n (1000)/PrimaryGroupId: 513
mrb3n (1000)/BadPasswordCount: 0
mrb3n (1000)/LogonCount: 0
mrb3n (1000)/PasswordLastSet: 2021-09-22 17:47:59
mrb3n (1000)/PasswordDoesNotExpire: False
mrb3n (1000)/AccountIsDisabled: False
mrb3n (1000)/ScriptPath: 
cry0l1t3 (1001)/FullName: cry0l1t3
cry0l1t3 (1001)/UserComment: 
cry0l1t3 (1001)/PrimaryGroupId: 513
cry0l1t3 (1001)/BadPasswordCount: 0
cry0l1t3 (1001)/LogonCount: 0
cry0l1t3 (1001)/PasswordLastSet: 2021-09-22 17:50:56
cry0l1t3 (1001)/PasswordDoesNotExpire: False
cry0l1t3 (1001)/AccountIsDisabled: False
cry0l1t3 (1001)/ScriptPath: 
[*] Received 2 entries.
```

---

## SMBMap

> Quick share enumeration with permission checking.

```bash
smbmap -H 10.129.14.128
```

**Output:**
```
[+] Finding open SMB ports....
[+] User SMB session established on 10.129.14.128...
[+] IP: 10.129.14.128:445       Name: 10.129.14.128                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        home                                                    NO ACCESS       INFREIGHT Samba
        dev                                                     NO ACCESS       DEVenv
        notes                                                   NO ACCESS       CheckIT
        IPC$                                                    NO ACCESS       IPC Service (DEVSM)
```

---

## CrackMapExec (CME)

> Swiss army knife for network pentesting — shows permissions clearly.

```bash
crackmapexec smb 10.129.14.128 --shares -u '' -p ''
```

**Output:**
```
SMB         10.129.14.128   445    DEVSMB           [*] Windows 6.1 Build 0 (name:DEVSMB) (domain:) (signing:False) (SMBv1:False)
SMB         10.129.14.128   445    DEVSMB           [+] \: 
SMB         10.129.14.128   445    DEVSMB           [+] Enumerated shares
SMB         10.129.14.128   445    DEVSMB           Share           Permissions     Remark
SMB         10.129.14.128   445    DEVSMB           -----           -----------     ------
SMB         10.129.14.128   445    DEVSMB           print$                          Printer Drivers
SMB         10.129.14.128   445    DEVSMB           home                            INFREIGHT Samba
SMB         10.129.14.128   445    DEVSMB           dev                             DEVenv
SMB         10.129.14.128   445    DEVSMB           notes           READ,WRITE      CheckIT
SMB         10.129.14.128   445    DEVSMB           IPC$                            IPC Service (DEVSM)
```

**Note:** CME clearly shows `READ,WRITE` permissions on `notes` share!

---

## Enum4Linux-ng

> Automated enumeration tool — successor to enum4linux.

### Installation
```bash
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt
```

### Run Full Enumeration
```bash
./enum4linux-ng.py 10.129.14.128 -A
```

### Example Output (Key Sections)

**Target & Service Scan:**
```
[*] Target ........... 10.129.14.128
[+] SMB is accessible on 445/tcp
[+] SMB over NetBIOS is accessible on 139/tcp
```

**NetBIOS Names:**
```
[+] Got domain/workgroup name: DEVOPS
- DEVSMB          <00> -         H <ACTIVE>  Workstation Service
- DEVSMB          <03> -         H <ACTIVE>  Messenger Service
- DEVSMB          <20> -         H <ACTIVE>  File Server Service
- DEVOPS          <00> - <GROUP> H <ACTIVE>  Domain/Workgroup Name
- DEVOPS          <1d> -         H <ACTIVE>  Master Browser
```

**SMB Dialect Check:**
```
SMB 1.0: false
SMB 2.02: true
SMB 2.1: true
SMB 3.0: true
Preferred dialect: SMB 3.0
SMB signing required: false
```

**Null Session Check:**
```
[+] Server allows session using username '', password ''
[+] Server allows session using username 'juzgtcsu', password ''
[H] Rerunning enumeration with user 'juzgtcsu' might give more results
```

**OS Information:**
```
OS: Windows 7, Windows Server 2008 R2
OS version: '6.1'
Platform id: '500'
Server type string: Wk Sv PrQ Unx NT SNT DEVSM
```

**Users Found:**
```
'1000':
  username: mrb3n
  name: ''
  acb: '0x00000010'
  description: ''
'1001':
  username: cry0l1t3
  name: cry0l1t3
  acb: '0x00000014'
  description: ''
```

**Shares Found:**
```
IPC$:
  comment: IPC Service (DEVSM)
  type: IPC
dev:
  comment: DEVenv
  type: Disk
home:
  comment: INFREIGHT Samba
  type: Disk
notes:
  comment: CheckIT
  type: Disk
print$:
  comment: Printer Drivers
  type: Disk

[*] Testing share home
[+] Mapping: OK, Listing: OK
[*] Testing share notes
[+] Mapping: OK, Listing: OK
[*] Testing share print$
[+] Mapping: DENIED, Listing: N/A
```

**Password Policy:**
```
domain_password_information:
  pw_history_length: None
  min_pw_length: 5
  min_pw_age: none
  max_pw_age: 49710 days 6 hours 21 minutes
  pw_properties:
  - DOMAIN_PASSWORD_COMPLEX: false
domain_lockout_information:
  lockout_observation_window: 30 minutes
  lockout_duration: 30 minutes
  lockout_threshold: None
```

---

## SMB Enumeration Tools Summary

| Tool | Best For |
|------|----------|
| **smbclient** | Manual share browsing, file operations |
| **rpcclient** | RPC queries, user/group enumeration |
| **smbmap** | Quick permission check on shares |
| **crackmapexec** | Network-wide SMB enumeration, clear permissions |
| **enum4linux-ng** | Comprehensive automated enumeration |
| **samrdump.py** | User enumeration via SAM Remote Protocol |
| **nmap** | Initial port/version scan |

---

## Key Takeaways

⚠️ **Never rely on a single tool** — different tools may return different information due to how they're programmed.

✅ **Always verify manually** — automated tools can miss things or produce false negatives.

✅ **Use multiple tools** — cross-reference results for complete enumeration.

---

## Attack Vectors

| Vector | Description |
|--------|-------------|
| **Anonymous/Null Session** | List shares, enumerate users without credentials |
| **User Enumeration** | Harvest usernames for brute-force attacks |
| **RID Cycling** | Brute force RIDs to discover hidden users |
| **Share Browsing** | Access misconfigured shares with sensitive data |
| **Writable Shares** | Upload malicious files if write access allowed |

⚠️ **Key Insight:** Anonymous access + human error (weak passwords, forgotten test configs) = significant risk
