# MySQL

> Open-source SQL relational database management system developed and supported by Oracle.

---

## Overview

**MySQL** is an open-source SQL relational database management system. A database is a structured collection of data organized for easy use and retrieval.

- Quickly processes large amounts of data with high performance
- Data storage optimized for minimal space usage
- Controlled using SQL database language
- Works on **client-server principle**
- Databases stored in files with `.sql` extension (e.g., `wordpress.sql`)

📚 **SQL Reference:** [W3Schools SQL Introduction](https://www.w3schools.com/sql/sql_intro.asp)

---

## Default Port

| Port | Protocol | Description |
|------|----------|-------------|
| **TCP 3306** | MySQL | Default MySQL server port |

---

## MySQL Architecture

### MySQL Server
- The actual database management system
- Handles data storage and distribution
- Data stored in **tables** with columns, rows, and data types

### MySQL Clients
- Retrieve and edit data using structured queries
- Operations: Insert, delete, modify, retrieve data
- Access via internal network or public Internet

---

## Common Use Cases

### LAMP/LEMP Stack

| Stack | Components |
|-------|------------|
| **LAMP** | Linux, Apache, MySQL, PHP |
| **LEMP** | Linux, Nginx, MySQL, PHP |

### Data Stored in MySQL

| Category | Examples |
|----------|----------|
| **Content** | Headers, Texts, Meta tags, Forms |
| **Users** | Customers, Usernames, Administrators, Moderators |
| **Sensitive** | Email addresses, Permissions, Passwords |
| **Links** | External/Internal links, Links to Files |

> ⚠️ **Security Note:** Passwords can be stored in plaintext but are generally encrypted by PHP scripts using One-Way-Encryption.

---

## MariaDB

**MariaDB** is a fork of the original MySQL code, developed by MySQL's chief developer after MySQL AB was acquired by Oracle. Often used interchangeably with MySQL.

---

## Default Configuration

### Install MySQL Server

```bash
sudo apt install mysql-server -y
```
> Installs MySQL server for lab setup purposes.

### View Configuration

```bash
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'
```
> Reads the MySQL config with comments and blank lines stripped. Look for `bind-address` (should be `127.0.0.1`, not `0.0.0.0`), `password` entries in plaintext, and `secure_file_priv` settings.

```
[client]
port        = 3306
socket      = /var/run/mysqld/mysqld.sock

[mysqld_safe]
pid-file    = /var/run/mysqld/mysqld.pid
socket      = /var/run/mysqld/mysqld.sock
nice        = 0

[mysqld]
skip-host-cache
skip-name-resolve
user        = mysql
pid-file    = /var/run/mysqld/mysqld.pid
socket      = /var/run/mysqld/mysqld.sock
port        = 3306
basedir     = /usr
datadir     = /var/lib/mysql
tmpdir      = /tmp
lc-messages-dir = /usr/share/mysql
explicit_defaults_for_timestamp

symbolic-links=0

!includedir /etc/mysql/conf.d/
```

---

## Dangerous Settings

| Setting | Description |
|---------|-------------|
| `user` | Sets which user the MySQL service runs as |
| `password` | Sets password for MySQL user (**stored in plaintext**) |
| `admin_address` | IP address for TCP/IP connections on admin interface |
| `debug` | Current debugging settings (reveals sensitive info) |
| `sql_warnings` | Controls information strings for INSERT warnings |
| `secure_file_priv` | Limits data import/export operations |

> ⚠️ **Security Risk:** `user`, `password`, and `admin_address` entries are in **plaintext**. If config file permissions are incorrect, credentials can be exposed.

---

## Footprinting the Service

### Nmap MySQL Scan

```bash
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```
> Runs all MySQL NSE scripts against port 3306. `mysql-empty-password` checks for passwordless root. `mysql-enum` enumerates valid usernames. `mysql-info` shows version and authentication plugin. Replace `10.129.14.128` with your target IP.

```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-21 00:53 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00021s latency).

PORT     STATE SERVICE     VERSION
3306/tcp open  nagios-nsca Nagios NSCA
| mysql-brute: 
|   Accounts: 
|     root:<empty> - Valid credentials
|_  Statistics: Performed 45010 guesses in 5 seconds, average tps: 9002.0
| mysql-empty-password: 
|_  root account has empty password
| mysql-enum: 
|   Valid usernames: 
|     root:<empty> - Valid credentials
|     netadmin:<empty> - Valid credentials
|     guest:<empty> - Valid credentials
|     user:<empty> - Valid credentials
|     web:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|     administrator:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     admin:<empty> - Valid credentials
|     test:<empty> - Valid credentials
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.26-0ubuntu0.20.04.1
|   Thread ID: 13
|   Capabilities flags: 65535
|   Status: Autocommit
|_  Auth Plugin Name: caching_sha2_password
MAC Address: 00:00:00:00:00:00 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 11.21 seconds
```

> ⚠️ **Warning:** Always manually verify results - Nmap can produce false positives!

---

## Connecting to MySQL

### Test Connection (No Password)

```bash
mysql -u root -h 10.129.14.132
```
> Tests a passwordless `root` connection to the remote MySQL server — many default installs allow it. Swap `10.129.14.132` for your target IP and `root` for the username to test.

```
ERROR 1045 (28000): Access denied for user 'root'@'10.129.14.1' (using password: NO)
```

### Connect with Password

```bash
mysql -u root -pP4SSw0rd -h 10.129.14.128
```
> Connects to the remote MySQL server with a known password (note: no space after `-p`). Swap `P4SSw0rd` for the password, `root` for the user, and `10.129.14.128` for your target IP.

> ⚠️ **Note:** No space between `-p` flag and password!

```
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 150165
Server version: 8.0.27-0ubuntu0.20.04.1 (Ubuntu)

MySQL [(none)]>
```

---

## MySQL Commands Reference

| Command | Description |
|---------|-------------|
| `mysql -u <user> -p<password> -h <IP>` | Connect to MySQL server (no space between -p and password) |
| `show databases;` | Show all databases |
| `use <database>;` | Select a database |
| `show tables;` | Show all tables in selected database |
| `show columns from <table>;` | Show all columns in a table |
| `select * from <table>;` | Show everything in a table |
| `select * from <table> where <column> = "<string>";` | Search for specific string |
| `select version();` | Show MySQL version |

---

## Database Enumeration Examples

### List Databases

```sql
show databases;
```
> Run inside the MySQL prompt to list every database on the server — your first move after connecting. No arguments to change.

```
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
```

### Select Database and List Tables

```sql
use mysql;
show tables;
```
> Selects the `mysql` system database then lists its tables (contains the `user` table with account hashes). Swap `mysql` for any database name from `show databases;`.

```
+------------------------------------------------------+
| Tables_in_mysql                                      |
+------------------------------------------------------+
| columns_priv                                         |
| db                                                   |
| user                                                 |
...SNIP...
+------------------------------------------------------+
```

### Query System Schema

```sql
use sys;
select host, unique_users from host_summary;
```
> Queries the `sys` schema's `host_summary` view to see which client hosts and how many distinct users have connected — useful for spotting other in-scope hosts. No values need changing.

```
+-------------+--------------+
| host        | unique_users |
+-------------+--------------+
| 10.129.14.1 |            1 |
| localhost   |            2 |
+-------------+--------------+
```

---

## Important Databases

| Database | Description |
|----------|-------------|
| **sys** | System schema - tables, info, metadata for management |
| **information_schema** | Metadata (ANSI/ISO standard) - retrieved from system schema |
| **mysql** | MySQL system database with user accounts and privileges |
| **performance_schema** | Performance monitoring data |

---

## Quick Reference

| Task | Command |
|------|---------|
| Nmap MySQL scan | `sudo nmap <IP> -sV -sC -p3306 --script mysql*` |
| Connect to MySQL | `mysql -u <user> -p<pass> -h <IP>` |
| Show databases | `show databases;` |
| Select database | `use <database>;` |
| Show tables | `show tables;` |
| Show MySQL version | `select version();` |

---

## Practical Enumeration Lab

### Lab Setup

| Component | Details |
|-----------|---------|
| **Attacker** | Kali Linux (10.37.129.3, host-only network) |
| **Target** | Ubuntu Server 24.04 (10.37.129.4, host-only network) |

> 🔒 **Network Isolation:** Both VMs configured as host-only to isolate the lab from external networks.

### Configuring a Vulnerable Target

```bash
# Install MySQL
sudo apt install mysql-server -y

# Jump into MySQL as root
sudo mysql

# Create misconfigured root account accessible from anywhere with no password
CREATE USER 'root'@'%' IDENTIFIED BY '';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%';
FLUSH PRIVILEGES;
exit;

# Edit config to listen on all interfaces
sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
# Change: bind-address = 127.0.0.1
# To:     bind-address = 0.0.0.0

sudo systemctl restart mysql
```
> Lab-only: installs MySQL, creates an insecure passwordless `root'@'%'` account, rebinds the server to all interfaces, and restarts it to build a vulnerable practice target. Run on a throwaway lab VM, never a real host.

### Enumeration from Kali

```bash
# Nmap fingerprint and script scan
sudo nmap 10.37.129.4 -Pn -sV -sC -p3306 --script mysql*

# If blocked due to too many connection errors
sudo mysqladmin flush-hosts  # run on target

# Connect - MySQL 8 requires --skip-ssl due to TLS enforcement
mysql -u root -h 10.37.129.4 --skip-ssl
```
> Nmap-scans the target's MySQL port, unblocks the host if the brute script tripped connection limits (`flush-hosts` runs on the target), then connects as `root` with `--skip-ssl` to bypass MySQL 8 TLS enforcement. Swap `10.37.129.4` for your target IP.

### Key MySQL Commands Used

```sql
show databases;
use mysql;
show tables;
select host, user, authentication_string from user;
select * from information_schema.tables limit 10;
```
> Core post-connection recon: lists databases, switches to `mysql`, dumps the `user` table (usernames + password hashes for offline cracking), and samples the global table list. Run as-is once connected.

### Key Findings

| Finding | Details |
|---------|---------|
| **MySQL Version** | 8.0.45 fingerprinted by Nmap |
| **mysql-enum** | Found 10 valid usernames with empty passwords: root, netadmin, guest, user, web, sysadmin, administrator, webadmin, admin, test |
| **mysql-brute** | Returned "No valid accounts found" — **false positive** |
| **root@%** | Empty password confirmed — accessible from any host with no authentication |
| **debian-sys-maint** | Exposed caching_sha2_password hash — crackable offline with hashcat |
| **Access Level** | Full access to all databases, tables, and user credentials with zero authentication |

### Gotchas Learned

| Issue | Solution |
|-------|----------|
| **Host blocked by mysql-brute** | Nmap hammers the server — run `sudo mysqladmin flush-hosts` on target to unblock |
| **MySQL 8 TLS enforcement** | Use `--skip-ssl` to bypass in lab context |
| **IP persistence after network change** | Always reboot Parallels VMs after changing network adapters |

### Why This Is Dangerous

> ⚠️ **An exposed MySQL port with default or empty credentials gives an attacker full read/write access to every database on the server.**

Combined with SNMP enumeration, an attacker can:
- ✅ Map the network
- ✅ Identify the database service and version
- ✅ Connect without authentication
- ✅ Dump all user credentials
- ✅ Reuse passwords against SSH, VPN, or other services

---
