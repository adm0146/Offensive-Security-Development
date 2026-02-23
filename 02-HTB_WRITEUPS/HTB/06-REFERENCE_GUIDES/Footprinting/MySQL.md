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

### View Configuration

```bash
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'
```

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

```
ERROR 1045 (28000): Access denied for user 'root'@'10.129.14.1' (using password: NO)
```

### Connect with Password

```bash
mysql -u root -pP4SSw0rd -h 10.129.14.128
```

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
