# Section 4 — Intro to MySQL

---

## Connecting to MySQL

```bash
# Interactive (password prompt — preferred, avoids bash history)
mysql -u root -p

# With remote host and port
mysql -u root -h TARGET_IP -P 3306 -p

# Inline password (avoid — logs to history)
mysql -u root -pPASSWORD -h TARGET_IP -P PORT

# Skip SSL (needed for some HTB targets)
mysql -u root -pPASSWORD -h TARGET_IP -P PORT --skip-ssl
```
> Connects to a MySQL server. `-u` sets the username, `-p` prompts for the password (no space before value when inlining it), `-h` sets the remote host, `-P` sets the port (uppercase). Use `--skip-ssl` on HTB lab targets that don't support SSL.

> Default MySQL port: **3306** (uppercase `-P` for port, lowercase `-p` for password)

---

## Essential MySQL Commands

```sql
SHOW DATABASES;               -- list all databases
USE dbname;                   -- switch to a database
SHOW TABLES;                  -- list tables in current database
DESCRIBE tablename;           -- show columns and data types
SHOW GRANTS;                  -- show current user's privileges
```
> Run these right after connecting to map out a MySQL server. `SHOW GRANTS` tells you whether the current user has the `FILE` privilege. If yes, you can read and write files on the server.

---

## Creating Databases and Tables

```sql
-- Create a database
CREATE DATABASE users;

-- Create a table with full constraints
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
);
```
> Example table creation showing common column constraints. Understanding this structure helps you write correct `SELECT` and `INSERT` payloads during injection. `AUTO_INCREMENT` means the `id` column is an integer that grows automatically — useful for targeting rows by ID.

**Column constraints:**
| Constraint | Purpose |
|-----------|---------|
| `NOT NULL` | Field cannot be empty |
| `UNIQUE` | No duplicate values in this column |
| `AUTO_INCREMENT` | Automatically increments integer by 1 on each insert |
| `DEFAULT NOW()` | Sets default value to current timestamp |
| `PRIMARY KEY` | Uniquely identifies each row — used for table relationships |

---

## Common Data Types

| Type | Use |
|------|-----|
| `INT` | Integer numbers |
| `VARCHAR(n)` | String up to n characters |
| `DATETIME` | Date and time |
| `TEXT` | Long strings |
| `BLOB` | Binary data |

---

## Lab — Connect and Enumerate

**Objective:** Connect to a remote MySQL instance and list databases.

```bash
mysql -u root -ppassword -h TARGET_IP -P TARGET_PORT --skip-ssl -e "SHOW DATABASES;"
```
> Non-interactive MySQL query. `-e` runs the SQL statement and exits immediately without opening an interactive shell. Replace `password`, `TARGET_IP`, and `TARGET_PORT` with your target's values.

**Why `-e`:** Runs a single query non-interactively and exits — no need to enter the MySQL shell.
**Why `--skip-ssl`:** HTB targets often don't support SSL — skip it to avoid connection errors.

**Output:**
```
Database
employees
information_schema
mysql
performance_schema
sys
```

**Q1 Answer:** `employees`

---

## Exam Notes

- SQL statements are **case-insensitive** but database/table names are **case-sensitive**
- Always terminate MySQL statements with `;`
- `information_schema` is a built-in MySQL database — stores metadata about all databases, tables, and columns — **critical for SQLi enumeration later**
- Add `--skip-ssl` when connecting to HTB/lab MySQL targets to avoid SSL errors
