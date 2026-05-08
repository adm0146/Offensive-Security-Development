# 08 — Databases

## Overview

Metasploit uses **PostgreSQL** to store and organize scan results, credentials, loot, and host data across assessments. This keeps complex engagements organized and allows importing/exporting results with third-party tools.

---

## Database Setup

### Step-by-Step Initialization

```bash
# 1. Start PostgreSQL
sudo systemctl start postgresql

# 2. Check status
sudo service postgresql status

# 3. Initialize the MSF database
sudo msfdb init

# 4. Launch msfconsole with database connected
sudo msfdb run
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| `msfdb init` fails with `NoMethodError` | `apt update && apt upgrade` then `sudo msfdb init` again |
| "Database already configured" | Run `sudo msfdb status` to verify — likely already working |
| Cannot change MSF password | `msfdb reinit` → `cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/` → `sudo service postgresql restart` |

### Verify Connection

```bash
msf6 > db_status
# [*] Connected to msf. Connection type: postgresql.
```

---

## Database Commands Overview

| Command | Description |
|---------|-------------|
| `db_status` | Show current database connection status |
| `db_connect` | Connect to an existing database |
| `db_disconnect` | Disconnect from current database |
| `db_nmap` | Run Nmap and auto-store results |
| `db_import` | Import scan results (XML preferred) |
| `db_export` | Export database to file (XML or pwdump) |
| `db_rebuild_cache` | Rebuild module cache stored in DB |
| `workspace` | Manage workspaces |
| `hosts` | List all hosts in database |
| `services` | List all discovered services |
| `creds` | List all gathered credentials |
| `loot` | List hash dumps and extracted data |
| `vulns` | List all discovered vulnerabilities |
| `notes` | List all notes in database |

---

## Workspaces

Workspaces segregate data by engagement, target, subnet, or domain — like project folders.

```bash
# List workspaces (* = active)
msf6 > workspace

# Create a new workspace
msf6 > workspace -a Target_1

# Switch to a workspace
msf6 > workspace Target_1

# Delete a workspace
msf6 > workspace -d Target_1

# List verbose
msf6 > workspace -v

# Rename
msf6 > workspace -r OldName NewName

# Delete ALL workspaces
msf6 > workspace -D
```

---

## Importing & Exporting Scan Data

### Import (XML preferred)

```bash
# Import Nmap XML results
msf6 > db_import Target.xml
# [*] Importing 'Nmap XML' data
# [*] Successfully imported ~/Target.xml

# Verify imported data
msf6 > hosts
msf6 > services
```

### Run Nmap Directly from msfconsole

```bash
# db_nmap auto-stores results in the database
msf6 > db_nmap -sV -sS 10.10.10.8
```

### Export

```bash
# Export to XML
msf6 > db_export -f xml backup.xml

# Export formats: xml, pwdump
```

---

## Data Commands

### hosts

```bash
# List all hosts
msf6 > hosts

# Filter columns
msf6 > hosts -c address,os_name,os_flavor

# Only show hosts that are up
msf6 > hosts -u

# Search filter
msf6 > hosts -S "Windows"

# Set RHOSTS from search results
msf6 > hosts -R

# Export to CSV
msf6 > hosts -o hosts.csv

# Add a host manually
msf6 > hosts -a 10.10.10.50

# Add comment
msf6 > hosts -m "Domain Controller" 10.10.10.50
```

Key columns: `address`, `arch`, `os_name`, `os_flavor`, `os_sp`, `purpose`, `info`, `comments`, `vuln_count`, `service_count`, `cred_count`

### services

```bash
# List all services
msf6 > services

# Filter by port
msf6 > services -p 445

# Filter by service name
msf6 > services -s http,ssh

# Only show running services
msf6 > services -u

# Set RHOSTS from results
msf6 > services -R

# Filter by protocol
msf6 > services -r tcp

# Export to CSV
msf6 > services -o services.csv
```

### creds

```bash
# List all credentials
msf6 > creds

# Filter by user
msf6 > creds -u admin

# Filter by port
msf6 > creds -p 22-25,445

# Filter by service
msf6 > creds -s ssh,smb

# Filter by type
msf6 > creds -t NTLM

# Add credentials manually
msf6 > creds add user:admin password:notpassword realm:workgroup
msf6 > creds add user:admin ntlm:E2FC15074BF7751DD408E6B105741864:A1074A69B1BDE45403AB680504BBDD1A
msf6 > creds add user:sshadmin ssh-key:/path/to/id_rsa

# Export to JTR format
msf6 > creds -o creds.jtr

# Export to hashcat format
msf6 > creds -o creds.hcat

# Set RHOSTS from results
msf6 > creds -R
```

### loot

```bash
# List all loot (hashes, passwd, shadow, etc.)
msf6 > loot

# Add loot
msf6 > loot -a -f /path/to/file -i "Description" -t hash_dump 10.10.10.40

# Filter by type
msf6 > loot -t password,hash

# Delete loot for a host
msf6 > loot -d 10.10.10.40
```

---

## Typical Workflow

```bash
# 1. Start database and msfconsole
sudo msfdb run

# 2. Create workspace for engagement
msf6 > workspace -a ClientA_Internal

# 3. Scan targets (results auto-stored)
msf6 > db_nmap -sV -sC -O 10.10.10.0/24

# 4. Review discovered hosts and services
msf6 > hosts
msf6 > services

# 5. Use hosts -R to auto-set RHOSTS for modules
msf6 > services -p 445 -R
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > run

# 6. View gathered credentials and loot
msf6 > creds
msf6 > loot

# 7. Export before closing
msf6 > db_export -f xml engagement_backup.xml
```

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **PostgreSQL backend** | Must be running before msfconsole can use the DB |
| **`msfdb init` once, `msfdb run` always** | Init creates the DB; `run` launches msf with DB connected |
| **Workspaces = project folders** | Separate engagements to avoid data mixing |
| **`db_nmap` > external nmap** | Auto-stores results — no import step needed |
| **XML format preferred** | For both `db_import` and `db_export` |
| **`-R` flag on hosts/services/creds** | Instantly populates RHOSTS from query results |
| **`creds` auto-populates** | Successful exploits store captured credentials automatically |
| **Always export before closing** | `db_export -f xml backup.xml` — protect your work |
