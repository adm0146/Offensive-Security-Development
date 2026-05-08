# 09 — Plugins

## Overview

Plugins extend msfconsole with third-party tool integrations, adding new commands and automating workflows. They interact directly with the Metasploit API, and results are automatically stored in the connected database.

---

## Plugin Directory

```
/usr/share/metasploit-framework/plugins/
```

### List Installed Plugins

```bash
ls /usr/share/metasploit-framework/plugins
```

---

## Using Plugins

### Load a Plugin

```bash
msf6 > load nessus
# [*] Successfully loaded Plugin: Nessus

msf6 > load pentest
# [*] Successfully loaded plugin: pentest
```

### View Plugin Commands

```bash
# Plugin-specific help
msf6 > nessus_help

# General help (shows all loaded plugin commands)
msf6 > help
```

### Failed Load (plugin not found)

```bash
msf6 > load Plugin_That_Does_Not_Exist
# [-] Failed to load plugin from /usr/share/metasploit-framework/plugins/Plugin_That_Does_Not_Exist.rb
```

---

## Installing New Plugins

### From GitHub (example: DarkOperator's Plugins)

```bash
# 1. Clone the repository
git clone https://github.com/darkoperator/Metasploit-Plugins

# 2. Copy desired plugin to MSF directory
sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb

# 3. Launch msfconsole and load
msfconsole -q
msf6 > load pentest
```

> Plugins are `.rb` (Ruby) files. Just drop them in the plugins directory with proper permissions.

---

## Popular Pre-Installed Plugins

| Plugin | Description |
|--------|-------------|
| **nMap** | Nmap integration (via `db_nmap`) |
| **Nessus** | Nessus vulnerability scanner bridge |
| **NexPose** | Rapid7 NexPose integration |
| **Mimikatz** | Credential extraction (v1, pre-installed) |
| **Stdapi** | Standard API extensions for Meterpreter |
| **Incognito** | Token impersonation and manipulation |
| **Priv** | Privilege escalation commands |
| **Railgun** | Direct Windows API calls from Meterpreter |

## Notable Third-Party Plugins

| Plugin | Source | Description |
|--------|--------|-------------|
| **pentest.rb** | DarkOperator | Adds discovery, auto-exploit, multi-session post commands |
| **wmap.rb** | Pre-installed | Web application scanner |
| **sqlmap.rb** | Pre-installed | SQLMap integration |
| **token_hunter.rb** | Pre-installed | Token hunting across sessions |
| **db_credcollect.rb** | Pre-installed | Auto-collect credentials to database |
| **auto_add_route.rb** | Pre-installed | Auto-add routes for pivoting |

---

## Pentest Plugin Commands (DarkOperator)

| Category | Command | Description |
|----------|---------|-------------|
| **Tradecraft** | `check_footprint` | Check post module footprint on target |
| **Auto-Exploit** | `vuln_exploit` | Run exploits from vuln scanner data |
| **Auto-Exploit** | `show_client_side` | Show matched client-side exploits |
| **Discovery** | `discover_db` | Run discovery modules against DB hosts |
| **Discovery** | `network_discover` | Port scan + enumerate non-pivot networks |
| **Discovery** | `pivot_network_discover` | Enumerate networks via Meterpreter pivot |
| **Discovery** | `show_session_networks` | List pivotable networks from sessions |
| **Postauto** | `multi_cmd` | Run shell command across multiple sessions |
| **Postauto** | `multi_post` | Run post module across sessions |
| **Postauto** | `sys_creds` | System password collection across sessions |
| **Postauto** | `app_creds` | Application password collection across sessions |
| **Postauto** | `get_lhost` | List local IPs usable for LHOST |
| **Project** | `project` | Manage engagement projects |

---

## Mixins (Conceptual Note)

| Detail | Description |
|--------|-------------|
| **What** | Ruby classes that provide methods to other classes via `include` (not inheritance) |
| **Why** | Adds optional features to many classes without requiring parent-child relationships |
| **Relevance** | MSF is written in Ruby — mixins power module flexibility and code reuse |
| **For beginners** | Not needed for day-to-day use — important for custom module development |

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Plugin directory** | `/usr/share/metasploit-framework/plugins/` |
| **Install = copy .rb file** | Drop the Ruby file in the plugins directory |
| **`load <name>` to activate** | Plugins aren't active until loaded in msfconsole |
| **Plugins extend `help` menu** | New commands appear in the general help after loading |
| **Results go to database** | Plugin actions auto-document to the connected PostgreSQL DB |
| **Pentest plugin is powerful** | Multi-session commands, auto-exploit, network discovery |
| **Pre-installed ≠ pre-loaded** | Plugins exist on disk but must be explicitly loaded each session |
