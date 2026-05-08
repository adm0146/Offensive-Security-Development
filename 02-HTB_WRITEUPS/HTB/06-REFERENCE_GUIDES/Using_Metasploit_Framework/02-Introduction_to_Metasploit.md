# 02 — Introduction to Metasploit

## Overview

The **Metasploit Project** is a Ruby-based, modular penetration testing platform that enables you to write, test, and execute exploit code. At its core, it's a collection of commonly used tools providing a complete environment for penetration testing and exploit development.

---

## Metasploit Versions

| Version | Description |
|---------|-------------|
| **Metasploit Framework** | Open source, community driven, free |
| **Metasploit Pro** | Commercial use, paid subscription, enterprise oriented |

### Metasploit Pro Additional Features

| Infiltrate | Collect Data | Remediate |
|------------|--------------|-----------|
| Manual Exploitation | Import and Scan Data | Bruteforce |
| Anti-virus Evasion | Discovery Scans | Task Chains |
| IPS/IDS Evasion | Meta-Modules | Exploitation Workflow |
| Proxy Pivot | Nexpose Scan Integration | Session Rerun |
| Post-Exploitation | | Task Replay |
| Session Clean-up | | Project Sonar Integration |
| Credentials Reuse | | Session Management |
| Social Engineering | | Credential Management |
| Payload Generator | | Team Collaboration |
| Quick Pen-testing | | Web Interface |
| VPN Pivoting | | Backup and Restore |
| Vulnerability Validation | | Data Export |
| Phishing Wizard | | Evidence Collection |
| Web App Testing | | Reporting |
| Persistent Sessions | | Tagging Data |

---

## Msfconsole — The Primary Interface

`msfconsole` is the most popular and fully supported interface to the Metasploit Framework.

| Feature | Description |
|---------|-------------|
| **Only supported way** | To access most features within MSF |
| **Console-based** | Centralized "all-in-one" interface |
| **Most stable** | Contains the most features of any MSF interface |
| **Readline support** | Tab completion, command history, command completion |
| **External commands** | Execute system commands directly from within msfconsole |

> Think of sessions and jobs like browser tabs — seamlessly switch between target connections during post-exploitation.

---

## Architecture — What's Under the Hood

Base files location (ParrotOS / Kali):

```
/usr/share/metasploit-framework/
```

### Directory Structure

| Directory | Purpose |
|-----------|---------|
| **Data** | Functioning data files for the msfconsole interface |
| **Documentation** | Technical details about the project |
| **Lib** | Core library files powering the framework |
| **Modules** | Exploit modules split into categories (the tools you use) |
| **Plugins** | Extra functionality loaded manually or automatically |
| **Scripts** | Meterpreter functionality and other useful scripts |
| **Tools** | Command-line utilities callable from msfconsole |

### Modules Directory

```bash
ls /usr/share/metasploit-framework/modules

auxiliary  encoders  evasion  exploits  nops  payloads  post
```

| Module Type | Purpose |
|-------------|---------|
| **auxiliary** | Scanners, fuzzers, crawlers, and other non-exploit modules |
| **encoders** | Encode payloads to evade AV/IDS signatures |
| **evasion** | Modules specifically designed to evade defenses |
| **exploits** | Proof-of-concept exploit code for known vulnerabilities |
| **nops** | NOP sled generators for buffer overflow padding |
| **payloads** | Code that runs on the target after successful exploitation |
| **post** | Post-exploitation modules (enumeration, pivoting, persistence) |

### Plugins Directory

```bash
ls /usr/share/metasploit-framework/plugins/

aggregator.rb      ips_filter.rb  openvas.rb           sounds.rb
alias.rb           komand.rb      pcap_log.rb          sqlmap.rb
auto_add_route.rb  lab.rb         request.rb           thread.rb
beholder.rb        libnotify.rb   rssfeed.rb           token_adduser.rb
db_credcollect.rb  msfd.rb        sample.rb            token_hunter.rb
db_tracker.rb      msgrpc.rb      session_notifier.rb  wiki.rb
event_tester.rb    nessus.rb      session_tagger.rb    wmap.rb
ffautoregen.rb     nexpose.rb     socket_logger.rb
```

> Plugins add flexibility — load them as needed for extra automation during assessments.

### Scripts Directory

```bash
ls /usr/share/metasploit-framework/scripts/

meterpreter  ps  resource  shell
```

### Tools Directory

```bash
ls /usr/share/metasploit-framework/tools/

context  docs     hardware  modules   payloads
dev      exploit  memdump   password  recon
```

---

## What Metasploit Is (and Isn't)

| Concept | Reality |
|---------|---------|
| **Not a jack of all trades** | A swiss army knife with enough tools for the most common unpatched vulnerabilities |
| **Strong suit** | Plethora of available targets and versions, a few commands away from a foothold |
| **Exploit → Payload → Access** | Exploit matches the vulnerability, payload gives you the shell, sessions let you manage multiple connections |
| **Modular** | Switch between targets, exploits, and payloads seamlessly |

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Ruby-based** | The entire framework is built in Ruby |
| **Base path** | `/usr/share/metasploit-framework/` |
| **7 module types** | auxiliary, encoders, evasion, exploits, nops, payloads, post |
| **msfconsole** | The only fully supported interface — learn it well |
| **Pro vs Framework** | Pro adds GUI, task chains, social engineering, Nexpose integration — but Framework is free and sufficient for most work |
| **Know the file structure** | Understanding where modules, plugins, and scripts live makes importing custom modules easy (like we did with `50064.rb` in the Shells assessment) |
