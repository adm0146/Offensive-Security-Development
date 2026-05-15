# Windows Remote Management Protocols

> Protocols and services for remotely managing Windows servers — RDP, WinRM, and WMI are the primary components, enabled by default since Windows Server 2016.

---

## Overview

| Component | Description |
|-----------|-------------|
| **RDP** | Remote Desktop Protocol — GUI-based remote access |
| **WinRM** | Windows Remote Management — command-line remote management (WS-Management protocol) |
| **WMI** | Windows Management Instrumentation — system administration and monitoring |

---

## RDP (Remote Desktop Protocol)

### Overview

**RDP** is a Microsoft protocol for remote GUI access to Windows systems over encrypted IP networks.

| Characteristic | Details |
|----------------|---------|
| **Default Port** | TCP/UDP 3389 |
| **Encryption** | TLS/SSL (since Windows Vista) |
| **Layer** | Application layer (TCP/IP model) |
| **Authentication** | Network Level Authentication (NLA) by default |
| **Installation** | Built-in on Windows servers — no external software needed |

> ⚠️ **Certificate Warning:** RDP certificates are **self-signed by default** — clients cannot distinguish genuine from forged certificates.

---

### RDP Requirements

For an RDP session to work:

| Requirement | Details |
|-------------|---------|
| **Network firewall** | Must allow inbound connections |
| **Host firewall** | Must allow connections from outside |
| **NAT** | Requires public IP + port forwarding on the NAT router |
| **NLA** | Default setting — only allows connections with Network Level Authentication |

---

### Footprinting RDP

#### Nmap — RDP Enumeration Scripts

```bash
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
```
> Runs all RDP NSE scripts against port 3389 to enumerate encryption/NLA, hostname, and Windows build. Swap `10.129.201.248` for your target IP.

```
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|_    RDSTLS: SUCCESS
| rdp-ntlm-info:
|   Target_Name: ILF-SQL-01
|   NetBIOS_Domain_Name: ILF-SQL-01
|   NetBIOS_Computer_Name: ILF-SQL-01
|   DNS_Domain_Name: ILF-SQL-01
|   DNS_Computer_Name: ILF-SQL-01
|   Product_Version: 10.0.17763
|_  System_Time: 2021-11-06T13:46:00+00:00
```

Key findings from Nmap:
- **NLA status** (CredSSP)
- **Hostname** and **NetBIOS names**
- **Product version** (Windows build)
- **System time**

> ⚠️ **OPSEC Warning:** Nmap uses RDP cookies (`mstshash=nmap`) that can be detected by **EDR** and threat hunters. Use `--packet-trace` to verify what's being sent.

#### Nmap — Packet Trace (OPSEC Awareness)

```bash
nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n
```

Reveals the `mstshash=nmap` cookie in the traffic:

```
Cookie: mstshash=nmap
```

#### rdp-sec-check — Security Audit

Perl-based tool from Cisco CX Security Labs — unauthenticated RDP security assessment.

**Installation:**

```bash
sudo cpan
cpan[1]> install Encoding::BER
```

```bash
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl 10.129.201.248
```

```
[+] Checking supported protocols

[-] Checking if RDP Security (PROTOCOL_RDP) is supported...Not supported - HYBRID_REQUIRED_BY_SERVER
[-] Checking if TLS Security (PROTOCOL_SSL) is supported...Not supported - HYBRID_REQUIRED_BY_SERVER
[-] Checking if CredSSP Security (PROTOCOL_HYBRID) is supported [uses NLA]...Supported

[+] Summary of protocol support

[-] 10.129.201.248:3389 supports PROTOCOL_SSL    : FALSE
[-] 10.129.201.248:3389 supports PROTOCOL_HYBRID : TRUE
[-] 10.129.201.248:3389 supports PROTOCOL_RDP    : FALSE

[+] Summary of RDP encryption support

[-] 10.129.201.248:3389 supports ENCRYPTION_METHOD_NONE   : FALSE
[-] 10.129.201.248:3389 supports ENCRYPTION_METHOD_40BIT  : FALSE
[-] 10.129.201.248:3389 supports ENCRYPTION_METHOD_128BIT : FALSE
[-] 10.129.201.248:3389 supports ENCRYPTION_METHOD_56BIT  : FALSE
[-] 10.129.201.248:3389 supports ENCRYPTION_METHOD_FIPS   : FALSE
```

---

### Connecting via RDP

#### Linux RDP Clients

| Tool | Description |
|------|-------------|
| **xfreerdp** | Most common, feature-rich |
| **rdesktop** | Lightweight alternative |
| **Remmina** | GUI-based client |

#### xfreerdp — Connect to RDP

```bash
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
```

> 📝 **Note:** You will receive a certificate warning (self-signed). Type `Y` to trust and continue.

---

## WinRM (Windows Remote Management)

### Overview

**WinRM** is a Windows integrated remote management protocol based on the command line, using **SOAP** (Simple Object Access Protocol) for connections.

| Characteristic | Details |
|----------------|---------|
| **Ports** | TCP 5985 (HTTP), TCP 5986 (HTTPS) |
| **Legacy Ports** | TCP 80/443 (no longer used — blocked for security) |
| **Protocol** | WS-Management (SOAP-based) |
| **Enabled By Default** | Windows Server 2012+ ; must be manually enabled on Windows 10 and older |
| **Related Tool** | WinRS (Windows Remote Shell) — execute arbitrary commands remotely |

> 📝 **Note:** In practice, HTTP (TCP 5985) is used far more often than HTTPS (TCP 5986).

### WinRM Capabilities

| Feature | Description |
|---------|-------------|
| **Remote PowerShell sessions** | Full PowerShell access to remote host |
| **Event log merging** | Centralized log collection |
| **WinRS** | Execute arbitrary commands remotely (included since Windows 7) |

---

### Footprinting WinRM

#### Nmap — Scan WinRM Ports

```bash
nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```

```
PORT     STATE SERVICE VERSION
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

#### PowerShell — Test WinRM Connectivity (from Windows)

```powershell
Test-WsMan <hostname>
```

---

### Connecting via WinRM

#### evil-winrm (Linux)

```bash
evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
```

```
Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Cry0l1t3\Documents>
```

> 💡 **evil-winrm** is a penetration testing tool designed specifically for WinRM interaction — provides a full PowerShell shell on the remote host.

---

## WMI (Windows Management Instrumentation)

### Overview

**WMI** is Microsoft's implementation of the Common Information Model (CIM) — provides **read and write access to almost all settings** on Windows systems.

| Characteristic | Details |
|----------------|---------|
| **Initial Port** | TCP 135 (then moves to a random port) |
| **Access Methods** | PowerShell, VBScript, WMIC (WMI Console) |
| **Architecture** | Multiple programs + databases (repositories) |
| **Scope** | Most critical Windows administration interface |

> ⚠️ **Critical:** WMI allows read/write access to **almost all Windows settings** — extremely powerful for both admins and attackers.

---

### Footprinting WMI

#### Impacket — wmiexec.py

```bash
/usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"
```

```
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
ILF-SQL-01
```

> 📝 **Note:** WMI communication starts on TCP 135, then moves to a random port after connection is established.

---

## Quick Reference — Ports & Tools

| Service | Port(s) | Tool (Linux) | Tool (Windows) |
|---------|---------|-------------|----------------|
| **RDP** | TCP/UDP 3389 | `xfreerdp`, `rdesktop`, Remmina | Built-in Remote Desktop |
| **WinRM** | TCP 5985 (HTTP), 5986 (HTTPS) | `evil-winrm` | PowerShell (`Test-WsMan`) |
| **WMI** | TCP 135 + random | `wmiexec.py` (Impacket) | PowerShell, WMIC, VBScript |

---

## Key Takeaways

1. **RDP TCP 3389** — GUI remote access; scan with `--script rdp*` for NLA, hostname, and version info
2. **Self-signed certs** — RDP uses self-signed certificates by default; clients can't verify authenticity
3. **Nmap OPSEC** — `mstshash=nmap` cookie is detectable by EDR; use `--packet-trace` to verify
4. **rdp-sec-check** — Perl tool for unauthenticated RDP security auditing (encryption methods, NLA)
5. **WinRM TCP 5985/5986** — SOAP-based remote management; HTTP (5985) is far more common than HTTPS
6. **evil-winrm** — Go-to Linux tool for WinRM shells; gives full PowerShell access
7. **WMI TCP 135** — Read/write access to nearly all Windows settings; uses Impacket's `wmiexec.py`
8. **Default on Server 2012+** — WinRM enabled by default; must be manually enabled on older systems
9. **xfreerdp** — Primary Linux RDP client: `xfreerdp /u:user /p:pass /v:target`
10. **Always check all three** — RDP (3389), WinRM (5985/5986), WMI (135) on every Windows target

---

*HTB Academy - Footprinting Module*
