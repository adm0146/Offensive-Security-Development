# SMTP (Simple Mail Transfer Protocol)

> Protocol for sending emails in an IP network between email clients and mail servers or between SMTP servers.

---

## Overview

The **Simple Mail Transfer Protocol (SMTP)** is used for sending emails in an IP network. It can be used:
- Between an email client and an outgoing mail server
- Between two SMTP servers (server acts as client)

SMTP is often combined with **IMAP** or **POP3** protocols for fetching and sending emails.

---

## Default Ports

| Port | Purpose |
|------|---------|
| **TCP 25** | Default SMTP port for connection requests |
| **TCP 587** | Receives mail from authenticated users/servers (uses STARTTLS) |
| **TCP 465** | Encrypted SMTP connection (SSL/TLS) |

---

## Authentication & Connection Flow

1. Connection request initiated
2. Client authenticates with **username and password**
3. Authentication data protected via STARTTLS (plaintext → encrypted)
4. Client sends sender/recipient addresses, email content, and parameters
5. Email transmitted
6. Connection terminated
7. Email server forwards to another SMTP server

---

## Security Considerations

| Risk | Detail |
|------|--------|
| **Plaintext Transmission** | SMTP works unencrypted by default - commands, data, and authentication visible in plain text |
| **SSL/TLS Encryption** | Used to prevent unauthorized reading of data |
| **Spam Prevention** | Authentication mechanisms (ESMTP with SMTP-Auth) allow only authorized users to send emails |
| **Open Relay Attack** | Misconfigured SMTP servers can be exploited as open relays |

---

## SMTP Components & Mail Flow

| Component | Full Name | Function |
|-----------|-----------|----------|
| **MUA** | Mail User Agent | Email client - converts email into header and body, uploads to SMTP server |
| **MSA** | Mail Submission Agent | Checks validity and origin of email (also called **Relay server**) |
| **MTA** | Mail Transfer Agent | Software basis for sending/receiving emails - checks size, spam, stores email, searches DNS for recipient |
| **MDA** | Mail Delivery Agent | Transfers email to recipient's mailbox |

### Mail Flow Diagram

```
Client (MUA) ➞ Submission Agent (MSA) ➞ Open Relay (MTA) ➞ Mail Delivery Agent (MDA) ➞ Mailbox (POP3/IMAP)
```

---

## Key Concepts

- **ESMTP (Extended SMTP)** - Protocol extension supporting SMTP-Auth for authentication
- **STARTTLS** - Command to switch existing plaintext connection to encrypted connection
- **Open Relay** - Misconfigured SMTP server that can be exploited (discussed in later sections)

---

## SMTP Disadvantages

| Issue | Description |
|-------|-------------|
| **No Delivery Confirmation** | Sending an email does not return a usable delivery confirmation. Only English-language error messaging with undelivered message header is returned |
| **No User Authentication** | Users are not authenticated when connection is established - sender is unreliable |
| **Open Relay Abuse** | Open SMTP relays misused to send spam en masse using fake sender addresses (**mail spoofing**) |

---

## Security Techniques

Modern security techniques to prevent SMTP misuse:

| Technique | Description |
|-----------|-------------|
| **DKIM** | DomainKeys Identified Mail - identification protocol |
| **SPF** | Sender Policy Framework - validates sender authorization |
| **ESMTP + TLS** | Extended SMTP uses TLS after EHLO command via STARTTLS |
| **AUTH PLAIN** | Safe authentication extension used over SSL-protected connection |

---

## Default Configuration

SMTP servers are only responsible for sending and forwarding emails.

### View Postfix Configuration

```bash
cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"
```

### Example Configuration Output

```
smtpd_banner = ESMTP Server 
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
myhostname = mail1.inlanefreight.htb
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
smtp_generic_maps = hash:/etc/postfix/generic
mydestination = $myhostname, localhost 
masquerade_domains = $myhostname
mynetworks = 127.0.0.0/8 10.129.0.0/16
mailbox_size_limit = 0
recipient_delimiter = +
smtp_bind_address = 0.0.0.0
inet_protocols = ipv4
smtpd_helo_restrictions = reject_invalid_hostname
home_mailbox = /home/postfix
```

---

## SMTP Commands

| Command | Description |
|---------|-------------|
| **AUTH PLAIN** | Service extension used to authenticate the client |
| **HELO** | Client logs in with computer name, starts the session |
| **EHLO** | Extended HELO - initiates ESMTP session |
| **MAIL FROM** | Client names the email sender |
| **RCPT TO** | Client names the email recipient |
| **DATA** | Client initiates the transmission of the email |
| **RSET** | Client aborts initiated transmission but keeps connection |
| **VRFY** | Client checks if a mailbox is available for message transfer |
| **EXPN** | Client checks if a mailbox is available for messaging |
| **NOOP** | Client requests response to prevent timeout disconnection |
| **QUIT** | Client terminates the session |

---

## Telnet Interaction

### Initialize SMTP Session

```bash
telnet 10.129.14.128 25
```

```
Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server 

HELO mail1.inlanefreight.htb

250 mail1.inlanefreight.htb

EHLO mail1

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
```

---

## User Enumeration with VRFY

The **VRFY** command can enumerate existing users on the system.

⚠️ **Warning:** This does not always work reliably. SMTP server may issue code **252** and confirm existence of users that don't exist.

```bash
telnet 10.129.14.128 25
```

```
Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server 

VRFY root

252 2.0.0 root

VRFY cry0l1t3

252 2.0.0 cry0l1t3

VRFY testuser

252 2.0.0 testuser

VRFY aaaaaaaaaaaaaaaaaaaaaaaaaaaa

252 2.0.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

> ⚠️ **Never entirely rely on results of automatic tools.** They execute pre-configured commands but don't account for how the administrator configured the server.

---

## Web Proxy Connection

To connect through a web proxy to SMTP server:

```
CONNECT 10.129.14.128:25 HTTP/1.0
```

---

## Sending an Email via Telnet

```bash
telnet 10.129.14.128 25
```

```
Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server

EHLO inlanefreight.htb

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING

MAIL FROM: <cry0l1t3@inlanefreight.htb>

250 2.1.0 Ok

RCPT TO: <mrb3n@inlanefreight.htb> NOTIFY=success,failure

250 2.1.5 Ok

DATA

354 End data with <CR><LF>.<CR><LF>

From: <cry0l1t3@inlanefreight.htb>
To: <mrb3n@inlanefreight.htb>
Subject: DB
Date: Tue, 28 Sept 2021 16:32:51 +0200
Hey man, I am trying to access our XY-DB but the creds don't work. 
Did you make any changes there?
.

250 2.0.0 Ok: queued as 6E1CF1681AB

QUIT

221 2.0.0 Bye
Connection closed by foreign host.
```

---

## Email Header Information

The **mail header** carries important information:

| Information | Description |
|-------------|-------------|
| Sender | Who sent the email |
| Recipient | Who receives the email |
| Time | When email was sent and arrived |
| Stations | Servers the email passed through |
| Content/Format | Message content and format type |

**Mandatory Fields:** Sender information, creation timestamp

**Optional Fields:** Various additional metadata

> 📚 Email header structure defined by **RFC5322**

⚠️ **Note:** Email header does not contain information necessary for technical delivery - that is transmitted as part of the transmission protocol.

---

## Dangerous Settings

### Open Relay Misconfiguration

To prevent emails from being filtered by spam filters, senders can use a **relay server** that the recipient trusts - an SMTP server known and verified by all others.

**Common Problem:** Administrators often don't have overview of which IP ranges to allow, resulting in misconfiguration where they allow **all IP addresses** to avoid email traffic errors.

### Open Relay Configuration

```
mynetworks = 0.0.0.0/0
```

⚠️ **Attack Possibilities with Open Relay:**
- Send fake/spoofed emails
- Initialize communication between multiple parties
- Spoof emails and read them

---

## Footprinting the Service

### Nmap SMTP Enumeration

Default Nmap scripts include **smtp-commands** which uses EHLO to list all possible commands on target SMTP server.

```bash
sudo nmap 10.129.14.128 -sC -sV -p25
```

```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-27 17:56 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00025s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail1.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.09 seconds
```

### Nmap Open Relay Detection

Use **smtp-open-relay** NSE script to identify open relay servers using 16 different tests.

```bash
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```

```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-30 02:29 CEST
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 02:29
Completed NSE at 02:29, 0.00s elapsed
Initiating ARP Ping Scan at 02:29
Scanning 10.129.14.128 [1 port]
Completed ARP Ping Scan at 02:29, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:29
Completed Parallel DNS resolution of 1 host. at 02:29, 0.03s elapsed
Initiating SYN Stealth Scan at 02:29
Scanning 10.129.14.128 [1 port]
Discovered open port 25/tcp on 10.129.14.128
Completed SYN Stealth Scan at 02:29, 0.06s elapsed (1 total ports)
NSE: Script scanning 10.129.14.128.
Initiating NSE at 02:29
Completed NSE at 02:29, 0.07s elapsed
Nmap scan report for 10.129.14.128
Host is up (0.00020s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-open-relay: Server is an open relay (16/16 tests)
|  MAIL FROM:<> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@nmap.scanme.org> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@ESMTP> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest%nmap.scanme.org@[10.129.14.128]>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest%nmap.scanme.org@ESMTP>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<"relaytest@nmap.scanme.org">
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<"relaytest%nmap.scanme.org">
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest@nmap.scanme.org@[10.129.14.128]>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<"relaytest@nmap.scanme.org"@[10.129.14.128]>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest@nmap.scanme.org@ESMTP>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<@[10.129.14.128]:relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<@ESMTP:relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<nmap.scanme.org!relaytest>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<nmap.scanme.org!relaytest@[10.129.14.128]>
|_ MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<nmap.scanme.org!relaytest@ESMTP>
MAC Address: 00:00:00:00:00:00 (VMware)

NSE: Script Post-scanning.
Initiating NSE at 02:29
Completed NSE at 02:29, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.48 seconds
           Raw packets sent: 2 (72B) | Rcvd: 2 (72B)
```

---

## Quick Reference

| Task | Command |
|------|---------|
| SMTP enumeration | `sudo nmap <IP> -sC -sV -p25` |
| Open relay check | `sudo nmap <IP> -p25 --script smtp-open-relay -v` |
| Telnet connection | `telnet <IP> 25` |
| User enumeration | `VRFY <username>` (in telnet session) |

---

