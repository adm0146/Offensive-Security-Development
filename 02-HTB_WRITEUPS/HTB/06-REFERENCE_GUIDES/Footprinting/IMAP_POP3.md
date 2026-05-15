# IMAP / POP3

> Protocols for accessing and managing emails on a remote mail server.

---

## Overview

### IMAP (Internet Message Access Protocol)

**IMAP** allows access to emails from a mail server with **online management** capabilities directly on the server. It supports folder structures and provides a network file system for emails, enabling synchronization across multiple independent clients.

### POP3 (Post Office Protocol 3)

**POP3** provides more limited functionality - only listing, retrieving, and deleting emails at the server level.

---

## IMAP vs POP3 Comparison

| Feature | IMAP | POP3 |
|---------|------|------|
| Email management on server | ✅ Yes | ❌ No |
| Folder structures | ✅ Yes | ❌ No |
| Multiple mailbox access per session | ✅ Yes | ❌ No |
| Email preselection | ✅ Yes | ❌ No |
| Emails remain on server | ✅ Until deleted | ❌ Downloaded locally |
| Multi-client synchronization | ✅ Yes | ❌ No |
| Simultaneous user access | ✅ Yes | ❌ No |
| Offline mode | ⚠️ Limited (local copy) | ✅ Full offline access |

---

## Default Ports

| Protocol | Port | Description |
|----------|------|-------------|
| **IMAP** | 143 | Unencrypted IMAP |
| **IMAP/S** | 993 | IMAP over SSL/TLS |
| **POP3** | 110 | Unencrypted POP3 |
| **POP3/S** | 995 | POP3 over SSL/TLS |

---

## IMAP Key Features

- **Text-based protocol** using ASCII format commands
- **Browse emails directly on server** without downloading
- **Multiple users** can access email server simultaneously
- **Personal folders and folder structures** in mailbox
- **Sent email synchronization** - copy sent emails to IMAP folder for access from any client
- **Commands sent in succession** without waiting for server confirmation
- **Identifiers** sent with commands allow matching server responses

---

## IMAP Connection Flow

1. Client establishes connection to server via **port 143**
2. User authenticates with **username and password**
3. Access to mailbox granted after successful authentication
4. Commands sent using text-based ASCII format
5. **SMTP** used separately for sending emails

---

## Security Considerations

| Risk | Detail |
|------|--------|
| **Plaintext Transmission** | IMAP works unencrypted by default - commands, emails, usernames, and passwords transmitted in plaintext |
| **SSL/TLS Encryption** | Required to ensure security and prevent unauthorized mailbox access |
| **Encrypted Ports** | Standard port 143 with STARTTLS or alternate port 993 for SSL/TLS |

---

## IMAP Advantages

- Uniform database across multiple clients
- Personal folder structures for organization
- Access sent emails from any device
- Server-side email management

## IMAP Disadvantages

- Requires active connection to server for email management
- Increased storage space requirement on email server
- Without encryption, credentials exposed in plaintext

---

## Default Configuration

Both IMAP and POP3 have many configuration options. For hands-on experimentation:

```bash
# Install Dovecot IMAP and POP3 packages
sudo apt install dovecot-imapd dovecot-pop3d
```
> Installs Dovecot for lab testing. Run this on a test server to set up a local IMAP/POP3 service to practice against.

📚 **Dovecot Documentation:**
- [Core Settings](https://doc.dovecot.org/2.4.1/core/summaries/settings.html)
- [Service Configuration](https://doc.dovecot.org/2.4.1/core/config/service.html)

---

## IMAP Commands

| Command | Description |
|---------|-------------|
| `1 LOGIN username password` | User's login |
| `1 LIST "" *` | Lists all directories |
| `1 CREATE "INBOX"` | Creates a mailbox with specified name |
| `1 DELETE "INBOX"` | Deletes a mailbox |
| `1 RENAME "ToRead" "Important"` | Renames a mailbox |
| `1 LSUB "" *` | Returns subset of names user has declared as active/subscribed |
| `1 SELECT INBOX` | Selects a mailbox so messages can be accessed |
| `1 UNSELECT INBOX` | Exits the selected mailbox |
| `1 FETCH <ID> all` | Retrieves data associated with a message in the mailbox |
| `1 CLOSE` | Removes all messages with the Deleted flag set |
| `1 LOGOUT` | Closes the connection with the IMAP server |

---

## POP3 Commands

| Command | Description |
|---------|-------------|
| `USER username` | Identifies the user |
| `PASS password` | Authentication of the user using its password |
| `STAT` | Requests the number of saved emails from the server |
| `LIST` | Requests from the server the number and size of all emails |
| `RETR id` | Requests the server to deliver the requested email by ID |
| `DELE id` | Requests the server to delete the requested email by ID |
| `CAPA` | Requests the server to display the server capabilities |
| `RSET` | Requests the server to reset the transmitted information |
| `QUIT` | Closes the connection with the POP3 server |

---

## Dangerous Settings

Improperly configured options can allow attackers to obtain sensitive information, including reading all sent/received emails containing confidential data.

> ⚠️ Many companies use third-party email providers (Google, Microsoft), but some maintain their own mail servers for privacy. Admin misconfigurations can be critical.

| Setting | Description |
|---------|-------------|
| `auth_debug` | Enables all authentication debug logging |
| `auth_debug_passwords` | Adjusts log verbosity - submitted passwords and scheme get logged |
| `auth_verbose` | Logs unsuccessful authentication attempts and their reasons |
| `auth_verbose_passwords` | Passwords used for authentication are logged (can be truncated) |
| `auth_anonymous_username` | Specifies username for logging in with ANONYMOUS SASL mechanism |

---

## Footprinting the Service

### Nmap Enumeration

```bash
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```
> Scans all four IMAP and POP3 ports with version detection and default scripts. The SSL certificate in the output often contains the mail server hostname and admin email. Replace `10.129.14.128` with your target IP.

```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 22:09 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00026s latency).

PORT    STATE SERVICE  VERSION
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE SASL STLS TOP UIDL RESP-CODES CAPA PIPELINING
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: more have post-login STARTTLS Pre-login capabilities LITERAL+ LOGIN-REFERRALS OK LOGINDISABLEDA0001 SASL-IR ENABLE listed IDLE ID IMAP4rev1
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
993/tcp open  ssl/imap Dovecot imapd
|_imap-capabilities: more have post-login OK capabilities LITERAL+ LOGIN-REFERRALS Pre-login AUTH=PLAINA0001 SASL-IR ENABLE listed IDLE ID IMAP4rev1
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
995/tcp open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE USER SASL(PLAIN) TOP UIDL RESP-CODES CAPA PIPELINING
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.74 seconds
```

**Key Information from Scan:**
- Common Name: `mail1.inlanefreight.htb`
- Organization: `Inlanefreight`
- Location: `California, US`
- Capabilities show available commands on each port

---

## cURL - IMAP Interaction

### Basic IMAP Connection

```bash
curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd
```
> `-k` skips SSL certificate validation (for self-signed certs). `--user user:password` authenticates and lists available mailboxes. Replace `10.129.14.128` with your target IP and `user:p4ssw0rd` with valid credentials.

```
* LIST (\HasNoChildren) "." Important
* LIST (\HasNoChildren) "." INBOX
```

### Verbose Connection (TLS Details)

```bash
curl -k 'imaps://10.129.14.128' --user cry0l1t3:1234 -v
```
> `-v` shows the full TLS handshake and IMAP protocol exchange. The certificate output reveals the server hostname and email address. Replace the IP and credentials with your target values.

```
*   Trying 10.129.14.128:993...
* TCP_NODELAY set
* Connected to 10.129.14.128 (10.129.14.128) port 993 (#0)
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* Server certificate:
*  subject: C=US; ST=California; L=Sacramento; O=Inlanefreight; OU=Customer Support; CN=mail1.inlanefreight.htb; emailAddress=cry0l1t3@inlanefreight.htb
*  start date: Sep 19 19:44:58 2021 GMT
*  expire date: Jul  4 19:44:58 2295 GMT
*  issuer: C=US; ST=California; L=Sacramento; O=Inlanefreight; OU=Customer Support; CN=mail1.inlanefreight.htb; emailAddress=cry0l1t3@inlanefreight.htb
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
< * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] HTB-Academy IMAP4 v.0.21.4
> A001 CAPABILITY
< * CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN
< A001 OK Pre-login capabilities listed, post-login capabilities have more.
> A002 AUTHENTICATE PLAIN AGNyeTBsMXQzADEyMzQ=
< A002 OK Logged in
> A003 LIST "" *
< * LIST (\HasNoChildren) "." Important
* LIST (\HasNoChildren) "." Important
< * LIST (\HasNoChildren) "." INBOX
* LIST (\HasNoChildren) "." INBOX
< A003 OK List completed (0.001 + 0.000 secs).
* Connection #0 to host 10.129.14.128 left intact
```

---

## OpenSSL - TLS Encrypted Interaction

### POP3 over SSL

```bash
openssl s_client -connect 10.129.14.128:pop3s
```
> Connects to POP3S (port 995) and shows the TLS certificate details before dropping into the POP3 prompt. Once connected, type `USER username` then `PASS password` to log in, then `LIST` to see emails and `RETR 1` to read message 1. Replace `10.129.14.128` with your target IP.

```
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify error:num=18:self signed certificate
verify return:1
---
Certificate chain
 0 s:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
...SNIP...
---
+OK HTB-Academy POP3 Server
```

### IMAP over SSL

```bash
openssl s_client -connect 10.129.14.128:imaps
```
> Connects to IMAPS (port 993). Once connected, authenticate with `A001 LOGIN username password`, then select the inbox with `A002 SELECT INBOX`, and fetch messages with `A003 FETCH 1 BODY[]`. Replace `10.129.14.128` with your target IP.

```
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify error:num=18:self signed certificate
verify return:1
---
Certificate chain
 0 s:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
...SNIP...
---
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] HTB-Academy IMAP4 v.0.21.4
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Nmap IMAP/POP3 scan | `sudo nmap <IP> -sV -p110,143,993,995 -sC` |
| cURL IMAP connection | `curl -k 'imaps://<IP>' --user user:pass` |
| cURL verbose | `curl -k 'imaps://<IP>' --user user:pass -v` |
| OpenSSL POP3S | `openssl s_client -connect <IP>:pop3s` |
| OpenSSL IMAPS | `openssl s_client -connect <IP>:imaps` |

---
