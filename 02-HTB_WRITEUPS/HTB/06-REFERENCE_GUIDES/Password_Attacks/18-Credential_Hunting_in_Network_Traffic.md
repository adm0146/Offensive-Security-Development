# 18 — Credential Hunting in Network Traffic

## Overview

Unencrypted protocols can expose credentials in cleartext network traffic. Legacy systems, misconfigured services, or test applications without HTTPS create opportunities to capture credentials.

---

## Common Protocols: Unencrypted vs Encrypted

| Unencrypted | Encrypted | Description |
|-------------|-----------|-------------|
| HTTP | HTTPS | Web page/resource transfer |
| FTP | FTPS/SFTP | File transfer |
| SNMP | SNMPv3 (encrypted) | Network device monitoring |
| POP3 | POP3S | Email retrieval |
| IMAP | IMAPS | Email access/management |
| SMTP | SMTPS | Email sending |
| LDAP | LDAPS | Directory services queries |
| RDP | RDP (with TLS) | Remote desktop access |
| DNS | DNS over HTTPS (DoH) | Domain name resolution |
| SMB | SMB over TLS (3.0) | File/printer sharing |
| VNC | VNC with TLS/SSL | Graphical remote control |

---

## Wireshark Filters

| Filter | Description |
|--------|-------------|
| `ip.addr == 56.48.210.13` | Packets with specific IP |
| `tcp.port == 80` | Filter by port (HTTP) |
| `http` | HTTP traffic only |
| `dns` | DNS traffic only |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN packets (scanning/connection attempts) |
| `icmp` | ICMP/Ping packets |
| `http.request.method == "POST"` | HTTP POST requests (may contain passwords) |
| `tcp.stream eq 53` | Specific TCP stream/conversation |
| `eth.addr == 00:11:22:33:44:55` | Specific MAC address |
| `ip.src == 192.168.24.3 && ip.dst == 56.48.210.3` | Traffic between two IPs |
| `http contains "passw"` | HTTP packets containing "passw" string |

### Finding Credentials in Wireshark

1. Use display filter: `http contains "passw"` or `http.request.method == "POST"`
2. Or go to **Edit → Find Packet** and search for strings like `passw`, `user`, `login`
3. Check POST request body for form data with username/password fields

---

## Pcredz

Extracts credentials from live traffic or packet captures.

### What It Finds

- Credit card numbers
- POP, SMTP, IMAP credentials
- SNMP community strings
- FTP credentials
- HTTP NTLM/Basic auth + HTTP form credentials
- NTLMv1/v2 hashes (DCE-RPC, SMBv1/2, LDAP, MSSQL, HTTP)
- Kerberos (AS-REQ Pre-Auth etype 23) hashes

### Usage

```bash
# Against a packet capture file
./Pcredz -f demo.pcapng -t -v

# Against a live interface
./Pcredz -i eth0 -t -v
```

### Example Output

```
Found SNMPv2 Community string: s3cr...
FTP User: le...
FTP Pass: qw...
```

---

## Key Takeaways

- Always check for unencrypted protocols in network captures — HTTP, FTP, SNMP are common sources
- `http.request.method == "POST"` is the go-to Wireshark filter for finding submitted credentials
- `http contains "passw"` quickly locates password-related packets
- Pcredz automates credential extraction from pcaps — supports NTLM hashes, FTP, HTTP, SNMP, Kerberos
- SNMP community strings are essentially passwords for network device management
- NTLMv1/v2 hashes captured from traffic can be cracked offline

---

## Skills Assessment Walkthrough

**Target:** `demo.pcapng` — mixed traffic capture with HTTP, FTP, and SNMP

### Step 1: Identify Protocols

```bash
tshark -r demo.pcapng -z io,phs -q
```

Key protocols found: `http`, `ftp`, `ftp-data`, `snmp`, `urlencoded-form`

### Step 2: Credit Card Number

Follow HTTP streams on port 80 to find a `POST /process_payment` request:

```bash
# Find all TCP streams on port 80
tshark -r demo.pcapng -Y "tcp.dstport==80||tcp.srcport==80" -T fields -e tcp.stream | sort -un

# Follow stream 76 (the payment POST)
tshark -r demo.pcapng -q -z "follow,tcp,ascii,76"
```

POST body:
```
card_name=Joshua+M+Benito&card_number=5156+8829+4478+9834&exp_date=12%2F30&cvv=928&product_id=SHRT553&quantity=3&price=49.99
```

> **Answer:** `5156 8829 4478 9834`

### Step 3: SNMP Community String

```bash
tshark -r demo.pcapng -Y snmp -T fields -e snmp.community | sort -u
```

> **Answer:** `s3cr3tSNMPC0mmun1ty`

### Step 4: FTP Password

```bash
tshark -r demo.pcapng -Y ftp
```

```
Request: USER leah
Response: 331 Please specify the password.
Request: PASS qwerty123
Response: 230 Login successful.
```

> **Answer:** `qwerty123`

### Step 5: FTP Downloaded File

Same FTP output shows:

```
Request: RETR creds.txt
Response: 150 Opening BINARY mode data connection for creds.txt (44 bytes).
Response: 226 Transfer complete.
```

> **Answer:** `creds.txt`
