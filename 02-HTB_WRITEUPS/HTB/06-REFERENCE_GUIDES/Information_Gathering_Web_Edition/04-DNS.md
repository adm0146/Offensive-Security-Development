# 🌐 DNS (Domain Name System)

## Overview

DNS translates domain names to IP addresses. For recon, DNS records reveal **subdomains, mail servers, hosting providers, and infrastructure** — all without touching the target directly.

---

## DNS Record Types — What Each One Gives You

| Record | What It Does | Recon Value |
|---|---|---|
| **A** | Maps hostname → IPv4 address | Target IPs for scanning |
| **AAAA** | Maps hostname → IPv6 address | IPv6 targets (often less secured) |
| **CNAME** | Alias pointing to another hostname | Reveals linked domains, old servers |
| **MX** | Mail server(s) for the domain | Email infrastructure, potential targets |
| **NS** | Authoritative name servers | Hosting provider, DNS infrastructure |
| **TXT** | Arbitrary text (SPF, DKIM, verification) | Leaks security policies, services in use |
| **SOA** | Zone admin info (primary NS, serial, timers) | DNS admin contact, zone config |
| **SRV** | Service hostname + port | Specific services running (SIP, LDAP, etc.) |
| **PTR** | Reverse DNS — IP → hostname | Maps IPs back to domains |

---

## DNS Resolution — How It Works

```
Your Computer → DNS Resolver → Root Server → TLD Server → Authoritative Server
     ↑                                                           |
     └──────────────── IP Address Returned ─────────────────────┘
```

Your machine checks local cache first → asks the resolver → resolver walks the hierarchy until an authoritative server returns the actual IP.

---

## The Hosts File — Local DNS Override

Bypasses DNS entirely. You will use this constantly to access discovered VHosts and HTB targets.

| OS | Path |
|---|---|
| **Linux/macOS** | `/etc/hosts` |
| **Windows** | `C:\Windows\System32\drivers\etc\hosts` |

### Adding Entries

```bash
# Add a target domain manually
echo "10.129.17.237  inlanefreight.htb" | sudo tee -a /etc/hosts

# Add a discovered VHost
echo "10.129.17.237  dev.inlanefreight.htb" | sudo tee -a /etc/hosts
```

### Format

```
<IP Address>    <Hostname>
```

> Changes take effect immediately — no restart needed.

---

## What DNS Findings Tell You

| Finding | What to Do Next |
|---|---|
| **A record** reveals IP `192.168.1.50` | Port scan that IP, check for other domains on same IP |
| **MX record** shows `mail.target.com` | Test mail server for misconfigs, open relay |
| **NS record** reveals hosting provider | Look for other domains on same name servers |
| **CNAME** points `dev.target.com → old.server.net` | Old server might have unpatched vulns |
| **TXT record** contains `v=spf1 ...` | Reveals email security policy — check for bypasses |
| **TXT record** contains `_1password=...` | Reveals password manager in use |

---

## Key Takeaways

- DNS records are a **goldmine** for mapping infrastructure — A records give IPs, MX gives mail servers, NS reveals hosting
- Know the record types and **what each one tells you** about the target
- The **hosts file** is your manual override — use it to access VHosts and lab targets
- **TXT records** often leak security policies and services (SPF, DKIM, verification tokens)
- Feed DNS findings into deeper enumeration — subdomains, zone transfers, port scans

---

## Module Questions & Answers

*Add exercise answers here as you complete them*
