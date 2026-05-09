# 09 — SSH Pivoting with Sshuttle

> Sshuttle automates iptables routing over SSH — no proxychains config, no `-sT -Pn` restrictions. Tools run directly as if the internal network were local.

---

## Why Sshuttle Over Proxychains

| | proxychains + `ssh -D` | sshuttle |
|--|----------------------|---------|
| Setup | Edit `/etc/proxychains4.conf` | Single command |
| Nmap scan type | `-sT -Pn` only (TCP connect, no ICMP) | Any scan type — `-A`, `-sS`, `-sU` |
| Tool compatibility | Must prefix every command with `proxychains` | Tools run directly — no prefix |
| UDP support | No (SOCKS4) | No (NAT method) |
| Requires sudo | No | Yes (modifies iptables) |
| Works with | SSH, Chisel, Ligolo (SOCKS5) | SSH only |

**Key advantage:** After starting sshuttle, run `nmap`, `xfreerdp`, `nxc`, etc. directly — no proxychains wrapper needed.

---

## How It Works

Sshuttle SSHes into the pivot and uses Python on the remote end to intercept traffic. Locally it sets up iptables NAT rules that redirect all traffic destined for the target subnet through the SSH tunnel.

```
Attack Box
    │  sshuttle -r ubuntu@PIVOT 172.16.5.0/23
    │  → SSH session + iptables NAT rules created automatically
    ▼
Ubuntu Pivot  [sshuttle Python server]
    │  forwards intercepted traffic to internal network
    ▼
172.16.5.0/23  (any host — transparent, no proxychains)
```

---

## Install

```bash
sudo apt-get install sshuttle
```

> ⚠️ Not installed by default on this machine — install before use.

---

## Basic Usage

```bash
# Route all traffic to 172.16.5.0/23 through the pivot
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```

- `-r ubuntu@10.129.202.64` — SSH into the pivot with this user/host
- `172.16.5.0/23` — subnet(s) to route through the pivot
- `-v` — verbose (shows iptables rules being added)

With password (non-interactive via sshpass):

```bash
sudo sshuttle -r ubuntu:HTB_@cademy_stdnt!@10.129.202.64 172.16.5.0/23
```

Or use SSH key:

```bash
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -e 'ssh -i ~/.ssh/id_rsa'
```

---

## Using Tools Directly (No proxychains)

Once sshuttle is running, all traffic to `172.16.5.0/23` is transparently tunnelled:

```bash
# Full nmap scan — no -sT or -Pn required
sudo nmap -v -A -sT -p3389 172.16.5.19 -Pn

# RDP directly
xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution

# SMB
smbclient -L //172.16.5.19 -U 'victor%pass@123'

# netexec
nxc smb 172.16.5.0/23
```

No `proxychains` prefix on any of these.

---

## What sshuttle Does to iptables

Sshuttle adds NAT rules automatically on startup and removes them cleanly on exit (Ctrl+C):

```
iptables -t nat -N sshuttle-12300
iptables -t nat -I OUTPUT 1 -j sshuttle-12300
iptables -t nat -I PREROUTING 1 -j sshuttle-12300
iptables -t nat -A sshuttle-12300 -j REDIRECT --dest 172.16.5.0/23 -p tcp --to-ports 12300
```

Ctrl+C tears it all down — no manual cleanup needed.

---

## Routing Multiple Subnets

```bash
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 10.10.10.0/24
```

Add as many subnets as needed, space-separated.

---

## Full Copy-Pastable Chain

**Install (if not present)**

```bash
sudo apt-get install -y sshuttle
```

**Start tunnel**

```bash
sudo sshuttle -r ubuntu@10.129.91.231 172.16.5.0/23 -v
# enter pivot SSH password when prompted: HTB_@cademy_stdnt!
```

**Use tools directly (new terminal, tunnel stays running in first)**

```bash
# Verify routing works
nmap -v -sT -Pn -p 3389,445,80 172.16.5.19

# RDP to Windows target
xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution

# Enumerate with netexec
nxc smb 172.16.5.0/23
```

**Stop tunnel**

```
Ctrl+C  (in the sshuttle terminal — iptables rules are cleaned up automatically)
```

---

## Triage

| Symptom | Fix |
|---------|-----|
| `Permission denied` on startup | Missing `sudo` — sshuttle needs root to modify iptables |
| `command not found: sshuttle` | Not installed — `sudo apt-get install sshuttle` |
| SSH password prompt | Normal — use sshpass prefix or SSH keys to automate |
| Tools still can't reach internal hosts | Check subnet matches — must include the target's subnet exactly |
| `Method: nat` warning about UDP | Expected — sshuttle NAT method doesn't support UDP |
| Can't reach pivot after sshuttle starts | Sshuttle excludes `127.0.0.1` and `::1` automatically — pivot's external IP still reachable |

---

## Key Takeaways

1. **No proxychains needed** — sshuttle makes the internal subnet appear local; tools run directly.
2. **Single command** to set up routing — much faster than proxychains + SSH -D + config file edits.
3. **SSH only** — unlike proxychains which works with any SOCKS server, sshuttle requires SSH access to the pivot.
4. **Requires sudo** — it modifies iptables. Clean exit on Ctrl+C, no manual cleanup.
5. **Nmap works normally** — `-A`, version detection, OS fingerprinting all work (no raw socket restrictions of SOCKS).

---

## Lab Solution — Section 9 Skills (May 8, 2026)

**Pivot host:** `10.129.91.231` (ACADEMY-PIVOTING-LINUXPIV)
**Pivot creds:** `ubuntu : HTB_@cademy_stdnt!`
**Internal target:** `172.16.5.19` — `victor : pass@123`

### Optional Exercise 1 → `I tried sshuttle`

```bash
# Install if needed
sudo apt-get install -y sshuttle

# Start tunnel
sudo sshuttle -r ubuntu@10.129.91.231 172.16.5.0/23 -v
# Password: HTB_@cademy_stdnt!

# RDP directly (no proxychains)
xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution
```

---

## References

- Previous: [08-SSH_for_Windows_plink.exe.md](08-SSH_for_Windows_plink.exe.md)
- Next: [10-Web_Server_Pivoting_with_Rpivot.md](10-Web_Server_Pivoting_with_Rpivot.md)
- Sshuttle GitHub: https://github.com/sshuttle/sshuttle
- Sshuttle docs: `sshuttle --help`
