# 11 — Port Forwarding with Windows Netsh

> Netsh.exe is a Windows built-in that can create port proxy rules — no extra tools needed. It forwards all traffic arriving on a local port straight to an internal host:port.

---

## How It Works

```
Attack Host  [xfreerdp /v:PIVOT_IP:8080]
    │  connects to pivot's external IP on port 8080
    ▼
Windows Pivot  [netsh portproxy: 8080 → 172.16.5.25:3389]
    │  netsh forwards the connection to the internal RDP target
    ▼
172.16.5.25:3389  (internal Windows Server — unreachable directly)
```

No SOCKS proxy. No proxychains. Direct TCP connection to the pivot's external IP — netsh handles the forward internally.

---

## Who Runs What

| Component | Runs on | Role |
|-----------|---------|------|
| `netsh interface portproxy add` | **Windows Pivot** | Creates the port forwarding rule |
| `xfreerdp /v:PIVOT_IP:PORT` | **Attack Host** | Connects through the forward |

---

## Scenario

| Host | IP | Role |
|------|----|------|
| Attack host | `10.10.15.5` | Where you run xfreerdp |
| Windows 10 pivot | `10.129.15.150` (external), `172.16.5.19` (internal) | Compromised workstation — runs netsh |
| Internal RDP target | `172.16.5.25` | Windows Server — RDP port 3389 |

---

## Step 1 — Add Port Proxy Rule on Windows Pivot

Run on the compromised Windows host (CMD as Administrator or via shell):

```cmd
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

Parameters:
- `v4tov4` — IPv4-to-IPv4 forwarding
- `listenport=8080` — port netsh listens on (what the attack host dials)
- `listenaddress=10.129.15.150` — pivot's external IP (or `0.0.0.0` to listen on all interfaces)
- `connectport=3389` — destination port on the internal target (RDP)
- `connectaddress=172.16.5.25` — internal target's IP

---

## Step 2 — Verify the Rule

```cmd
netsh.exe interface portproxy show v4tov4
```

Expected output:
```
Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.15.150   8080        172.16.5.25     3389
```

---

## Step 3 — Connect from Attack Host

No proxychains — connect directly to the pivot's external IP on the listen port:

```bash
xfreerdp /v:10.129.15.150:8080 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution
```

Or using the `rdp` alias from CLAUDE.md:
```bash
xfreerdp3 /v:10.129.15.150:8080 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution +clipboard /compression
```

---

## Removing the Rule (Cleanup)

```cmd
netsh.exe interface portproxy delete v4tov4 listenport=8080 listenaddress=10.129.15.150
```

Verify it's gone:
```cmd
netsh.exe interface portproxy show all
```

---

## Full Copy-Pastable Chain

**On Windows pivot (CMD / existing shell):**

```cmd
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.5.25
netsh.exe interface portproxy show v4tov4
```

**On attack host:**

```bash
# Replace PIVOT_IP with the pivot's spawned external IP
xfreerdp /v:PIVOT_IP:8080 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution
```

---

## Port Mapping

| What | IP | Port |
|------|----|------|
| Attack host dials | Pivot external IP | `8080` — netsh listens here |
| Netsh forwards to | Internal target (`172.16.5.25`) | `3389` — RDP |

---

## Netsh vs Other Pivot Methods

| Method | OS | Requires | Notes |
|--------|----|----------|-------|
| **netsh portproxy** | Windows only | Admin shell on pivot | No extra tools — Windows built-in |
| `ssh -L` | Linux/Mac | SSH creds/keys | Port forward over SSH |
| socat | Linux | socat binary | Dumb TCP forwarder, no SSH |
| rpivot | Any (Python 2.7) | Outbound connection from pivot | Reverse SOCKS |

Netsh advantage: zero additional tooling needed on a Windows pivot — it's a LOL-bin (living off the land).

---

## Triage

| Symptom | Fix |
|---------|-----|
| `The parameter is incorrect` | Missing `listenaddress` — it's required |
| Rule added but connection refused | Windows Firewall may block port 8080 — check/add inbound rule |
| xfreerdp connects but hangs | Internal RDP target (172.16.5.25) not reachable from pivot — verify routing |
| `Access is denied` running netsh | Needs elevated CMD (Administrator) |
| Rule survives reboot | Netsh portproxy rules are persistent — remember to clean up |

**Adding a firewall exception for the listen port (if needed):**
```cmd
netsh advfirewall firewall add rule name="rpivot8080" protocol=TCP dir=in localport=8080 action=allow
```

---

## Key Takeaways

1. **Windows built-in — no uploads needed.** Netsh portproxy is a LOL-bin; it's already on every Windows system.
2. **Direct connection — no proxychains.** The attack host dials the pivot's external IP:listenport directly.
3. **Rules are persistent** across reboots — always delete them on cleanup (`portproxy delete v4tov4`).
4. **`listenaddress=0.0.0.0`** is simpler than specifying a specific IP and works when you don't know which interface the attack host will reach the pivot on.
5. Windows Firewall may block the custom listen port — may need to add an inbound rule with `netsh advfirewall`.

---

## Lab Solution — Section 11 Skills (May 8, 2026)

**Pivot host:** `10.129.x.x` (ACADEMY-PIVOTING-WIN10PIV) — IP changes per spawn
**Pivot creds:** `htb-student : HTB_@cademy_stdnt!` via RDP
**Pivot internal IP:** `172.16.5.150`
**DC (target):** `172.16.5.19`
**DC creds:** `victor : pass@123`

> **Lab note:** Wait 3–5 minutes after spawn before attempting — the DC takes time to fully boot. Verify the internal network is up by pinging `172.16.5.1` from the pivot before proceeding.

### Q1 — Approved contact name from VendorContacts.txt → `Jim Flipflop`

**Full verified chain:**

**Step 1 — RDP into Windows 10 pivot:**
```bash
xfreerdp /v:PIVOT_IP /u:htb-student /p:'HTB_@cademy_stdnt!' /cert:ignore /dynamic-resolution
```

**Step 2 — On the pivot (run PowerShell as Administrator), wait for gateway then set up portproxy:**
```powershell
# Confirm internal network is up before proceeding
ping 172.16.5.1 -n 2

# Add portproxy: listen on 8080, forward to DC:3389
netsh.exe interface portproxy add v4tov4 listenport=8080 connectaddress=172.16.5.19 connectport=3389

# Add firewall exception
netsh advfirewall firewall add rule name="pivot8080" protocol=TCP dir=in localport=8080 action=allow

# Verify
netsh.exe interface portproxy show v4tov4
```

Expected portproxy output:
```
Listen on ipv4:             Connect to ipv4:
Address         Port        Address         Port
--------------- ----------  --------------- ----------
*               8080        172.16.5.19     3389
```

**Step 3 — From attack host, RDP through the forward to the DC:**
```bash
xfreerdp /v:PIVOT_IP:8080 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution
```

**Step 4 — On victor's desktop → Approved Vendors → VendorContacts.txt:**
```
Name:         Jim Flipflop
Phone:        123-123-1234
Organization: CAT5 Security
```

**Flag:** `Jim Flipflop`

**Cleanup (run on pivot after done):**
```powershell
netsh.exe interface portproxy delete v4tov4 listenport=8080
netsh advfirewall firewall delete rule name="pivot8080"
```

---

## References

- Previous: [10-Web_Server_Pivoting_with_Rpivot.md](10-Web_Server_Pivoting_with_Rpivot.md)
- Next: [12-DNS_Tunneling_with_Dnscat2.md](12-DNS_Tunneling_with_Dnscat2.md)
- Netsh docs: `netsh interface portproxy /?`
