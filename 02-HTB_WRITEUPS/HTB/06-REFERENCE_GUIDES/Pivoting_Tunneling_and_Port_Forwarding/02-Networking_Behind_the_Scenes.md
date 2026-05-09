# 02 — The Networking Behind Pivoting

> Networking refresher tuned for pivoting: NICs, IP addressing, routing tables, ports/services. Without these fundamentals, pivoting is guess-and-check.

---

## IP Addressing & NICs

Every host on a network needs an IP. No IP → not on the network. IPs are assigned in software, either:

- **Dynamically** via DHCP (most clients), or
- **Statically** — typical for servers, routers, switch SVIs, printers, and any device offering critical services.

The IP is bound to a **Network Interface Controller (NIC)** — also called a network adapter / network interface card. A host can have **multiple NICs (physical or virtual)** with multiple IPs, letting it talk to multiple networks at once.

> **Why this matters for pivoting:** the IPs assigned to a compromised host tell you which networks it can reach. A second NIC = potential bridge to a new segment. **Always check NICs first.**

---

## Linux — `ifconfig` / `ip`

```bash
ifconfig            # legacy but everywhere
ip a                # modern
ip -br a            # one-line summary
```

Example output of `ifconfig`:

```text
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 134.122.100.200  netmask 255.255.240.0  broadcast 134.122.111.255
        ether 12:ed:13:35:68:f5

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.106.0.172  netmask 255.255.240.0  broadcast 10.106.15.255
        ether 4e:c7:60:b0:01:8d

lo:   flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.15.54  netmask 255.255.254.0  destination 10.10.15.54
```

What to read from this:

| Interface | IP | Meaning |
|-----------|-----|---------|
| `eth0` | `134.122.100.200` | **Public** routable IP — internet-facing (often DMZ) |
| `eth1` | `10.106.0.172` | RFC1918 private — internal LAN |
| `lo` | `127.0.0.1` | Loopback |
| `tun0` | `10.10.15.54` | **VPN tunnel** active (HTB lab access) |

> A `tun*`/`tap*` interface is your tip-off that a VPN is up. Without it, HTB lab networks are unreachable.
> Public IPs reach the open Internet via ISPs. Private IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are routable only inside an org and require **NAT** to talk outbound.

---

## Windows — `ipconfig`

```powershell
ipconfig                # short
ipconfig /all           # full (DHCP, DNS, MAC, lease)
Get-NetIPAddress        # PowerShell native
Get-NetIPConfiguration
```

Example output:

```text
Ethernet adapter Ethernet0 2:
   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::1a9
   Link-local IPv6 Address . . . . . : fe80::f58b:6381:c648:1fb0%8
   IPv4 Address. . . . . . . . . . . : 10.129.221.36
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.129.0.1
```

This NIC is **dual-stack** (IPv4 + IPv6). This module focuses on IPv4 — still dominant in enterprise LANs.

### Subnet mask = "area code" for IPs

The subnet mask defines the **network portion** vs the **host portion** of an IP. When traffic targets an IP outside the local subnet, it goes to the **default gateway** (typically the LAN router's NIC).

> Pivot mindset: document every IP, mask, and gateway you find on every foothold. They tell you what networks the box can reach and where to point routes.

---

## Routing

Any computer can route — not just appliances. A router is just a host with a **routing table** that uses the destination IP to decide where to forward each packet. We'll later use Metasploit's **AutoRoute** to make our attack box treat a pivot host as the next hop for an internal subnet.

### Reading a routing table

```bash
# Linux
netstat -r
ip route                 # modern
ip route get 10.129.10.25     # show which route applies for an IP
```

```cmd
:: Windows
route print
Get-NetRoute               # PowerShell
```

Example `netstat -r` from Pwnbox:

```text
Kernel IP routing table
Destination     Gateway         Genmask         Flags   Iface
default         178.62.64.1     0.0.0.0         UG      eth0
10.10.10.0      10.10.14.1      255.255.254.0   UG      tun0
10.10.14.0      0.0.0.0         255.255.254.0   U       tun0
10.106.0.0      0.0.0.0         255.255.240.0   U       eth1
10.129.0.0      10.10.14.1      255.255.0.0     UG      tun0
178.62.64.0     0.0.0.0         255.255.192.0   U       eth0
```

How packets get routed:

- For `10.129.10.25` → matches `10.129.0.0/16` → next hop `10.10.14.1` via `tun0`.
- For `8.8.8.8` (no match) → falls back to `default` via `eth0` → `178.62.64.1` (gateway of last resort).

Flag glossary:

| Flag | Meaning |
|------|---------|
| `U` | Up |
| `G` | Gateway (indirect) — packet goes through next hop |
| `H` | Host route (single IP, not subnet) |
| `D` | Dynamically added (e.g., ICMP redirect) |

### How routes get into the table

| Source | Example |
|--------|---------|
| Directly connected NIC | `eth1` brings in `10.106.0.0/20` automatically |
| Static route | manually `ip route add 172.16.5.0/24 via 10.106.0.1` |
| Routing protocol | OSPF / EIGRP / BGP on dedicated routers |
| AutoRoute (Metasploit) | meterpreter session injects route through pivot |
| Tunnel interface | OpenVPN/Ligolo creates `tun*` and adds routes |

> Pivot recipe: read the foothold's routing table → identify reachable internal subnets → either route your attack box's traffic through it (AutoRoute / Ligolo / SOCKS) or add static routes to networks the pivot already knows about.

---

## Protocols, Services & Ports

- **Protocols** = the rules of network communication.
- **Logical ports** = software identifiers (0–65535) bound to applications listening on a NIC.
- **IP** identifies the host. **Port** identifies the service on that host.

Open ports = potential entry points. Many engagements start by abusing a service legitimately exposed through the firewall:

> Example: a webserver on `tcp/80` cannot be blocked inbound or no one could reach the site. That same port is your way in if the app is vulnerable.

### Source vs destination ports

- **Destination port** is the listening service (e.g., 80, 22, 445).
- **Source port** is randomly chosen by the client to track the connection.

When your payload calls home, **source port matters too** — make sure the listener you set up matches the port the payload is hard-coded to dial. Port reuse and confusion cause silent failures.

### Common ports — pivoting cheat

| Port | Service | Pivot relevance |
|------|---------|-----------------|
| 22 | SSH | best-of-class tunneling — `-L`, `-R`, `-D` |
| 53 | DNS | egress almost always allowed → DNS tunneling (`dnscat2`) |
| 80 / 443 | HTTP(S) | Chisel, HTTPS-wrapped C2; port 443 always egresses |
| 445 | SMB | named-pipe pivots, lateral movement |
| 3389 | RDP | Windows port forward via plink/socat |
| 5985 / 5986 | WinRM | PS Remoting jump hosts |
| 8080 / 8443 | HTTP-alt | proxychains-friendly |

---

## Pivot-Hunting Checklist on a New Foothold

```bash
# Linux
id; whoami
ip -br a                                # all NICs at a glance
ip route                                # known networks
arp -a                                  # neighbors on attached subnets
ss -tlnp                                # listening services (local pivot opportunities)
cat /etc/hosts /etc/resolv.conf         # name → IP hints
ls /etc/openvpn /etc/wireguard 2>/dev/null   # pre-configured tunnels?
which sshpass socat chisel ssh nc       # tools available for pivoting
```

```powershell
# Windows
whoami /priv
ipconfig /all
route print
arp -a
Get-NetTCPConnection | Sort State,LocalPort
Get-Service | Where-Object Status -eq Running | Select Name,DisplayName
Get-NetAdapter
```

What to look for:

1. **More than one NIC** with non-loopback IPs → probable bridge.
2. **Routes to RFC1918 networks you don't already have access to** from your VPN.
3. **Hostfile entries / DNS suffixes** revealing internal domains.
4. **Installed VPN clients** (OpenVPN, NordLynx, AnyConnect, GlobalProtect, WireGuard) — sometimes pre-configured with creds in `/etc/openvpn/*.conf`.
5. **Other listening services** on the foothold (e.g., `127.0.0.1:3306`) → forward back via SSH `-L` to reach from your box.

---

## Practical Tip (LTNB0B)

> Draw your topology as you discover it. [Draw.io](https://app.diagrams.net) is great for this — visualize NICs, IPs, gateways, tunnels, and ports as you map them. It doubles as engagement documentation.

This module gets progressively harder; build the muscle memory by **drawing** every new lab network you face.

---

## Section Questions (Answers)

| # | Question | Answer |
|---|----------|--------|
| 1 | Reference the `ifconfig` output. Which NIC is assigned a public IP address? | **`eth0`** (`134.122.100.200`) |
| 2 | Reference the routing table. If a packet is destined for `10.129.10.25`, which NIC forwards it? | **`tun0`** (matches `10.129.0.0/16` via gateway `10.10.14.1`) |
| 3 | Reference the routing table. If a packet is destined for `www.hackthebox.com`, what is the gateway IP? | **`178.62.64.1`** (default route via `eth0`) |

---

## Key Takeaways

1. Multiple NICs on a host = strongest pivot signal. Always inventory them.
2. Public IP on `eth0` + private IP on `eth1` = textbook DMZ pivot host.
3. The routing table tells you what networks a host **already** knows how to reach — use it before brute-forcing routes.
4. Ports / services are the hooks you'll forward through your tunnels later in the module.
5. Document everything: `ip a`, `ip route`, `arp -a`, `ss -tlnp` (or Windows equivalents) on every foothold, every time.

---

## References

- Previous: [01-Introduction.md](01-Introduction.md)
- Next: [03-Dynamic_Port_Forwarding_with_SSH_and_SOCKS_Tunneling.md](03-Dynamic_Port_Forwarding_with_SSH_and_SOCKS_Tunneling.md)
- HTB Academy module: *Introduction to Networking*
- Diagramming: <https://app.diagrams.net>
