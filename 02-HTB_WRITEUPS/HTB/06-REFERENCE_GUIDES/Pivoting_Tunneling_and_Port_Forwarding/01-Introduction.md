# 01 — Introduction to Pivoting, Tunneling, and Port Forwarding

> Foundational concepts: defeating network segmentation by re-routing traffic through compromised hosts.

---

## The Problem We're Solving

We've compromised a host and have creds / keys / hashes / tokens for the **next** target — but that next target isn't reachable from our attack box. The first compromised host has another NIC, sits in another VLAN, or routes to an isolated segment. We use it as a stepping stone.

> First thing to check on every new foothold: **privilege level**, **network connections**, and any **VPN / remote-access software** installed.

If a host has more than one network adapter, it's almost certainly your bridge to a new segment.

---

## Vocabulary

A compromised host used to reach a previously unreachable network has many names — they all mean the same thing:

| Term | Notes |
|------|-------|
| **Pivot host** | Generic |
| **Proxy** | Often when used as a SOCKS endpoint |
| **Foothold** | Initial access host |
| **Beach head system** | Military-flavored synonym |
| **Jump host** | Often legitimate admin terminology (jumpbox) |

---

## Three Tactics — Compared

### Lateral Movement

Spreading **wide** within a network we already have access to: re-using creds, abusing trust, hopping between hosts at the same trust boundary.

> Goal: more hosts, more apps, more services — often to escalate privileges across the domain.

**Practical example:** We popped local admin on Host A, scanned the subnet, found three more Windows hosts, tried the same local admin creds → one accepted → moved laterally to Host B.

References: [Palo Alto explanation](https://www.paloaltonetworks.com/cyberpedia/what-is-lateral-movement) · [MITRE ATT&CK TA0008](https://attack.mitre.org/tactics/TA0008/).

### Pivoting

Going **deeper**: using a compromised host as a relay to reach a network segment we couldn't touch from outside.

> Goal: defeat physical/logical segmentation. Targeted, not wide.

**Practical example:** Engagement target was physically and logically segmented (enterprise ↔ operational). We compromised a **dual-homed** engineering workstation that bridged the two networks; without it we'd have been stuck.

### Tunneling

**Encapsulating** our traffic inside another protocol (HTTP, HTTPS, DNS, ICMP, SSH) to evade detection and traverse filtered egress.

> Goal: obfuscation. Hide command-and-control, exfil, and payload delivery in something that looks normal.

**Practical example:** C2 traffic disguised as ordinary GET/POST requests to a valid-looking domain over HTTPS — proper packets forward to our C2, malformed ones redirect to a real site to throw off any analyst inspecting the traffic.

### Quick comparison

| Concept | Direction | Primary goal |
|---------|-----------|--------------|
| **Lateral movement** | wide | spread across same trust zone, escalate privs |
| **Pivoting** | deep | cross segmentation boundary |
| **Tunneling** | through | hide / encapsulate the traffic itself |

> **Tunneling is a subset of pivoting** — pivoting is the *what* (cross the boundary), tunneling is often the *how* (wrap the traffic so it gets through).

---

## Mental Model — The "Stuffed Toy" Analogy

We need to send a key to a partner without anyone in transit recognizing it as a key. We hide the key inside a stuffed animal toy with instructions, ship the toy. Inspectors see a toy. The partner knows to open it. That's tunneling — the key (our payload / traffic) is wrapped in something innocuous (the carrier protocol).

VPNs and "secure browsers" are just sanctioned versions of the same idea.

---

## Why This Matters for the Exam / Engagement

- Most CPTS labs and real engagements use **tiered networks**: external DMZ → internal corporate → restricted (DC / OT) — you cannot reach the DC from your VPN. You must pivot.
- Listeners must bind to the IP the **target** can reach (the foothold's internal IP), not your VPN tun0.
- Detection often happens at the egress: tunneling over allowed protocols (HTTPS/443, DNS/53) keeps you alive longer.

---

## Key Takeaways

1. **Pivot host = jump host = foothold = proxy = beach head** — same thing.
2. **Always check `ip a`, `route`, `arp -a`, and installed VPN/remote tools** on every new foothold.
3. **Lateral movement ≠ pivoting.** Wide vs deep.
4. **Tunneling ⊂ pivoting.** It's the encapsulation technique that often makes pivoting possible past defenders.
5. The rest of this module operationalizes these ideas with SSH port forwards, SOCKS, Chisel, Ligolo, plink, sshuttle, dnscat2, ICMP tunnels, and Windows-native tooling.

---

## References

- Module index: [README.md](README.md)
- Next: [02-Networking_Behind_the_Scenes.md](02-Networking_Behind_the_Scenes.md)
- MITRE ATT&CK Lateral Movement: <https://attack.mitre.org/tactics/TA0008/>
- Palo Alto — What is Lateral Movement: <https://www.paloaltonetworks.com/cyberpedia/what-is-lateral-movement>
