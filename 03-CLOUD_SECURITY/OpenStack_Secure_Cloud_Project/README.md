# Secure Cloud Computing — Private OpenStack Cloud: Build, Operate, and Tenant Deployment

**Author:** Andrew Mullins
**Course:** Secure Cloud Computing (graduate-level cloud infrastructure & security)
**Environment:** Self-hosted OpenStack (Kolla-Ansible) on a 5-node rack, no managed CSP
**Scope:** End-to-end — deploy and operate a private cloud as a **provider**, then deploy a hardened workload into a peer cloud as a **tenant**

**Competencies demonstrated:** private-cloud deployment (Kolla-Ansible) · multi-tenant isolation · network segmentation · Ceph distributed storage · internal DNS · security groups & least-privilege · NAT gateway design · bastion access model · Infrastructure-as-Code (Ansible) · container deployment

> **Credentials redacted.** Every password, key, fsid, and account name from the live environment is replaced with `<REDACTED>` or a placeholder. This document describes architecture and method only — no live secrets are published. Private (RFC 1918) addresses are retained because they are non-sensitive and make the topology concrete.

---

## Table of contents

1. [Project overview](#1-project-overview)
2. [Environment & constraints](#2-environment--constraints)
3. [Access model — defense in depth before you reach the cloud](#3-access-model)
4. [Part A — Provider role: building & operating a private cloud](#4-part-a--provider-role)
   - [A.1 Kolla-Ansible deployment](#a1-kolla-ansible-deployment)
   - [A.2 Network architecture & segmentation](#a2-network-architecture--segmentation)
   - [A.3 Internal DNS (BIND)](#a3-internal-dns-bind)
   - [A.4 Ceph distributed storage](#a4-ceph-distributed-storage)
   - [A.5 Multi-tenant provisioning](#a5-multi-tenant-provisioning)
5. [Part B — Tenant role: hardened workload deployment](#5-part-b--tenant-role)
   - [OS-1 · Segmented networks, router, floating IP](#os-1)
   - [OS-2 · Internet-connected VM](#os-2)
   - [OS-3 · NAT gateway](#os-3)
   - [OS-4 · Ansible (Infrastructure-as-Code)](#os-4)
   - [OS-5 · Containerized app deployment](#os-5)
   - [Verification](#verification)
6. [Security analysis](#6-security-analysis)
7. [Skills mapped to cloud-security competencies](#7-skills-mapped)
8. [Engineering lessons](#8-engineering-lessons)

---

## 1. Project overview

The course models a real cloud relationship: each team **builds and operates its own private OpenStack cloud** (the provider), and each team is also a **tenant deploying workloads into a peer team's cloud**. Both sides were graded, and the two roles exercise opposite sides of the cloud-security boundary:

| Role | What it proves |
|---|---|
| **Provider** | You can stand up and secure the *infrastructure* — compute, storage, networking, DNS, and multi-tenant isolation — that other people's workloads run on. |
| **Tenant** | You can deploy a workload *securely into infrastructure you don't control* — segmenting, minimizing attack surface, and automating the build. |

```
        ┌──────────────────────────── PROVIDER (our cloud) ───────────────────────────┐
        │  Kolla-Ansible control plane across 5 role nodes                              │
        │                                                                               │
        │   mgmt ──── controller ──── compute ──── storage1 ──── storage2               │
        │  (gateway,   (Neutron,      (Nova,       (Ceph OSDs)   (Ceph OSDs)            │
        │   DNS/BIND)   Keystone,      QEMU)                                             │
        │               Ceph mon/mgr)                                                    │
        │                                                                               │
        │   Segmented nets: int1 (mgmt) · int2 · storage (Ceph) · ext (NAT out)         │
        │   Provisioned projects/users/quota for external tenant teams  ────────────────┼──▶ peer teams
        └───────────────────────────────────────────────────────────────────────────────┘

        ┌──────────────────────────── TENANT (peer's cloud) ──────────────────────────┐
        │   OS-1 two segmented networks + router + floating IP                          │
        │   OS-2 internet-connected Ubuntu VM (cloud-init)                              │
        │   OS-3 NAT gateway (ip_forward + iptables MASQUERADE/DNAT)                     │
        │   OS-4 Ansible installed (Infrastructure-as-Code)                             │
        │   OS-5 Ansible builds a Docker image and runs a Flask container (:80→:5000)   │
        │        least-privilege security group: only TCP/80 ingress                    │
        └───────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Environment & constraints

- **Fully self-hosted.** No AWS/Azure/GCP. The cloud is Kolla-Ansible (containerized OpenStack) deployed by the team onto five nodes running Ubuntu 24.04.
- **No hardware virtualization.** The compute node exposes no `vmx`/`svm` and no `/dev/kvm`; Nova runs `virt_type = qemu` (TCG software emulation). Every guest operation is 10–50× slower than native. Real numbers: an instance reaches `ACTIVE` in ~4.5 min, and `sshd` starts listening ~8–10 min *after that*. Long `apt`/`docker build` steps take tens of minutes. An SSH "Connection refused" here means `sshd` hasn't come up yet — not a network fault. This constraint shaped several engineering decisions below.
- **Access is password-based, not keypair.** The private key was never distributed, so cloud-init sets a group password on `ubuntu`/`root`. Bastion hops use keyboard-interactive auth with university MFA.

---

## 3. Access model
### Defense in depth before you reach the cloud

The control plane is never directly exposed. Reaching it requires a chain of authenticated hops, MFA at the perimeter, and (for dashboards) SSH-tunneled port forwards — no cloud management port is reachable from the open internet.

```
analyst ──(1) SSH + Duo MFA──▶ university gate bastion
        ──(2) SSH────────────▶ shared cloud bastion (osc-mgmt)
        ──(3) SSH────────────▶ our mgmt node (cloud gateway)
                                 └─ OpenStack CLI, DNS, NAT egress
```

Dashboards (Horizon on TLS 443, Ceph dashboard, Grafana) are reached only through **local SSH port-forwards** layered on the same jump chain, e.g.:

```bash
# Horizon (self-signed TLS) over the bastion chain -> https://localhost:8443
ssh -L 8443:<internal-VIP>:443 \
    -J <you>@<gate-bastion>,<group>@<cloud-bastion> ubuntu@<mgmt-floating-ip>
```

**Security rationale:** every management surface sits behind MFA + multiple authenticated hops. Compromise of a single hop does not reach the control plane, and no OpenStack API/dashboard port is internet-exposed.

> **Operational hardening learned the hard way:** the gate bastion disables plain-password auth (keyboard-interactive + MFA only). An SSH client configured to *offer* password auth first gets rejected and trips `fail2ban`, escalating a per-source-IP ban. Fix: pin `PreferredAuthentications keyboard-interactive` for that host. This is a real lesson in how a client misconfiguration becomes a lockout.

---

## 4. Part A — Provider role
### Building & operating a private cloud

### A.1 Kolla-Ansible deployment

The team deployed containerized OpenStack (Kolla-Ansible) across five role-separated nodes rather than an all-in-one, mirroring a production separation of concerns:

| Node | Role |
|---|---|
| **mgmt** | Cloud gateway, internal DNS (BIND), NAT egress for internal nodes |
| **controller** | Keystone (identity), Neutron (networking), Ceph mon + mgr |
| **compute** | Nova compute (QEMU software emulation) |
| **storage1 / storage2** | Ceph OSDs (distributed block storage) |

Deployment produces a set of highly-available VIPs (internal + external) with **Horizon served over TLS (self-signed) on 443**; port 80 only issues a `301` redirect to TLS. The OpenStack CLI requires `--insecure` for the self-signed cert and authenticates against Keystone at `https://<external-VIP>:5000/v3`.

### A.2 Network architecture & segmentation

Traffic is split across four purpose-built L2 segments so that management, tenant, storage, and external traffic never share a broadcast domain:

| Network | CIDR | Purpose |
|---|---|---|
| **int1** (management) | `10.10.1.0/24` | Node management; internal DNS records live here |
| **int2** | `10.10.2.0/24` | Secondary internal / API VIP segment |
| **storage** | `10.10.3.0/24` | Ceph public + cluster network (isolated storage traffic) |
| **ext** | `10.10.0.0/24` | External/provider segment; internet egress via NAT on the mgmt node |

**Security rationale:** isolating Ceph replication onto its own segment keeps storage traffic off the management and tenant paths (both a performance and a blast-radius decision). Only the mgmt node touches the external segment, so internal nodes have no direct external interface.

> **Neutron port-security gotcha (diagnosed & fixed):** each node bridges its internal interface into `br0`; the bridge MAC **must** equal the Neutron port MAC or port-security silently drops all traffic on that segment. One storage node had a mismatched random bridge MAC and was black-holing — corrected and persisted in netplan. This is exactly the kind of "everything looks up but traffic vanishes" failure that teaches you how the SDN layer actually enforces security.

### A.3 Internal DNS (BIND)

Authoritative BIND server on the mgmt node for the private domain, with forward and reverse zones for the management segment, recursive forwarding for external names, and query scoping:

- Forward + reverse (`in-addr.arpa`) zones for the internal hosts.
- Unknown queries forwarded to a public resolver.
- **`allow-query` scoped to the internal CIDRs** — the resolver is not open to arbitrary clients (avoids running an open/abusable DNS server).
- Every node's stub resolver points at the mgmt BIND server and forces *all* queries through it, so name resolution is centralized and observable.

### A.4 Ceph distributed storage

Distributed block storage via `cephadm`, providing resilient backing for cloud volumes:

- 1 monitor + 1 manager pinned to the controller.
- **6 OSDs** (three per storage node) providing the cluster's raw capacity.
- Dedicated storage network (A.2) for public + cluster replication traffic.
- Health and capacity monitored through the Ceph dashboard, reached over the same tunneled-forward access model (never exposed directly).

### A.5 Multi-tenant provisioning

As a provider, the team onboarded external tenant teams — the multi-tenancy boundary that is the heart of cloud security:

1. **Created an isolated project** per tenant with a bounded **resource quota** (so no tenant can exhaust the cloud's compute/RAM — an availability/DoS control).
2. **Created scoped user accounts** added only to their own project (no cross-tenant visibility).
3. **Created a gateway account** on the mgmt node so tenants could reach the cloud API through the bastion, without any control-plane admin rights.

**Security rationale:** quotas bound the blast radius of a compromised or noisy tenant; per-project users enforce that one tenant can never see or touch another's resources. This is least privilege applied at the tenancy layer.

---

## 5. Part B — Tenant role
### Hardened workload deployment (into a peer team's cloud)

As a tenant, I deployed a complete, internet-reachable, containerized web workload into a peer team's cloud — controlling only the tenant project, not the infrastructure. Tracked as tickets **OS-1 … OS-5**.

<a name="os-1"></a>
### OS-1 · Segmented networks, router, floating IP

Rather than a single flat network, the workload sits on **two isolated tenant networks** joined by a Neutron router with an external gateway; a floating IP provides the single internet-facing entry point.

| Resource | Value |
|---|---|
| Network A | `172.31.10.0/24` (VM `ens3` = `172.31.10.144`) |
| Network B | `172.31.20.0/24` (VM `ens4` = `172.31.20.10`) |
| Router | external gateway on the provider network |
| Floating IP | `10.2.0.134` → the VM |

**Security rationale:** two segments limit east-west movement; the VM's real addresses are never on the provider network — inbound arrives only via the floating IP's controlled NAT.

<a name="os-2"></a>
### OS-2 · Internet-connected VM

A single Ubuntu 22.04 instance (not CIRROS), configured at first boot via **cloud-init** (`config-drive`) to set credentials and enable password SSH. Internet egress verified (`ping`, DNS both functional) through the router's NAT.

<a name="os-3"></a>
### OS-3 · NAT gateway

The VM routes between its segmented networks and the outside using kernel forwarding + iptables, persisted across reboot with `iptables-persistent`:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE
sudo iptables -A FORWARD -i ens4 -o ens3 -j ACCEPT
sudo iptables -A FORWARD -i ens3 -o ens4 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

The `RELATED,ESTABLISHED` return path means inbound is only accepted for connections the internal side initiated — a stateful-firewall default-deny for unsolicited inbound.

<a name="os-4"></a>
### OS-4 · Ansible (Infrastructure-as-Code)

Ansible + Docker installed on the VM so the workload is defined and deployed **as code**, not by hand:

```bash
sudo apt-get install -y ansible docker.io
sudo systemctl enable --now docker
ansible-galaxy collection install community.docker
```

> **Documented deviation:** the spec called for Ansible in a Python virtualenv, but building the `cryptography`/`cffi` wheels was impractical under the cloud's QEMU software emulation (see §2). I used the distribution Ansible package — identical deployment outcome — and documented the tradeoff rather than burning hours on a wheel build. Knowing when a prescribed method's cost outweighs its benefit is an engineering judgment, not a shortcut.

<a name="os-5"></a>
### OS-5 · Containerized app deployment

An Ansible playbook builds a Docker image and runs a Flask container, publishing host `:80` → container `:5000`. The application is isolated in a container, not run on the host. Full artifacts are in [`deploy/`](deploy/):

- [`deploy/app.py`](deploy/app.py) — minimal Flask service
- [`deploy/Dockerfile`](deploy/Dockerfile) — slim base image, single service
- [`deploy/deploy.yml`](deploy/deploy.yml) — Ansible playbook (build image + run container)

```bash
cd ~/flask-app
ansible-playbook deploy.yml
```

**Least-privilege ingress** — only the service port is opened on the tenant security group; everything else (including SSH) is default-deny at the virtual firewall:

```bash
openstack --insecure security group rule create \
  --proto tcp --dst-port 80 --remote-ip 0.0.0.0/0 <SECURITY_GROUP_ID>
```

> `0.0.0.0/0` is intentional here so the workload is broadly reachable for grading. In production this source would be scoped to a known CIDR (LB/WAF/corporate range) and management access locked to the bastion only.

<a name="verification"></a>
### Verification

```bash
# on the VM — container running, app serving locally
$ sudo docker ps
CONTAINER ID   IMAGE       ...   PORTS                  NAMES
3fd251f8f698   flask-app   ...   0.0.0.0:80->5000/tcp   flask-app
$ curl localhost
Flask app running in Docker via Ansible on OpenStack

# from an EXTERNAL host — full path through the floating IP
$ curl 10.2.0.134
Flask app running in Docker via Ansible on OpenStack
```

The external test proves the whole chain: **external host → floating IP → router DNAT → VM → Docker container → Flask.**

> **NAT-hairpin lesson:** curling the floating IP *from the VM itself* times out — expected, not a bug. Reachability must be validated from outside the NAT boundary. Distinguishing a self-test from a true external test is a real troubleshooting skill.

---

## 6. Security analysis

| Layer | Control applied | Threat mitigated |
|---|---|---|
| Perimeter access | MFA-gated bastion chain, no internet-exposed control plane, tunneled dashboards | Credential stuffing / direct API attack on the cloud control plane |
| Network (provider) | Four segmented L2 networks; isolated Ceph/storage segment | East-west lateral movement; storage-plane exposure |
| Multi-tenancy | Per-tenant projects, scoped users, resource quotas | Cross-tenant data access; resource-exhaustion DoS by one tenant |
| Name resolution | `allow-query`-scoped internal BIND | Open-resolver abuse / DNS amplification |
| Network (tenant) | Two segments + router; VM off the provider network | Direct exposure of workload addresses; lateral movement |
| Virtual firewall | Security group scoped to one ingress port, default-deny | Exposure of SSH and non-service ports |
| Host firewall | Stateful iptables (`RELATED,ESTABLISHED` return path) | Unsolicited inbound to the internal segment |
| Application | Flask isolated in Docker, slim single-service image | Host-level impact of an app compromise |
| Repeatability | Entire workload defined as Ansible + Dockerfile | Configuration drift; unauditable manual changes |

---

## 7. Skills mapped
### to cloud-security competencies

| Competency | Evidence |
|---|---|
| Private-cloud deployment | Kolla-Ansible across 5 role-separated nodes |
| Distributed storage | Ceph (`cephadm`), 6 OSDs, isolated storage network |
| Cloud networking & SDN | Neutron segmentation, routers, floating IPs, port-security debugging |
| DNS infrastructure | Authoritative BIND with scoped queries, forward/reverse zones |
| Multi-tenant isolation | Projects, scoped users, quotas for external tenants |
| Identity & access | MFA bastion chain, Keystone auth, no control-plane exposure |
| Virtual + host firewalling | Least-privilege security groups; stateful iptables NAT gateway |
| Infrastructure-as-Code | Ansible playbook + Dockerfile defining a reproducible workload |
| Container fundamentals | Single-service Docker deployment, slim base image |
| Operational troubleshooting | NAT hairpin, Neutron MAC black-hole, fail2ban lockout, no-KVM tuning |

---

## 8. Engineering lessons

- **Least privilege is a posture, not a checkbox.** It shows up at every layer here: one open port, per-tenant quotas, scoped DNS queries, a bastion chain. Small consistent decisions compound into a defensible attack surface.
- **Segmentation is the cheapest blast-radius control you have.** Splitting storage, management, and tenant traffic costs a little config and buys a lot of containment.
- **Know your environment's real constraints.** No KVM meant every guest operation was slow and fragile; adapting (tmux for long runs, distro packages over wheel builds, patience for slow `sshd` startup) mattered more than any single command.
- **"Up but silent" is the hard class of failure.** The Neutron bridge-MAC black-hole and the NAT hairpin both looked like healthy systems while dropping traffic. Understanding *why* the security layer drops packets is the difference between guessing and fixing.

---

*Coursework, sanitized for public reference. Demonstrates method and security reasoning on a self-hosted OpenStack cloud built and operated by the team. No live credentials or private data are included.*
