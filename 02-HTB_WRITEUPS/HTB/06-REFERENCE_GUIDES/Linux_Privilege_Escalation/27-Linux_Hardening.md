# Section 27 — Linux Hardening

> No lab for this section — defensive reference only.

---

## Hardening Categories

### 1. Updates and Patching

Most privesc techniques in this module exploit **known CVEs in outdated software**. Regular patching eliminates the lowest-hanging fruit.

| Distro | Auto-update package |
|--------|-------------------|
| Ubuntu 18.04+ | `unattended-upgrades` (installed by default) |
| Debian (Jessie+) | `unattended-upgrades` (available via apt) |
| RHEL / CentOS | `yum-cron` |

### 2. Configuration Management

| Hardening Action | Privesc Technique It Prevents |
|-----------------|------------------------------|
| Audit writable files/dirs and SUID binaries | SUID abuse (§8), shared object hijacking (§21) |
| Cron jobs use absolute paths | Cron job abuse (§13), path abuse (§5), wildcard abuse (§6) |
| No cleartext credentials in world-readable files | Credential hunting (§4) |
| Clean home dirs and bash history | Credential hunting (§4) |
| Protect custom libraries from low-priv users | Python library hijacking (§22), LD_PRELOAD (§20), shared object hijacking (§21) |
| Remove unnecessary packages/services | Vulnerable services (§12), reduce attack surface |
| Implement SELinux / AppArmor | Limits damage from any successful exploit |

### 3. User Management

- Limit user and admin accounts per system
- Log and monitor logon attempts (valid and invalid)
- Strong password policy — prioritize long passphrases over forced rotation
- Block password reuse via `/etc/security/opasswd` with PAM
- Apply least-privilege principle to group memberships and sudo rights
- Audit sudo rules: no `(ALL, !root)` patterns (§23), no `env_keep+=LD_PRELOAD` (§20), no `SETENV:` with script paths (§22)

### 4. Audit Tools and Frameworks

| Tool/Framework | Purpose |
|---------------|---------|
| **Lynis** | Unix system auditing — checks config, suggests hardening |
| **DISA STIGs** | Security baselines for OS/device configuration |
| **ISO 27001** | Information security management framework |
| **PCI-DSS** | Payment card data security standard |
| **HIPAA** | Health information privacy/security |
| Puppet / SaltStack | Configuration management automation |
| Zabbix / Nagios | Monitoring, alerting, checksum verification |

---

## Lynis Quick Reference

```bash
# Clone and run (non-privileged scan)
git clone https://github.com/CISOfy/lynis.git
cd lynis
./lynis audit system

# Run as root for full scan
sudo ./lynis audit system

# Output:
# - Hardening index (0-100)
# - Warnings (critical findings)
# - Suggestions (hardening recommendations)
# - lynis.log (detailed test results)
# - lynis-report.dat (machine-readable report)
```
> Non-privileged scan skips some tests. Root scan gives complete results. The hardening index is a quick gauge — 60/100 in the module example means significant room for improvement.

---

## Mapping Hardening to Module Sections

| Privesc Vector | Section | What to Harden |
|---------------|---------|----------------|
| Environment enumeration | §2-3 | Restrict access to system info, limit `/proc` visibility |
| Credential hunting | §4 | No cleartext creds, clean bash history, restrict file permissions |
| PATH abuse | §5 | Use absolute paths in scripts and cron, secure PATH order |
| Wildcard abuse | §6 | Avoid wildcards in cron/scripts, use `--` to end options |
| Restricted shell escape | §7 | Use rbash properly, remove escape vectors |
| SUID/SGID/sticky bit | §8 | Audit SUID binaries regularly, remove unnecessary SUID |
| Sudo rights | §9 | Least privilege, no GTFOBins as sudo targets |
| Privileged groups | §10 | Don't add users to docker, lxd, disk, adm groups unnecessarily |
| Capabilities | §11 | Audit `getcap`, remove unnecessary capabilities |
| Vulnerable services | §12 | Patch services, remove unnecessary ones |
| Cron jobs | §13 | Absolute paths, proper permissions on scripts, no writable dirs |
| Containers | §14-16 | Don't run containers as root, use seccomp/AppArmor profiles |
| Logrotate | §17 | Patch logrotate, restrict write access to log directories |
| NFS | §18 | Use `root_squash` (default), restrict exports |
| Kernel exploits | §19,25,26 | Keep kernel updated — eliminates Dirty Pipe, OverlayFS, Netfilter |
| Shared libraries | §20-21 | Protect library paths, don't use `env_keep+=LD_PRELOAD` |
| Python hijacking | §22 | Protect module files, don't use `SETENV:` in sudo rules |
| Sudo CVEs | §23 | Patch sudo — eliminates CVE-2019-14287 and Baron Samedit |
| Polkit/PwnKit | §24 | Patch polkit — eliminates CVE-2021-4034 |

---

## Exam / Engagement Notes

- **This section won't be tested directly** — but understanding defenses helps you recognize what's NOT hardened on a target.
- **Lynis output is useful for pentesters too** — run it on a compromised box to quickly find additional misconfigurations.
- **Audits ≠ pentests** — compliance checks verify minimum standards, pentesting finds what's actually exploitable. The exam tests exploitation, not auditing.
- **On a real engagement**: include hardening recommendations in your report. Map each finding to a specific remediation from this section.

> One line: patching + least privilege + proper file permissions + regular auditing eliminates most Linux privesc vectors covered in this module.
