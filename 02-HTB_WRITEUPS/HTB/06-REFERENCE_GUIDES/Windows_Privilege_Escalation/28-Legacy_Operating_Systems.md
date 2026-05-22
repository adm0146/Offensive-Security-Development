# Section 28 — Legacy Operating Systems

> **Lab: no** — Reading-only section covering differences between legacy and modern Windows for privilege escalation.

**Core principle:** Legacy operating systems (Server 2003/2008, Windows XP/7) lack modern security features (Credential Guard, Device Guard, AMSI, AppLocker) and are often massively unpatched. They are common in medical, government, and university environments due to mission-critical legacy software.

---

## EOL dates to know

| Version | EOL Date |
|---------|----------|
| Windows XP | April 8, 2014 |
| Windows 7 | January 14, 2020 |
| Windows Server 2003 | April 8, 2014 |
| Windows Server 2008/R2 | January 14, 2020 |
| Windows Server 2012/R2 | October 10, 2023 |

---

## Why legacy systems matter for pentesting

- **No security updates** — known kernel exploits remain unpatched permanently.
- **Missing modern protections** — no Credential Guard, no AMSI, no AppLocker, weak/no Windows Defender.
- **Common in enterprise** — hospitals, universities, local government often can't upgrade due to vendor-locked software.
- **Easy footholds** — often vulnerable to remote code execution (EternalBlue, BlueKeep) AND local privesc.
- **Always check with the client** before attacking — legacy systems may be fragile and running mission-critical applications.

---

## Key takeaway

When you encounter a legacy OS during an assessment, it's usually exploitable through multiple vectors. Enumerate the patch level (`wmic qfe`, Sherlock, Windows-Exploit-Suggester) and pick the most reliable exploit. Always confirm with the client that the system can handle exploitation without disrupting operations.
