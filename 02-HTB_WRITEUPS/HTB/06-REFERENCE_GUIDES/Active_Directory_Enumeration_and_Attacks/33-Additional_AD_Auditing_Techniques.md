# Section 33 — Additional AD Auditing Techniques

> Four tools for comprehensive AD auditing and reporting: AD Explorer, PingCastle, Group3r, ADRecon.
> These are used at the end of an assessment to collect evidence for the client report and find anything manual enumeration missed.
> RDP to target: htb-student / Academy_student_AD!
> Lab answer: COMPLETE (no flag — just run the tools)

---

## QUICK REFERENCE

```cmd
:: PingCastle — run healthcheck and generate domain risk report
PingCastle.exe --healthcheck --server INLANEFREIGHT.LOCAL

:: PingCastle — interactive TUI (pick options from menu)
PingCastle.exe

:: Group3r — scan all GPOs and write findings to a log file
group3r.exe -f C:\Tools\group3r_output.log

:: Group3r — write findings to stdout instead of a file
group3r.exe -s

:: ADRecon — collect everything from AD and generate report
.\ADRecon.ps1

:: ADRecon — generate Excel report from previously collected CSVs (run on host with Excel)
.\ADRecon.ps1 -GenExcel C:\Tools\ADRecon-Report-20220328092458
```

---

## Tool 1 — AD Explorer (Sysinternals)

**What it is:** An advanced AD viewer and editor that lets you browse AD objects, view all attributes without dialog boxes, and save offline snapshots for later analysis.

**Why it matters on an assessment:**
- You can export a point-in-time snapshot of the full AD database to disk and analyze it during the reporting phase without staying connected to the target
- Enables before/after comparison — if you make changes or the client makes changes between engagements, you can diff the two snapshots
- Lets you browse AD with any valid domain user — no admin rights needed for read access

**How to use:**
1. Launch `ADExplorer.exe` from the Sysinternals suite
2. When prompted, enter any valid domain user credentials and the domain controller hostname
3. Browse: objects appear in a tree on the left, attributes on the right — no dialog boxes required
4. To save a snapshot: `File → Create Snapshot` → enter a name → move the .dat file offline

**Value to the client:** Evidence. A snapshot proves what permissions, attributes, and misconfigurations existed at a specific point in time — hard to dispute in a remediation meeting.

---

## Tool 2 — PingCastle

**What it is:** A domain security scoring tool that produces a risk report based on CMMI (Capability Maturity Model Integration). It goes beyond raw enumeration — it scores the domain's security posture and calls out specific misconfigurations with severity ratings.

**Why it matters:** PingCastle finds the same misconfigs you look for manually (delegation issues, trusts, weak GPOs, stale accounts, shares) but presents them in a client-readable report with risk scores. It also flags recent CVE susceptibility.

### Running PingCastle

```cmd
PingCastle.exe
:: Drops into interactive TUI — choose option 1 for healthcheck
:: The healthcheck is the main output: domain risk score + full misconfiguration report
```

```cmd
PingCastle.exe --healthcheck --server INLANEFREIGHT.LOCAL
:: Non-interactive: directly runs healthcheck against the specified domain
:: --server = target domain name or DC IP
:: Outputs: ad_hc_inlanefreight.local.html (HTML report) in the current directory
```

**PingCastle scanner options** (from the interactive menu → option 4-scanner):

| Scanner | What It Checks |
|---------|---------------|
| aclcheck | ACL permissions on AD objects — finds over-permissioned users/groups |
| antivirus | Whether AV is deployed across domain computers |
| computerversion | OS versions — identifies stale/unpatched hosts |
| foreignusers | Accounts from outside the domain in local groups (cross-trust exposure) |
| laps_bitlocker | Whether LAPS and BitLocker are deployed |
| localadmin | Finds who has local admin on which machines |
| nullsession | Tests for null session access (unauthenticated SMB enumeration) |
| nullsession-trust | Null session exposure across trust boundaries |
| oxidbindings | DCOM/RPC exposure |
| share | Share enumeration and access |
| smb | SMB version and signing status — finds SMB1, missing signing |
| spooler | Whether Print Spooler service is running (PrintNightmare exposure) |
| zerologon | Tests for Zerologon (CVE-2020-1472) vulnerability |

**What the report shows:**
- Overall domain risk score (0–100, lower = better)
- Sections for: Domain, Users, Groups, Trusts
- Anomalies table — immediate-attention findings
- Stale objects, delegation misconfigs, GPO issues, share exposure

**Note:** If PingCastle fails to start, the evaluation license may have expired. Change the system date to before July 31, 2023 via Control Panel → Date and Time, then re-run.

---

## Tool 3 — Group3r

**What it is:** A purpose-built GPO vulnerability scanner. It parses every GPO in the domain and identifies security-relevant misconfigurations, embedded credentials, weak settings, and interesting policy paths.

**Why it matters:** GPOs are frequently overlooked in manual enumeration. Group3r automates what would take hours of manual GPO review and flags the interesting findings with context.

**Requirements:**
- Must run from a domain-joined host
- Must run as a domain user (does NOT need to be an administrator)
- If running from a non-joined host, use `runas /netonly` to run in the context of a domain user

### Running Group3r

```cmd
group3r.exe -f C:\Tools\group3r_output.log
:: -f <filepath> = write all findings to this log file
:: Recommended: always use -f so output isn't lost in terminal scroll
:: The tool will parse every GPO linked in the domain — can take a few minutes on large domains
```

```cmd
group3r.exe -s
:: -s = write output to stdout instead of a file
:: Useful for quick checks or piping to grep/findstr
```

```cmd
group3r.exe -h
:: -h = print help — shows all available flags and options
```

**Reading Group3r output — indentation levels:**

```
GPO Name                          ← no indent = the Group Policy Object itself
  Policy Setting Name             ← one indent = a specific setting within the GPO  
    [FINDING] Description         ← two indents = a security-relevant finding in that setting
    Reason: <why it's interesting>
```

**Common findings Group3r surfaces:**
- Passwords embedded in GPO scripts (SYSVOL readable by all domain users)
- LAPS not deployed (computers managed without rotating local admin passwords)
- Weak LDAP/SMB signing settings in GPOs
- Registry keys enabling insecure authentication
- User rights assignments granting excessive privileges

---

## Tool 4 — ADRecon

**What it is:** A comprehensive AD data collection script that gathers almost everything enumerable from AD in a single run and produces a structured report (HTML + CSV + optionally Excel).

**Why it matters:** Acts as a catch-all — collects data that manual enumeration may have missed and outputs it in a format that's directly useful for reporting. The Excel output is particularly useful for delivering evidence to clients.

### Running ADRecon

```powershell
.\ADRecon.ps1
# Runs with all default collection modules enabled
# Must be run from a domain-joined host as a domain user
# No admin rights required for most modules (LAPS and BitLocker keys require privileged access)
# Total run time: ~10–15 minutes on a typical domain
# Output: creates a new folder named ADRecon-Report-YYYYMMDDHHMMSS in the current directory
```

**What ADRecon collects:**

| Module | Data Collected |
|--------|---------------|
| Domain | Domain name, functional level, FSMO roles |
| Forest | Forest root, forest trusts |
| Trusts | All trust relationships with attributes |
| Sites / Subnets | AD sites and associated subnets |
| Default Password Policy | Min length, complexity, lockout settings |
| Fine Grained Password Policy | Per-group/user PSO settings (needs privileged account) |
| Domain Controllers | All DCs, OS versions, roles |
| Users and SPNs | All user accounts, SPNs, key UAC attributes |
| PasswordAttributes | Accounts with PASSWD_NOTREQD, DONT_REQ_PREAUTH, etc. |
| Groups and Membership | Group membership including nested groups |
| OUs | Organizational unit structure |
| GPOs | All GPOs with their settings |
| DNS Zones and Records | Internal DNS records |
| Printers | Printer objects (PrintNightmare surface) |
| Computers and SPNs | All domain-joined computers |
| LAPS | LAPS deployment status (needs privileged account) |
| BitLocker | BitLocker recovery keys (needs privileged account) |

**ADRecon output structure:**
```
ADRecon-Report-YYYYMMDDHHMMSS\
  CSV-Files\          ← raw CSV data for each module
  GPO-Report.html     ← rendered HTML GPO report
  GPO-Report.xml      ← raw GPO XML
  ADRecon-Report.xlsx ← Excel workbook (requires Excel installed on the host)
```

```powershell
.\ADRecon.ps1 -GenExcel C:\Tools\ADRecon-Report-20220328092458
# -GenExcel <folder> = generate Excel report from existing CSV files
# Use this if the initial run was on a host without Excel — copy the folder to a host with Excel
# and re-run with this flag to generate the .xlsx workbook
```

**Requirements note:**
- Excel must be installed on the host for the `.xlsx` report to be auto-generated
- GPO report requires the `GroupPolicy` PowerShell module to be installed on the host
- If either is missing, the raw CSV files are still produced and can be processed elsewhere

---

## When to Use Each Tool

| Tool | Best Used For |
|------|--------------|
| AD Explorer | Offline analysis; before/after snapshots; quick object browsing without RSAT |
| PingCastle | Client-facing domain risk report; quick risk score; CVE susceptibility check |
| Group3r | Deep GPO audit; finding embedded creds and weak policy settings |
| ADRecon | Comprehensive data dump for reporting; catch-all enumeration at end of assessment |

**Assessment workflow:** Run these tools toward the **end** of an assessment, after initial exploitation and enumeration. They're loud (lots of LDAP queries) but comprehensive. Their output feeds directly into the client deliverable.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Run the tools and confirm | `COMPLETE` |

---

## Exam Notes

- PingCastle = risk-scored AD health report — uses CMMI scoring model; lower score = better security posture
- Group3r = GPO-specific scanner — finds embedded creds, weak settings, insecure registry keys in GPOs
- ADRecon = comprehensive dump — HTML + CSV + optional Excel; requires Excel on host for .xlsx auto-generation
- AD Explorer = Sysinternals tool for offline AD snapshot capture and comparison
- All four tools work with standard domain user credentials — none require Domain Admin to get useful output
- Group3r must run from a domain-joined host or with `runas /netonly` — not usable from a non-joined Linux host
- PingCastle's `--healthcheck` flag runs the main scan non-interactively — useful for scripted assessments
- ADRecon LAPS and BitLocker modules require privileged account — note this in findings if creds are unavailable
- PingCastle spooler scanner = automated PrintNightmare exposure check across all domain hosts
- PingCastle zerologon scanner = automated CVE-2020-1472 check — high value finding if vulnerable DCs found
- These tools produce client-deliverable evidence: screenshots + exported reports make remediation conversations concrete
