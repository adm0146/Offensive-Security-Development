# NIBBLES - Very Easy

**Date Started:** January 26, 2026  
**Difficulty:** Very Easy  
**Status:** 🔄 IN PROGRESS

---

## Phase 1: Initial Reconnaissance

### Step 1: Initial Service Enumeration Scan

**Command:**
```
nmap -sV --open -oA nibbles_initial_scan TARGET_IP
```

**Explanation:**
- `-sV`: Service version enumeration scan
- `--open`: Only return ports that are open (filters out closed/filtered)
- `-oA nibbles_initial_scan`: Output all formats (XML, greppable, text) with basename `nibbles_initial_scan`
  - Outputs: `nibbles_initial_scan.nmap`, `nibbles_initial_scan.xml`, `nibbles_initial_scan.gnmap`

**Best Practice Note:** It is essential to get in the habit of taking extensive notes and saving all console output early on. The better we get at this while practicing, the more second nature it will become when on real-world engagements. Proper notetaking is critical for pentesting and will significantly speed up the reporting process and ensure no evidence is lost. It is also essential to keep detailed time-stamped logs of scanning and exploitation attempts in an outage or incident where the client needs information about our activities.

**Understanding Default Port Scans:**
To see which ports a given nmap scan type will probe, run:
```
nmap -v -oG - [no target specified]
```
- `-v`: Verbose output
- `-oG -`: Output in greppable format to stdout

This will fail (no target), but shows which ports are scanned by default for that scan type.

---

### Step 2: Target Machine Service Enumeration

**Command Run:**
```
nmap -sS -sV TARGET_IP
```

**Scan Type Explanation:**
- `-sS`: TCP SYN stealth scan
- `-sV`: Service version detection

**Findings:**

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 80 | HTTP | Apache 2.4.18 | Open |

**Apache Version Identified:** Apache 2.4.18

---

## Key Information Gathered

- Apache web server running on port 80
- Version: 2.4.18 (useful for CVE research and known vulnerabilities)

---

## Next Steps

[To be filled as you continue enumeration...]

---

## Notes & Observations

- Starting with standard reconnaissance methodology
- Documenting all scan outputs for future reference
- Apache 2.4.18 is an older version - check for known vulnerabilities
