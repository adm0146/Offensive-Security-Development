# 02 — The Concept of Attacks

## Overview

Rather than memorizing attack techniques service-by-service, this section establishes a **universal attack pattern** that applies to every service. Understanding this framework allows you to analyze any vulnerability — old or new — and quickly identify the attack vector, execution path, privilege context, and impact.

---

## The Four Categories

Every attack maps to four core categories:

| Category | Question It Answers | Description |
|----------|-------------------|-------------|
| **Source** | Where does the input come from? | The origin of information that gets passed into a process |
| **Process** | How is the input handled? | The program logic that processes the source data |
| **Privileges** | What permissions does the process run with? | The rights context under which the process executes |
| **Destination** | Where does the output go? | Where results are stored or forwarded after processing |

> The cycle is linear: Source → Process → Privileges → Destination. The Destination does not automatically become a new Source — a new task must be initiated.

---

## Category Detail

### Source — Information Origins

| Source Type | Description | Attack Relevance |
|-------------|-------------|-----------------|
| **Code** | Output/results from already-running code | Return value manipulation, logic flaws |
| **Libraries** | Bundled resources, prebuilt code, classes | Vulnerable dependency exploitation (e.g., Log4j) |
| **Config** | Static/prescribed values for process behavior | Misconfiguration abuse |
| **APIs** | Interfaces for retrieving or providing data | Injection via API parameters, header manipulation |
| **User Input** | Direct values entered by a person | SQLi, XSS, command injection, buffer overflow |

---

### Process — Execution Components

| Component | Description | Vulnerability Relevance |
|-----------|-------------|------------------------|
| **PID** | Process ID — identifies the running process | Process already has assigned privileges |
| **Input** | Information fed into the process | Entry point for malicious data |
| **Data processing** | Hard-coded functions that handle input | Logic flaws, improper sanitization |
| **Variables** | Placeholders reused across functions | Variable manipulation, type confusion |
| **Logging** | Event documentation stored in files/registers | Input echoed into logs can be interpreted as commands |

> **Most vulnerabilities live in the process** — where developer-written logic handles attacker-controlled input.

---

### Privileges — Permission Context

| Privilege Level | Windows Equivalent | Linux Equivalent | Notes |
|----------------|-------------------|-----------------|-------|
| **System** | `SYSTEM` | `root` | Full system modification rights |
| **User** | Standard user account | Named service user | Scoped to that user's permissions |
| **Groups** | Group membership | `/etc/group` | Inherited permissions from group |
| **Policies** | Group Policy (GPO) | PAM / sudoers | App-level command execution rules |
| **Rules** | Application ACLs | AppArmor / SELinux | Enforced within the application itself |

> **Key insight:** The higher the privilege the vulnerable process runs under, the more devastating the exploit. Services running as SYSTEM/root are prime targets.

---

### Destination — Output Targets

| Destination Type | Description | Impact |
|-----------------|-------------|--------|
| **Local** | Results stored or processed on the same system | File write, DB modification, credential storage |
| **Network** | Results forwarded to a remote host/service | Data exfiltration, C2 callback, lateral movement |

---

## The Log4j Case Study (CVE-2021-44228)

Log4j is a Java logging library used in countless applications. Its default behavior of resolving JNDI lookups inside logged strings created a critical RCE vulnerability.

### Phase 1 — Initiation of Attack

| Step | What Happens | Category |
|------|-------------|----------|
| 1 | Attacker injects a JNDI lookup string into the HTTP `User-Agent` header | **Source** |
| 2 | Log4j misinterprets the string as a command instead of text to log | **Process** |
| 3 | The JNDI lookup executes with administrator privileges (logging service runs as admin) | **Privileges** |
| 4 | The lookup reaches out to an attacker-controlled server hosting a malicious Java class | **Destination** |

### Phase 2 — Remote Code Execution

| Step | What Happens | Category |
|------|-------------|----------|
| 5 | The malicious Java class retrieved from attacker's server becomes the new input | **Source** |
| 6 | The malicious Java code is read and executed | **Process** |
| 7 | Code runs under administrator privileges | **Privileges** |
| 8 | A reverse shell or C2 callback is established back to the attacker | **Destination** |

### Why It Was So Dangerous

| Factor | Detail |
|--------|--------|
| **Library** | Log4j was embedded in thousands of products (VMware, Minecraft, enterprise apps) |
| **Privileges** | Logging services almost universally ran as admin/root |
| **Source** | `User-Agent` is attacker-controlled and logged by default |
| **Ease of exploitation** | Single HTTP request triggered full RCE |

---

## Applying the Framework

Use this pattern to analyze any vulnerability:

```
1. SOURCE   — What attacker-controlled input reaches the process?
2. PROCESS  — How does the application handle that input? Where is it mishandled?
3. PRIVILEGES — What account/permissions does the vulnerable process run under?
4. DESTINATION — Where does the result go? Local file? Network callback? DB?
```

### Use Cases for This Framework

| Use Case | How to Apply |
|----------|-------------|
| **Analyzing a CVE** | Map the exploit steps to the four categories |
| **Manual code review** | Trace data flow: where does user input go, how is it processed? |
| **Developing exploits** | Debug by verifying each category is functioning as intended |
| **Reporting findings** | Structure findings around source → process → privileges → destination |

---

## Key Takeaways

| Concept | Takeaway |
|---------|----------|
| Universal pattern | Source → Process → Privileges → Destination applies to every attack |
| Most vulns are in Process | Developer logic mishandling attacker-controlled input |
| Privileges amplify impact | High-privilege processes = high-severity exploits |
| Destination defines impact | Local = host compromise; Network = exfil/lateral movement |
| Log4j as the model | A library (Source) mishandled user input (Process) as admin (Privileges), calling out to attacker (Destination) |
