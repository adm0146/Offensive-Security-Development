# 10 — Sessions

## Overview

MSFconsole can manage **multiple modules simultaneously** through sessions. Each session is a dedicated control interface for a deployed module's connection to a target. Sessions persist in the background, allowing you to switch between targets and chain post-exploitation modules.

---

## Session Management

### Background a Session

| Method | Context |
|--------|---------|
| `Ctrl+Z` | From any active session (Meterpreter or shell) |
| `background` | Meterpreter command |

Both return you to the `msf6 >` prompt while keeping the connection alive.

### List Active Sessions

```bash
msf6 > sessions

# Active sessions
# ===============
#   Id  Name  Type                     Information                 Connection
#   --  ----  ----                     -----------                 ----------
#   1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ MS01  10.10.10.129:443 -> 10.10.10.205:50501
```
> Shows all active sessions with their ID, type, user context, and connection info. Note the session ID — you'll need it to interact, kill, or target with post modules.

### Interact with a Session

```bash
msf6 > sessions -i 1
# [*] Starting interaction with 1...
meterpreter >
```
> `-i` followed by the session ID resumes interaction. Replace `1` with the ID from `sessions`. Returns you to the Meterpreter or shell prompt for that session.

### Kill a Session

```bash
msf6 > sessions -k 1      # Kill session by ID
msf6 > sessions -K        # Kill ALL sessions
```
> `-k <id>` kills one session cleanly. `-K` (capital) kills all sessions at once. Use with care during multi-target engagements.

---

## Session Workflow: Chaining Modules

```bash
# 1. Exploit target → get Meterpreter session
msf6 exploit(...) > run
meterpreter >

# 2. Background the session
meterpreter > background
# [*] Backgrounding session 1...

# 3. Load a post-exploitation module
msf6 > use post/windows/gather/hashdump

# 4. Set the session to run against
msf6 post(windows/gather/hashdump) > set SESSION 1
msf6 post(windows/gather/hashdump) > run

# 5. Switch back to original session
msf6 > sessions -i 1
```
> The standard post-exploitation chain: exploit → background → load post module → set SESSION → run → return to session. Replace `1` with your actual session ID from `sessions`.

### Common Post-Exploitation Module Types

| Category | Examples |
|----------|----------|
| **Credential Gatherers** | `post/windows/gather/hashdump`, `post/windows/gather/credentials/*` |
| **Local Exploit Suggesters** | `post/multi/recon/local_exploit_suggester` |
| **Internal Network Scanners** | `post/multi/gather/ping_sweep`, `post/windows/gather/arp_scanner` |

---

## Jobs

Jobs run modules in the background, freeing the console for other tasks. Useful when a module holds a port (like `multi/handler`) and you need to keep it running.

### Run an Exploit as a Background Job

```bash
msf6 exploit(multi/handler) > exploit -j
# [*] Exploit running as background job 0.
# [*] Started reverse TCP handler on 10.10.14.34:4444
```
> `-j` runs the module as a background job so you keep the console free. Essential for `multi/handler` — the listener stays open while you do other things.

### Key `exploit` / `run` Flags

| Flag | Description |
|------|-------------|
| `-j` | Run as a background job |
| `-J` | Force running in foreground (even if passive) |
| `-e <encoder>` | Specify payload encoder |
| `-f` | Force run regardless of MinimumRank |

### List Running Jobs

```bash
msf6 > jobs -l

# Jobs
# ====
#  Id  Name                    Payload                    Payload opts
#  --  ----                    -------                    ------------
#  0   Exploit: multi/handler  generic/shell_reverse_tcp  tcp://10.10.14.34:4444
```
> `-l` lists all running background jobs with their ID, module name, and payload. Use the job ID with `jobs -k <id>` to stop a specific listener.

### Job Management Commands

| Command | Description |
|---------|-------------|
| `jobs -l` | List all running jobs |
| `jobs -i <id>` | Detailed info about a job |
| `jobs -k <id>` | Kill a specific job |
| `jobs -K` | Kill ALL running jobs |
| `jobs -P` | Persist all jobs on restart |
| `jobs -p <id>` | Add persistence to a specific job |
| `jobs -v` | Verbose output (use with `-l` or `-i`) |

---

## Sessions vs Jobs

| Feature | Sessions | Jobs |
|---------|----------|------|
| **What** | Active connections to targets | Background tasks/listeners |
| **Created by** | Successful exploits | `exploit -j` or passive modules |
| **Interact** | `sessions -i <id>` | Cannot interact directly |
| **Purpose** | Run commands on target | Keep listeners/handlers running |
| **Kill** | `sessions -k <id>` | `jobs -k <id>` |
| **Kill all** | `sessions -K` | `jobs -K` |

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **`Ctrl+Z` to background** | Session stays alive — you return to msf6 prompt |
| **`sessions -i <id>` to resume** | Jump back into any active session |
| **`SESSION` option in post modules** | Set which session to run post-exploitation against |
| **`exploit -j` for background jobs** | Keeps listeners running without blocking console |
| **Sessions can die** | If payload crashes or network drops, the channel tears down |
| **Don't `Ctrl+C` listeners** | Port stays bound — use `jobs -k` to properly free it |
| **Chain modules via sessions** | Exploit → background → post module → set SESSION → run |
