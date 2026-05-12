# Section 5 — Hybrid Attacks

> Theory + command chain. No lab.

---

## What Is a Hybrid Attack?

Combines dictionary and brute force — start with a wordlist, then apply mutations (append numbers, symbols, increment years) to each word.

**Exploits the most common password change behavior:**
- `Summer2023` → `Summer2023!` → `Summer2024` → `Summer2024!`

Users think they're complying with policy. They're still predictable.

---

## How It Works

1. **Dictionary phase** — try the wordlist as-is against all accounts
2. **Mutation phase** — if that fails, systematically modify each word:
   - Append digits: `word1`, `word123`, `word2024`
   - Append symbols: `word!`, `word@`
   - Capitalize first letter: `Word`
   - Combine: `Word2024!`

This covers a huge % of real-world passwords while keeping the search space small.

---

## Filtering a Wordlist to Match a Password Policy

When you know a target's password policy, filter your wordlist down to only candidates that comply — cuts search space dramatically.

**Policy example:** Min 8 chars, must have uppercase, lowercase, and a number.

### Command Chain

```bash
# Step 1 — download the wordlist (already at ~/SecLists — skip wget if using local copy)
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/darkweb2017_top-10000.txt

# Step 2 — filter: minimum 8 characters
grep -E '^.{8,}$' darkweb2017_top-10000.txt > darkweb2017-minlength.txt

# Step 3 — filter: must contain at least one uppercase letter
grep -E '[A-Z]' darkweb2017-minlength.txt > darkweb2017-uppercase.txt

# Step 4 — filter: must contain at least one lowercase letter
grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt

# Step 5 — filter: must contain at least one number
grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-number.txt

# Check how many candidates remain
wc -l darkweb2017-number.txt
# Result: 89 passwords (down from 10,000)
```

**What each command does:**
| Command | Regex | Filters for |
|---------|-------|-------------|
| `grep -E '^.{8,}$'` | `^.{8,}$` | Lines with 8+ characters |
| `grep -E '[A-Z]'` | `[A-Z]` | Lines containing at least one uppercase letter |
| `grep -E '[a-z]'` | `[a-z]` | Lines containing at least one lowercase letter |
| `grep -E '[0-9]'` | `[0-9]` | Lines containing at least one digit |

> Each step pipes the *output* of the previous as its *input* — only passwords that pass all four filters survive.

### One-liner version (same result)

```bash
grep -E '^.{8,}$' darkweb2017_top-10000.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' > policy-compliant.txt
```

**When to use this:** Whenever you know the target's password policy. Filtering 10,000 → 89 means your attack runs ~112x faster and avoids wasting attempts on non-compliant passwords.

---

## Credential Stuffing

Uses *known leaked credentials* from one breach to attack other services, banking on password reuse.

**Attack flow:**
1. Obtain breach dump (username:password pairs)
2. Identify target services (email, banking, social media)
3. Automate login attempts against each service
4. Successful match = unauthorized access

**Why it works:** Most users reuse passwords across accounts. One breach compromises everything.

**Tools:** `nxc`, `hydra`, custom scripts — all support credential list formats.

---

## Exam Notes

- **Hybrid** = dictionary wordlist + mutations — use when policy forces changes and you suspect incremental patterns
- **Policy filtering with grep** = always do this when you know the policy — shrinks the wordlist massively
- **Credential stuffing** = try every found credential across every service on the network — reuse is common
- Local darkweb wordlist: `~/SecLists/Passwords/Common-Credentials/darkweb2017_top-10000.txt`
- Add `[^a-zA-Z0-9]` to the grep chain if policy also requires a special character
