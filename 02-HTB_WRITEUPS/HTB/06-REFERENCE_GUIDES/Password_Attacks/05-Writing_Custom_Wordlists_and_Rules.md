# 05 — Writing Custom Wordlists and Rules

## Overview

Even with password policies in place, users follow predictable patterns — capitalizing the first letter, appending a year, adding `!` at the end. Custom wordlists and rules exploit these patterns by combining OSINT-derived base words with common mutations.

---

## Common Password Patterns

| Pattern | Example | Policy Satisfied |
|---------|---------|-----------------|
| First letter uppercase | `Password` | Uppercase + lowercase |
| Append numbers | `Password123` | + number |
| Append year | `Password2022` | + number |
| Append month | `Password02` | + number |
| Trailing `!` | `Password2022!` | + symbol |
| Leet speak + all | `P@ssw0rd2022!` | All categories |

> Most passwords are ≤10 characters. Users pick familiar 5+ char words, append year + symbol to meet policy.

---

## Hashcat Rule Syntax

| Function | Description | Example |
|----------|-------------|---------|
| `:` | Do nothing (passthrough) | `password` → `password` |
| `l` | Lowercase all | `Password` → `password` |
| `u` | Uppercase all | `password` → `PASSWORD` |
| `c` | Capitalize first, lowercase rest | `password` → `Password` |
| `sXY` | Replace all X with Y | `so0` → `passw0rd` |
| `$X` | Append character X | `$!` → `password!` |
| `^X` | Prepend character X | `^!` → `!password` |

### Example Rule File

```bash
cat custom.rule
```
```
:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

### Applying Rules to Generate Wordlist

```bash
# Generate mutated wordlist (no cracking, just output)
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

**Input**: 1 word (`password`) → **Output**: 15 mutated variants:
```
password, Password, passw0rd, Passw0rd, p@ssword, P@ssword, P@ssw0rd,
password!, Password!, passw0rd!, p@ssword!, Passw0rd!, P@ssword!, p@ssw0rd!, P@ssw0rd!
```

### Pre-built Rule Files

| Rule File | Use Case |
|-----------|----------|
| `best64.rule` / `best66.rule` | Most effective general-purpose rules — **start here** |
| `rockyou-30000.rule` | Comprehensive rockyou-derived rules |
| `d3ad0ne.rule` | Large ruleset for thorough attacks |
| `dive.rule` | Very large — exhaustive mutations |
| `leetspeak.rule` | Leet substitutions only |

---

## Generating Wordlists with CeWL

Scrape words from a target company's website for use as base words.

```bash
# Spider website, min 6-char words, lowercase, save to file
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist

wc -l inlane.wordlist
# 326
```

| Flag | Purpose |
|------|---------|
| `-d <depth>` | Spider depth (how many links deep) |
| `-m <min>` | Minimum word length |
| `--lowercase` | Store all words in lowercase |
| `-w <file>` | Output file |

---

## OSINT-to-Wordlist Workflow

```
1. Gather OSINT: names, pets, hobbies, dates, company, location
2. Build base wordlist from findings
3. Create rules targeting the password policy
4. Generate mutated wordlist: hashcat --force base.list -r rules.rule --stdout > final.list
5. Crack: hashcat -a 0 -m <type> <hash> final.list
```

### OSINT Sources for Base Words

| Source | Yields |
|--------|--------|
| Company name | `Nexura`, `nexura` |
| Birthdate | `1998`, `0805`, `August` |
| Family names | `Maria`, `Alex`, `Bella` |
| Pets | `Bella`, `bella` |
| Hobbies/interests | `Baseball`, `baseball` |
| Location | `SanFrancisco`, `California` |

---

## Exercise: Cracking Mark White's Password

### OSINT Gathered

| Detail | Value |
|--------|-------|
| **Born** | August 5, 1998 |
| **Company** | Nexura, Ltd. |
| **Password Policy** | 12+ chars, upper + lower + symbol + number |
| **Location** | San Francisco, CA |
| **Pet cat** | Bella |
| **Wife** | Maria |
| **Son** | Alex |
| **Hobby** | Baseball |
| **Hash (MD5)** | `97268a8ae45ac7d15c3cea4ce6ea550b` |

### Step 1: Build Base Wordlist from OSINT

```bash
cat > mark_base.list << 'EOF'
bella
maria
alex
baseball
nexura
sanfrancisco
california
mark
white
august
cat
EOF
```

### Step 2: Create Targeted Rules

Rules designed to meet 12+ char policy (capitalize + append year/date + symbol):

```bash
cat > mark_rules.rule << 'EOF'
:
c
c $1
c $1 $!
c $1 $9 $9 $8
c $1 $9 $9 $8 $!
c $0 $8 $0 $5
c $0 $8 $0 $5 $!
c $2 $0 $2 $5
c $2 $0 $2 $5 $!
c $2 $0 $2 $6
c $2 $0 $2 $6 $!
c sa@ $1 $9 $9 $8 $!
c so0 $1 $9 $9 $8 $!
c sa@ so0 $1 $9 $9 $8 $!
c $0 $5 $1 $9 $9 $8
c $0 $5 $1 $9 $9 $8 $!
c $1 $2 $3 $!
c sa@
c so0
c sa@ so0
EOF
```

### Step 3: Generate Mutated Wordlist

```bash
hashcat --force mark_base.list -r mark_rules.rule --stdout | sort -u > mark_final.list
wc -l mark_final.list
# 455 candidates
```

### Step 4: Crack the Hash

```bash
hashcat -a 0 -m 0 97268a8ae45ac7d15c3cea4ce6ea550b mark_final.list
```

### Result

```
97268a8ae45ac7d15c3cea4ce6ea550b:Baseball1998!
```

**Answer: `Baseball1998!`** — Hobby (capitalize) + birth year + `!`. Meets all policy requirements.

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Users follow patterns** | Capitalize + append year + `!` is extremely common |
| **Rules multiply your wordlist** | 1 word × 15 rules = 15 candidates |
| **OSINT drives base words** | Names, dates, hobbies, company = high-probability guesses |
| **CeWL for company words** | Scrape the website for industry/brand terms |
| **`hashcat --stdout`** | Generate wordlist without cracking (preview mutations) |
| **Password policy = pattern hint** | 12 chars + all categories = `Word` + `Year` + `Symbol` |
| **`best64.rule` first** | Then custom rules for targeted attacks |
