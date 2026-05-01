# 🛡️ Password Policies

> **Module Section:** 24 / 26 — Password Attacks

## Overview

Having covered numerous ways to **capture** credentials, the focus now shifts to **defense** — creating and enforcing password policies that actually work.

> 🚗 Analogy: Traffic laws exist so driving is safe and predictable. Without password policies, users act without constraints and the environment becomes chaotic.

### Two Essential Components

| Component | Description |
|-----------|-------------|
| **Definition** | The written rules and expectations for password creation |
| **Enforcement** | The technology that ensures compliance |

Both are required — a policy without enforcement is just a suggestion.

---

## What Is a Password Policy?

A **password policy** is a set of rules designed to enhance security by encouraging strong password creation and usage. Its scope goes beyond minimum requirements to cover the entire password lifecycle:

- Creation
- Storage
- Management
- Transmission (in flight)

---

## Password Policy Standards

Major compliance frameworks include password policy guidance. The most commonly referenced:

| Standard | Focus |
|----------|-------|
| **NIST SP 800-63B** | Modern guidance — de-emphasizes expiration, emphasizes length + deny-lists |
| **CIS Password Policy Guide** | Practical baseline for enterprises |
| **PCI DSS** | Required for handling payment card data |

> ⚠️ **Compliance ≠ security.** These standards are baselines, not guarantees.

### Controversial Example: Password Expiration

- ❌ **Old practice:** "Change your password every 90 days"
- ✅ **Modern practice (NIST):** **Don't force expiration** unless there's evidence of compromise
- 🔎 **Why changed:** Forced rotation leads to **predictable patterns** (`Summer2024!` → `Summer2025!`)

---

## Sample Password Policy

A baseline policy might require passwords to:

- Be a **minimum of 8 characters**
- Include **uppercase** and **lowercase** letters
- Include at least **one number**
- Include at least **one special character**
- **Not** match the username
- Be changed every **60 days**

### Why This Sample Policy Still Fails

Meet **Mark**, a new Inlanefreight employee:

- ❌ `password123` — rejected (fails minimum requirements)
- ✅ `Inlanefreight01!` — accepted

**But this is still weak!** Why?

- Contains the **company name** (known to attackers)
- Predictable mutation pattern (covered in "Password Mutations")
- When forced to rotate, Mark changes `01` → `02` → `03` while technically complying

---

## 🚫 Password Blacklists (Deny-Lists)

A good policy should **reject** these patterns outright:

| Category | Examples |
|----------|----------|
| **Company identifiers** | Company name, product names, acronyms |
| **Industry terms** | Words associated with the company's business |
| **Time references** | Months (`January`, `August`) |
| **Seasons** | `Winter`, `Summer`, `Fall`, `Autumn`, `Spring` |
| **"Welcome" / "Password" variants** | `Welcome1`, `P@ssword`, `Passw0rd!` |
| **Common weak passwords** | `123456`, `abcde`, `qwerty`, `letmein` |
| **Keyboard walks** | `qwerty`, `asdfgh`, `1q2w3e4r` |

> 💡 Use a **real-world breach corpus** (e.g., HaveIBeenPwned, rockyou.txt) as the deny-list source.

---

## Enforcing the Policy

Writing the policy is half the work — **enforcement** makes it real.

### Technical Enforcement

| Platform | Enforcement Mechanism |
|----------|----------------------|
| **Active Directory** | GPO — *Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy* |
| **Fine-Grained AD Policies (FGPP)** | Per-group overrides via PSOs |
| **Azure AD / Entra ID** | Password Protection + banned password list |
| **Linux (PAM)** | `pam_pwquality` / `pam_cracklib` |
| **Web apps** | Application-layer validation (zxcvbn, custom regex + deny-list) |

### Process Enforcement

- Communicate the policy to all users
- Build onboarding/offboarding procedures around it
- Integrate with **identity management systems**
- Periodically audit password quality (e.g., DSInternals, hashcat against a domain dump)

---

## Creating Strong Passwords

### Option 1: Generated Random Passwords

Tools like **PasswordMonster** (strength evaluator) and the **1Password Password Generator** produce strings like:

```
CjDC2x[U
```

- ✅ Very strong (estimated crack time: ~1,000 years)
- ❌ Hard to remember → drives users toward reuse or post-it notes

### Option 2: Passphrases (Recommended by NIST)

Ordinary words, phrases, or lyrics chained together:

| Example | Strength |
|---------|----------|
| `The name of my dog is Popy` | Very strong (~381 trillion years) |
| `()The name of my dog is Popy!` | Stronger still with added symbols |
| `This is my secure password` | Strong due to length alone |

> ⚠️ **OSINT caveat:** Attackers can research you. Avoid phrases tied to:
> - Pet names on social media
> - Kids' / spouse's names
> - Favorite bands
> - Anniversary dates

### Why Passphrases Win

- **Length > complexity** for defeating brute force
- **Easier to remember** → less reuse
- **Harder to shoulder-surf** than short random strings

---

## The Scalability Problem

Even with great passphrases, users can't remember **hundreds** of them. This is where **password managers** come in — covered in the next section.

---

## Policy Checklist

- [ ] **Minimum length** ≥ 12 characters (NIST recommends 8 min, longer preferred)
- [ ] **Character complexity** requirements (or dropped in favor of length per NIST)
- [ ] **Deny-list** of breached / common / company-related passwords
- [ ] **Username ≠ password** enforcement
- [ ] **Expiration disabled** unless compromise suspected (NIST) or risk-based
- [ ] **Breach monitoring** (HaveIBeenPwned API integration)
- [ ] **MFA required** (policies alone are insufficient)
- [ ] **Password manager** sanctioned and provided
- [ ] **Offboarding procedure** for password/credential revocation
- [ ] **Audit mechanism** (periodic hash dumps → cracking tests)

---

## Key Takeaways

1. **Policy = definition + enforcement** — both are required
2. **Compliance is a floor, not a ceiling** — meeting PCI DSS doesn't mean you're secure
3. **NIST SP 800-63B** is the modern gold standard: **length > complexity**, no forced rotation
4. **Forced expiration is harmful** — leads to `Summer2025!` / `CompanyName02!` patterns
5. **Deny-lists are essential** — block company names, seasons, months, common passwords
6. **AD password policies** are enforced via GPO (+ FGPP for granular control)
7. **Passphrases beat random strings** for most users — easier to remember, resistant to brute force
8. **OSINT** makes personal-detail passwords trivial to guess — avoid dog names, birthdays, etc.
9. Even perfect policies fail without **MFA** layered on top
10. **Users can't remember 100 strong passwords** → **password managers** are the solution

---

## References

- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [CIS Password Policy Guide](https://www.cisecurity.org/insights/white-papers/cis-password-policy-guide)
- [PCI DSS](https://www.pcisecuritystandards.org/)
- [HaveIBeenPwned](https://haveibeenpwned.com/)
- [PasswordMonster](https://www.passwordmonster.com/)
- [1Password Generator](https://1password.com/password-generator/)
- [zxcvbn (strength estimator)](https://github.com/dropbox/zxcvbn)
