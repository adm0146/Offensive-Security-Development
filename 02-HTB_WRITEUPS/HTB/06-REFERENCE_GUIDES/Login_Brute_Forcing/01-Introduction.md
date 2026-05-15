# Section 1 — Introduction

> Theory only. No lab.

---

## What is Brute Forcing?

Brute forcing means trying every possible combination of credentials until you find the right one. How well it works depends on three things:

- **Password complexity** — longer passwords with mixed characters take exponentially longer to crack
- **Attacker compute** — modern hardware can try billions of combinations per second
- **Target defenses** — lockouts, CAPTCHAs, and rate limiting can slow or block the attack

---

## Attack Types

| Method | How It Works | Best When |
|--------|-------------|-----------|
| **Simple Brute Force** | Try every character combination | No info about password, lots of compute |
| **Dictionary Attack** | Try passwords from a wordlist (e.g. rockyou.txt) | Target likely uses a common/weak password |
| **Hybrid Attack** | Dictionary words + appended numbers/symbols | Target uses a slightly modified common password |
| **Credential Stuffing** | Use leaked creds from one service on another | Large breach dump available, user reuse suspected |
| **Password Spraying** | Few common passwords against many usernames | Lockout policies exist — spread attempts to avoid triggering |
| **Rainbow Table** | Pre-computed hash tables to reverse hashes | Large number of hashes to crack, storage available |
| **Reverse Brute Force** | One password, many usernames | Strong suspicion a specific password is reused |
| **Distributed** | Split workload across many machines | Complex target, single machine too slow |

---

## When Brute Forcing Is Used in Pentesting

- Other access methods (exploits, social engineering) failed
- Weak password policies make guessing viable
- Specific high-value accounts are being targeted (e.g. admin, domain admin)

---

## Exam Notes

- **Spraying** = few passwords, many users → use when lockout policies exist
- **Stuffing** = known leaked creds → always try these first if you have a breach list
- **Dictionary** = most common attack in this module — rockyou.txt is the default wordlist
- Account lockout thresholds matter — know the policy before blasting
