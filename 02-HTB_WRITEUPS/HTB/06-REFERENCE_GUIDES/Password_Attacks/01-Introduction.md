# 01 — Introduction

## Overview

Password Attacks focuses on compromising the **authentication** tenet of security. Authentication validates identity before granting access — and passwords remain the most common (and most attackable) authentication factor. This section establishes the fundamentals of authentication, password usage, and why passwords remain a high-value target.

---

## The CIA Triad & Authentication

| Principle | Role |
|-----------|------|
| **Confidentiality** | Only authorized users access resources |
| **Integrity** | Data is not tampered with |
| **Availability** | Resources are accessible when needed |
| **Authentication** | Verifies identity — the gatekeeper for all three |

---

## Authentication Factors

| Factor | Category | Examples |
|--------|----------|----------|
| **Something you know** | Knowledge | Password, PIN, passphrase, passcode |
| **Something you have** | Possession | Smart card, CAC, trusted phone, hardware token |
| **Something you are** | Inherence | Fingerprint, face recognition, iris, voice |
| **Somewhere you are** | Location | Geolocation, IP address |

> Organizations choose how many factors to require based on the sensitivity of the data. Medical systems (e.g., patient data) often require CAC + PIN + authenticator app.

### Authentication vs Authorization

| Concept | Definition |
|---------|------------|
| **Authentication** | Proving you are who you claim to be |
| **Authorization** | The permissions granted after successful authentication |

---

## Password Statistics

### Google/Harris Poll (2019)

| Statistic | Value |
|-----------|-------|
| Used `123456`, `qwerty`, or `password` | **24%** of Americans |
| Used their own name | **22%** |
| Used pet/children's name | **33%** |
| Reused passwords across multiple accounts | **66%** |
| Used a password manager | **15%** |
| Would change password after a breach | **45%** |

### Panda Security (2025)

| Statistic | Value |
|-----------|-------|
| Most common password | `123456` (4.5M breach appearances) |
| Reuse across 3+ accounts | **23%** |
| Use password managers | **36%** (up from 15% in 2019) |

---

## Why This Matters for Attackers

| Insight | Implication |
|---------|-------------|
| 66% password reuse | One cracked password → likely access to multiple platforms |
| 55% don't change after breach | Leaked credentials remain valid long-term |
| Common passwords dominate | Dictionary/wordlist attacks are highly effective |
| Password managers still minority | Most users have weak or predictable passwords |

### Breach Checking

| Resource | Purpose |
|----------|---------|
| [HaveIBeenPwned](https://haveibeenpwned.com) | Check if email/password appeared in known breaches |

---

## Password Complexity Math

For an 8-character password using only uppercase letters + digits:

$$36^8 = 208{,}827{,}064{,}576 \text{ possible combinations}$$

> Realistically, passwords can be anything — song lyrics, book quotes, concatenated words (`TreeDogEvilElephant`). The key is meeting the organization's security standards.

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **Authentication = identity verification** | Knowledge, possession, inherence, location |
| **Passwords are the weakest link** | Most common factor, most commonly attacked |
| **Password reuse is the #1 attacker advantage** | One credential → many accounts |
| **Convenience vs security** | MFA adds friction but dramatically improves security |
| **Breached passwords stay in use** | Over half of users never change them |
| **This module attacks authentication** | Across OSes, applications, and encryption methods |
