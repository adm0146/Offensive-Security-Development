# Section 2 — Password Security Fundamentals

> Theory only. No lab.

---

## Strong Password Characteristics

| Factor | Guideline |
|--------|-----------|
| **Length** | 12+ characters minimum — each extra character exponentially increases combinations |
| **Complexity** | Mix uppercase, lowercase, numbers, symbols — expands the per-character pool |
| **Uniqueness** | One password per account — breach on one doesn't cascade |
| **Randomness** | No dictionary words, personal info, or common phrases |

**Why length beats complexity:** A 6-character lowercase password has about 300 million possible combinations. An 8-character one has 200 billion. Same character set, two extra characters, 667 times harder to crack.

---

## Common Password Weaknesses (What to Look For)

- Fewer than 8 characters
- Dictionary words or names
- Personal info (birthdate, pet, address)
- Reused across accounts
- Predictable patterns: `qwerty`, `123456`, `p@ssw0rd`

---

## Password Policies (What Defenders Set)

| Policy | Purpose |
|--------|---------|
| Minimum length | Force longer passwords |
| Complexity requirements | Force mixed character types |
| Expiration | Force periodic changes |
| Password history | Prevent reuse of old passwords |

> **Pentester note:** Strict policies often lead to *predictable behavior* — users append `!1` to old passwords, cycle through minor variations, write them down. Hybrid attacks exploit this.

---

## Default Credentials — High-Value Targets

Default creds are pre-set by manufacturers and rarely changed. Always try these before launching a full brute force.

| Device | Username | Password |
|--------|----------|----------|
| Linksys / D-Link / TP-Link / Asus Router | admin | admin |
| Netgear / Belkin Router | admin | password |
| Cisco Router | cisco | cisco |
| Zyxel Router | admin | 1234 |
| Samsung SmartCam | admin | 4321 |
| Hikvision DVR / Panasonic DVR | admin | 12345 |
| Axis IP Camera | root | pass |
| Ubiquiti UniFi AP | ubnt | ubnt |
| Canon Printer | admin | admin |
| Honeywell Thermostat | admin | 1234 |

**SecLists default credential wordlists:**
```
~/SecLists/Passwords/Default-Credentials/default-passwords.csv
~/SecLists/Usernames/top-usernames-shortlist.txt
```
> The CSV file has `user:pass` pairs for common devices. The username shortlist covers the 17 most common admin account names. Use both with Hydra or Medusa when attacking routers, cameras, or IoT (Internet of Things) devices.

---

## Pentester Takeaways

| Situation | Approach |
|-----------|----------|
| No password policy | Simple dictionary attack (rockyou.txt) likely sufficient |
| Strict policy with lockouts | Spray with a tiny list; hybrid attack on known patterns |
| IoT / network devices | Try default creds first — high hit rate |
| Known username | Skip username brute force entirely, focus on password |
| Default username unchanged | Attack surface is halved — password only |
