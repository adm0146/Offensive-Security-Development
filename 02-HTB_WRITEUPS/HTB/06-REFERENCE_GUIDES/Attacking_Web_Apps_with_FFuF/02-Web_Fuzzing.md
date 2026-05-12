# Section 2 — Web Fuzzing

> Concepts section. No lab. Explains the fuzzing idea and the wordlists used throughout the module.

---

## The Core Concept

Web servers don't publish a list of all their pages. Fuzzing = sending requests for every word in a wordlist and seeing which ones return something real (200 OK) vs not found (404).

```
Request: GET /FUZZ HTTP/1.1          (ffuf replaces FUZZ with each wordlist line)
Hit: /admin        → 200 OK   ← page exists
Miss: /doesnotexist → 404     ← page doesn't exist
```

---

## Key Wordlists for This Module

All SecLists at `/opt/useful/SecLists/` (PwnBox) or `~/SecLists/` (Kali).

| Wordlist | Path | Use |
|----------|------|-----|
| `directory-list-2.3-small.txt` | `Discovery/Web-Content/directory-list-2.3-small.txt` | Quick directory scan (~87k entries) |
| `directory-list-2.3-medium.txt` | `Discovery/Web-Content/directory-list-2.3-medium.txt` | Thorough directory scan (~220k entries) |
| `web-extensions.txt` | `Discovery/Web-Content/web-extensions.txt` | File extension fuzzing |
| `subdomains-top1million-5000.txt` | `Discovery/DNS/subdomains-top1million-5000.txt` | Vhost/subdomain fuzzing |
| `burp-parameter-names.txt` | `Discovery/Web-Content/burp-parameter-names.txt` | Parameter name fuzzing |

---

## ffuf Basics

```bash
ffuf -w WORDLIST -u http://TARGET/FUZZ

# -w = wordlist path
# -u = URL with FUZZ as the injection point
# -ic = ignore comments in wordlist (lines starting with #)
```

**-ic flag is important:** The directory-list-2.3 wordlists start with copyright comment lines. Without `-ic`, those comment lines become part of the fuzzing — they'll all 404 but clutter results.

```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt \
     -u http://SERVER_IP:PORT/FUZZ \
     -ic
```

---

## Exam Notes

- Always use `-ic` with directory-list-2.3 wordlists — skips the copyright comments at the top
- `FUZZ` is case-sensitive — must be uppercase exactly as written
- On Kali: wordlists are at `~/SecLists/` | On PwnBox: `/opt/useful/SecLists/`
- 200 = exists | 301/302 = redirect (also interesting) | 403 = exists but forbidden | 404 = not found
