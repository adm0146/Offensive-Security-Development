# Section 8 — Vhost Fuzzing

> Concepts only. No lab. Fuzz the Host: header to discover internal/non-public vhosts on a known IP.

---

## Vhosts vs. Sub-domains

| | Sub-domain Fuzzing | Vhost Fuzzing |
|--|---|---|
| Method | DNS resolution (`FUZZ.domain.com`) | `Host:` header manipulation |
| Finds | Public subdomains only | Public AND internal vhosts |
| Works on HTB targets | No | Yes |
| Requires DNS | Yes | No — hits the IP directly |

**Key insight:** A server at one IP can host multiple sites, each responding to a different `Host:` header. Vhost fuzzing probes those by sending every wordlist entry as the `Host:` value.

---

## The Command

```bash
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://academy.htb:PORT/ \
  -H 'Host: FUZZ.academy.htb' \
  -t 100
```

- `-u` points to the known IP/domain — the actual destination for every request
- `-H 'Host: FUZZ.academy.htb'` — the header is what changes per request
- All requests hit the same IP; the server routes based on the `Host:` value

---

## The Noise Problem and How to Fix It

An unconfigured vhost will fall through to the default page — so every wordlist entry returns 200 OK with the same response size. You'll get thousands of false positives.

**Step 1:** Run without a filter to find the default response size:
```
mail2   [Status: 200, Size: 900, Words: 423, Lines: 56]
dns2    [Status: 200, Size: 900, Words: 423, Lines: 56]
# All returning size 900 → that's the default "not found" response
```

**Step 2:** Re-run with `-fs` to filter out that size:
```bash
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://academy.htb:PORT/ \
  -H 'Host: FUZZ.academy.htb' \
  -fs 900 \
  -t 100
```

Any result with a different size = a real vhost.

---

## After Finding a Vhost

Add it to `/etc/hosts` to browse it:
```bash
sudo sh -c 'echo "TARGET_IP  admin.academy.htb" >> /etc/hosts'
```

Then visit `http://admin.academy.htb:PORT/` in the browser.

---

## Exam Notes

- Always use vhost fuzzing (not subdomain fuzzing) for HTB/internal targets
- First run without `-fs` to identify the default response size, then filter it out
- The real vhost will have a noticeably different size — often much larger (actual page content) or smaller (redirect)
- After adding the vhost to `/etc/hosts`, re-enumerate it: dir fuzzing, page fuzzing, etc.
- Use `-ac` (auto-calibrate) as an alternative to manually finding and filtering the default size:
  ```bash
  ffuf -w WORDLIST:FUZZ -u http://TARGET/ -H 'Host: FUZZ.academy.htb' -ac
  ```
