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

**Key insight:** One IP address can serve many different websites. Each site has its own `Host:` header value. Vhost fuzzing sends every wordlist entry as the `Host:` header value to find them all.

---

## The Command

```bash
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://academy.htb:PORT/ \
  -H 'Host: FUZZ.academy.htb' \
  -t 100
```
> `-u` is the actual IP destination — all requests hit the same server. `-H 'Host: FUZZ.academy.htb'` changes only the header, which is what the server uses to route to the right virtual host. This finds vhosts that have no DNS record.

- `-u` points to the known IP/domain — the actual destination for every request
- `-H 'Host: FUZZ.academy.htb'` — the header is what changes per request
- All requests hit the same IP; the server routes based on the `Host:` value

---

## The Noise Problem and How to Fix It

If a vhost doesn't exist, the server serves the default page instead. That means every single wordlist entry returns 200 OK with the same size. You get thousands of false positives.

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
> `-fs 900` removes every response that is exactly 900 bytes — the default "catch-all" page size found in the step above. Any response with a different size is a real vhost with actual content.

Any result with a different size is a real vhost.

---

## After Finding a Vhost

Add it to `/etc/hosts` to browse it:
```bash
sudo sh -c 'echo "TARGET_IP  admin.academy.htb" >> /etc/hosts'
```
> Adds the discovered vhost to `/etc/hosts` so your browser can resolve it. Replace `TARGET_IP` with the actual IP of the HTB box.

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
  > `-ac` probes a fake vhost automatically, measures the default response, and filters it out — no need to run a manual curl step first.
