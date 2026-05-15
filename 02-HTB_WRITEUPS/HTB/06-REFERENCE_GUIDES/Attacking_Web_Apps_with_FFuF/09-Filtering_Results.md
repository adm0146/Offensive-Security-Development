# Section 9 — Filtering Results

> Use ffuf's filter/match flags to cut noise and surface real hits — demonstrated via vhost fuzzing academy.htb.

---

## Lab Answer

| Question | Answer |
|----------|--------|
| Other VHosts found on academy.htb | `admin` and `test` (i.e. admin.academy.htb, test.academy.htb) |

---

## Filter vs. Match Flags

```
MATCHERS — keep responses that match:        FILTERS — drop responses that match:
  -mc  status code                             -fc  status code
  -ml  line count                              -fl  line count
  -mr  regexp                                  -fr  regexp
  -ms  response size (bytes)                   -fs  response size (bytes)
  -mw  word count                              -fw  word count
```

**Rule of thumb:**
- Use **matchers** when you know what a hit looks like (e.g., `-mc 200`)
- Use **filters** when you know what a miss looks like (e.g., `-fs 986` to drop the default page)

For vhost fuzzing, filters are the right choice. You don't know the real vhost's size yet, but you do know the default "catch-all" size after one curl probe.

---

## The Two-Step Vhost Workflow

**Step 1 — Find the default response size:**
```bash
curl -s -o /dev/null -w "%{size_download}" \
  -H 'Host: totallyfake123.academy.htb' \
  http://TARGET_IP:PORT/
# Returns: 986  ← this is the noise size
```
> Sends a request for a fake vhost to measure the default "not found" response size. `-o /dev/null` discards the body; `-w "%{size_download}"` prints only the byte count. Use this number with `-fs` in the next step.

**Step 2 — Fuzz filtering out that size:**
```bash
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://TARGET_IP:PORT/ \
  -H 'Host: FUZZ.academy.htb' \
  -fs 986 \
  -t 100
# Returns only: admin, test  ← real vhosts with different content
```
> `-fs 986` removes every 986-byte default response. Only vhosts with different content (different size) survive the filter. The result is a short list of real vhosts.

---

## After Finding Vhosts

```bash
# Add to /etc/hosts:
sudo sh -c 'echo "TARGET_IP  admin.academy.htb test.academy.htb" >> /etc/hosts'

# Visit and enumerate further:
curl -s http://admin.academy.htb:PORT/
ffuf -w ~/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ \
  -u http://admin.academy.htb:PORT/FUZZ \
  -recursion -recursion-depth 1 -e .php -v -ic -t 100
```
> After adding the vhosts to `/etc/hosts`, curl the root to see what's there, then immediately start recursive directory fuzzing on the new vhost. Each new vhost is treated as a fresh target.

---

## Auto-Calibration Alternative

Instead of manually finding the default size, use `-ac` to let ffuf calibrate automatically:

```bash
ffuf -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://TARGET_IP:PORT/ \
  -H 'Host: FUZZ.academy.htb' \
  -ac -t 100
```
> `-ac` replaces the manual curl-probe step. ffuf sends a few baseline requests itself, measures the default response, and filters it automatically. Cleaner and faster than finding `-fs` by hand.

`-ac` sends a few probe requests first. It measures the baseline response, then automatically filters anything that matches it.

---

## Exam Notes

- Default ffuf only filters 404 — everything else comes through; use `-fs`/`-fw`/`-fl` to cut noise
- For vhost fuzzing: probe a fake vhost first with curl to get the baseline size, then `-fs` that size
- `test.academy.htb` is often present in HTB labs as a second vhost alongside `admin` — fuzz both
- After finding vhosts, always add them to `/etc/hosts` and re-enumerate with dir/page fuzzing
- `-ac` is a clean alternative to manual `-fs` when you don't want to probe first
