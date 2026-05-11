# Section 2 — Setting Up

> Installation and launch. Both tools are pre-installed on Kali/Parrot/PwnBox — skip the install steps on exam day.

---

## Launching the Tools

```bash
burpsuite    # launch Burp from terminal
zaproxy      # launch ZAP from terminal

# JAR alternative (if not installed, or using downloaded JAR):
java -jar /path/to/burpsuite.jar
java -jar /path/to/zap.jar
```

Both tools require Java (JRE). Pre-installed on Kali — no action needed.

---

## Burp Suite First-Run

1. **Project type:** Select **Temporary project** (Community Edition doesn't support saving to disk — Pro/Enterprise does)
2. **Configuration:** Select **Use Burp defaults** → click **Start Burp**

That's it. You'll be at the main Burp dashboard.

**When you'd save a project (Pro only):** Long-running assessments against large apps, or when you're running the Active Scanner and want to resume later. For most work, temporary is fine.

---

## ZAP First-Run

1. When prompted about session persistence → choose **No** (don't persist) for temporary work
2. ZAP opens directly — no project config needed

**ZAP advantage here:** Even the free version lets you save sessions. Burp requires Pro for that.

---

## Optional: Dark Theme

```
Burp: Burp → Settings → User Interface → Display → Theme: Dark
ZAP:  Tools → Options → Display → Look and Feel: Flat Dark
```

---

## Exam Notes

- On the CPTS exam PwnBox, both tools are already installed — just type `burpsuite` or `zaproxy`
- Always use **Temporary Project** in Community Edition — disk projects are Pro-only
- If Burp is slow to start, it's loading the JVM — give it 10-15 seconds
- Both tools default to listening on `127.0.0.1:8080` — the browser proxy settings in the next section point there
