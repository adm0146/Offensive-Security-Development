# Section 1 — Introduction to Attacking Common Applications

> Theory only. No lab.

---

## Module Premise

External perimeters are getting smaller. Workstations and APIs are getting harder to attack directly. **Web applications** — especially common off-the-shelf ones — are increasingly the path of least resistance, both externally (internet-exposed admin panels) and internally (intranet portals, dev tools).

A pentester needs to know how to:
1. **Identify** common apps (fingerprint by paths, headers, favicon hashes)
2. **Find** public CVEs for the version detected
3. **Abuse built-in functionality** when no CVE applies — admin features in these apps often grant code execution by design

Last skill is the one this module hammers on. Most of these apps have a "run script" or "execute Groovy" or "test SQL connection" feature that hands you RCE if you can log in.

---

## Application Categories Covered

| Category | Examples | Module covers |
|----------|----------|---------------|
| **CMS** | WordPress, Drupal, Joomla, DotNetNuke | WordPress, Drupal, Joomla |
| **App servers** | Tomcat, JBoss, WebLogic, WebSphere | Tomcat |
| **CI/CD** | Jenkins, GitLab CI, Azure Pipelines | Jenkins, GitLab |
| **SIEM** | Splunk, LogRhythm, ArcSight | Splunk |
| **Network monitoring** | PRTG, OpManager, Nagios | PRTG |
| **Ticketing** | osTicket, Zendesk, JIRA Service Desk | osTicket |
| **Code repos** | GitLab, Gitea, Bitbucket, GitHub Enterprise | GitLab |

The 9 apps the module focuses on: **WordPress, Drupal, Joomla, Tomcat, Jenkins, Splunk, PRTG, osTicket, GitLab**.

---

## Why These Apps Are Reliable Targets

| Trait | Consequence |
|-------|-------------|
| Default credentials remain unchanged | First login attempt often succeeds (`admin:admin`, `admin:admin123`, `tomcat:s3cret`) |
| Frequent CVEs with public exploits | Unpatched installs are common, especially internal "we don't expose this" deployments |
| Plugin/extension ecosystem | Third-party plugins multiply the attack surface; CMS cores are often patched but plugins aren't |
| "Run script" admin features | RCE is a documented feature, not a vulnerability — once authenticated, it's intended |
| Run as privileged accounts | Tomcat/Jenkins/PRTG often run as `SYSTEM` or `root` — no privesc needed |
| Stored secrets | These apps house DB creds, API keys, customer data — even read-only access is high-value |

---

## Common Abuse Patterns (Preview)

### Default creds
```
admin:admin            (Tomcat manager-app — many installs)
admin:admin123         (Nexus OSS — story in the section)
admin:prtgadmin        (PRTG older versions)
admin:changeme         (Jenkins older installs)
```

### Built-in code execution features (post-auth)
| App | Feature | Yields |
|-----|---------|--------|
| Jenkins | Script Console (Groovy) | RCE |
| WordPress | Theme/Plugin editor | RCE |
| Joomla | Template editor | RCE |
| Drupal | PHP filter (older versions) | RCE |
| Tomcat | manager-app WAR deploy | RCE |
| PRTG | Notification "Execute Program" | RCE |
| osTicket | File upload via ticket attachment | (sometimes) RCE |
| GitLab | CI pipeline YAML | RCE |
| Splunk | Custom search command / app upload | RCE |

These features exist for legitimate admin reasons — they're attacker-friendly because **most installs don't lock them down**.

---

## The Mindset

> "Approach all applications with a critical eye and assess them for public vulnerabilities and misconfigurations."

For every app encountered, ask:
1. What version is this? Are there public CVEs?
2. What are the default credentials? Have they been changed?
3. What admin features exist that could lead to file write / code execution?
4. What does the app run as? (`whoami` after foothold tells you who owns the box)
5. What's stored in it? (creds, source code, customer PII, secrets)
6. Can I pivot from here? (linked services, SSO trust, network access)

This same checklist works for apps you've never seen before.

---

## Module Lab Setup

The module uses **vhosts** to simulate a realistic environment — multiple apps on different hostnames mapped to one IP.

```bash
IP=10.129.42.195
printf "%s\t%s\n\n" "$IP" "app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local" | sudo tee -a /etc/hosts
```
> Maps the lab vhosts to the target IP in `/etc/hosts`; swap `IP` and the hostname list to match your target.

`/etc/hosts` becomes:
```
10.129.42.195   app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local
```

Each section that uses vhosts lists which hostnames to add. Sections that target a bare IP+port (Splunk) don't need this.

### Pitfall
If a section's screenshots show a FQDN and you can't reach it — first thing to check is `/etc/hosts`. Vhost-routed Apache returns the wrong site (or 404) for direct IP access.

### My setup helper
For repeated module work:
```bash
# Clean previous lab vhost entries
sudo sed -i '/inlanefreight.local/d' /etc/hosts
# Add fresh ones for new target
IP=<new_ip>
echo "$IP   app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local" | sudo tee -a /etc/hosts
```
> Resets stale lab vhost entries then re-adds them for a fresh target; swap `<new_ip>` and the hostname list as needed.

---

## The Story (from the Module)

The author's anecdote about Nexus Repository OSS is the canonical pattern this module teaches:
1. Encountered an unfamiliar app
2. Tried default creds (`admin:admin123`) → worked
3. Explored admin features
4. Found Groovy script execution → RCE

**Lesson:** if you don't recognize the app, it doesn't matter. Default creds + admin abuse will probably still work.

---

## Module Roadmap

```
01      Introduction (this)
02-03   Discovery basics — finding apps, identifying versions
04-08   WordPress
09-12   Drupal
13-15   Joomla
16-18   Tomcat
19-21   Jenkins
22-23   Splunk
24-25   PRTG
26-27   osTicket
28-30   GitLab
31-33   Skills assessments
```

Each app section follows a similar pattern: **enumerate → identify version → check default creds → find built-in RCE path OR exploit public CVE**.

---

## Exam Notes

- This module covers 9 apps that appear across most CPTS engagements — high probability one of them is on the exam target list
- Default credentials are the #1 attack — always try them before anything else
- Built-in admin features = RCE is the recurring theme — `manager-app` (Tomcat), Script Console (Jenkins), Theme Editor (WordPress), etc.
- Public CVE exploitation is secondary — if creds work, you skip CVE hunting entirely
- Most of these apps run as elevated accounts — RCE = SYSTEM/root in many cases
- For unfamiliar apps: try default creds, then look for "run script" or "execute" or "deploy" features in the admin UI
