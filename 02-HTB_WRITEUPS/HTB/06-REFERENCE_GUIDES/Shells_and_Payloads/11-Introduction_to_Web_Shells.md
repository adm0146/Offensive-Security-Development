# 11 — Introduction to Web Shells

## Overview

Web applications dominate modern infrastructure. External penetration tests increasingly rely on web-based attacks to gain initial access because perimeter networks are well-hardened — vulnerable services like SMB are rarely exposed externally anymore.

---

## Why Web Shells Matter

| Context | Reality |
|---------|---------|
| **External pentests** | Web apps are often the primary attack surface |
| **Perimeter hardening** | SMB, RDP, and other services are typically blocked externally |
| **Initial access methods** | File upload attacks, SQLi, RFI/LFI, command injection, password spraying |
| **Modern apps** | Everything is web-based — streaming, gaming, enterprise software |

> On external engagements, the most common ways "in" are:
> - Web application attacks (file upload, SQLi, RFI/LFI, command injection)
> - Password spraying (RDS, VPN portals, Citrix, OWA, AD-authenticated apps)
> - Social engineering

---

## What is a Web Shell?

A **web shell** is a browser-based shell session used to interact with the underlying operating system of a web server.

| Characteristic | Description |
|----------------|-------------|
| **Delivery** | Upload a payload written in a web language (PHP, JSP, ASP.NET) |
| **Execution** | Payload provides remote code execution via the browser |
| **Access method** | Navigate to the uploaded file in a browser to execute commands |
| **Limitation** | Can be unstable — some apps delete uploads after a period of time |

---

## How Web Shells Are Gained

To gain RCE via web shell, you must first find a vulnerability or misconfiguration that allows file upload.

### Common Upload Vectors

| Vector | Description |
|--------|-------------|
| **Public file upload forms** | Directly upload PHP/JSP/ASPX shells |
| **Profile picture uploads** | Self-registration features with image upload (bypass client-side checks) |
| **Application managers** | Tomcat, Axis2, WebLogic — deploy JSP via WAR files |
| **Misconfigured FTP** | FTP allows uploads directly to the webroot |
| **CMS vulnerabilities** | WordPress, Joomla, Drupal plugin/theme uploads |
| **Authenticated features** | Document upload, attachment features after login |

---

## Web Shell Workflow

```
1. Identify upload vulnerability or misconfiguration
          ↓
2. Upload payload (PHP, JSP, ASP.NET web shell)
          ↓
3. Navigate to uploaded file in browser
          ↓
4. Execute commands via web interface
          ↓
5. Upgrade to reverse shell for persistence
```

---

## Web Shell vs Reverse Shell

| Aspect | Web Shell | Reverse Shell |
|--------|-----------|---------------|
| **Access** | Through browser | Direct terminal connection |
| **Stability** | Less stable (files may be deleted) | More stable |
| **Persistence** | Temporary | Better for maintaining access |
| **Interaction** | Limited (HTTP request/response) | Full interactive shell |
| **Use case** | Initial foothold | Long-term access |

> **Best Practice:** Use web shell to gain initial RCE, then upgrade to a reverse shell for persistence and stability.

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **External pentests** | Web apps are the primary attack surface |
| **Web shell** | Browser-based shell via uploaded payload |
| **File upload** | Required vulnerability to deploy web shell |
| **Instability** | Web shells can be deleted — upgrade to reverse shell |
| **Common languages** | PHP, JSP, ASP.NET depending on the server |
| **Upgrade path** | Web shell → Reverse shell for persistence |
