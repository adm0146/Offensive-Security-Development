# Section 3 — Proxy Setup

> Three ways to route browser traffic through a proxy. CA cert install is required for HTTPS.

---

## Option 1 — Pre-Configured Browser (Fastest, Use This First)

Both tools include a built-in browser with the proxy and CA cert pre-configured. No setup needed.

```
Burp:  Proxy → Intercept → "Open Browser"
ZAP:   Click the Firefox icon in the top toolbar
```

Use this for quick tests. Use your real browser when you need extensions or saved sessions.

---

## Option 2 — FoxyProxy (Best for Real Firefox)

FoxyProxy is a Firefox extension that lets you toggle the proxy on/off with one click instead of digging through Firefox settings every time.

**On PwnBox:** Already installed and configured — just click the FoxyProxy icon and select Burp or ZAP.

**On your own machine:**
1. Install FoxyProxy from the Firefox Extensions page
2. Click the FoxyProxy icon → Options → Add
3. Fill in:
   - IP: `127.0.0.1`
   - Port: `8080`
   - Title: `Burp` (or `ZAP`)
4. Click Save
5. To activate: click FoxyProxy icon → select the profile you just created
6. To deactivate: click FoxyProxy icon → select "Disable"

**Change the proxy port if 8080 is in use:**
```
Burp: Proxy → Proxy Settings → Proxy Listeners
ZAP:  Tools → Options → Network → Local Servers/Proxies
```
Make sure Firefox's FoxyProxy profile matches whatever port you set.

---

## Option 3 — Manual Firefox Proxy (No Extension)

```
Firefox → Settings → search "proxy" → Settings...
→ Manual proxy configuration
   HTTP Proxy: 127.0.0.1   Port: 8080
   ✅ Use this proxy for HTTPS too
→ OK
```

This is slower to toggle on/off — use FoxyProxy instead.

---

## Installing CA Certificates (Required for HTTPS)

Without this, Firefox will show a certificate error on every HTTPS site, or traffic won't route at all.

### Burp CA Certificate

```
1. Enable Burp proxy in FoxyProxy
2. Browse to: http://burp
3. Click "CA Certificate" to download it (cacert.der)
```

### ZAP CA Certificate

```
1. ZAP → Tools → Options → Network → Server Certificates
2. Click "Save" to export the certificate
```

### Install in Firefox (same steps for both)

```
1. Firefox → Settings → search "certificates" → View Certificates
2. Authorities tab → Import
3. Select the downloaded certificate file
4. Check both:
   ✅ Trust this CA to identify websites
   ✅ Trust this CA to identify email users
5. OK → OK
```

After this, all HTTPS traffic routes cleanly through the proxy with no warnings.

---

## Quick Checklist

- [ ] FoxyProxy installed and profile created (127.0.0.1:8080)
- [ ] CA certificate downloaded from Burp (`http://burp`) or ZAP (Tools → Options)
- [ ] CA certificate installed in Firefox (Authorities tab → Import)
- [ ] FoxyProxy toggled ON
- [ ] Test: browse any site in Firefox → check Burp's HTTP History or ZAP's History tab for requests

---

## Exam Notes

- On PwnBox, FoxyProxy and CA certs are already configured — just click FoxyProxy → Burp/ZAP
- Always toggle FoxyProxy OFF when not actively proxying — browsing with it on and Burp closed will break Firefox
- `http://burp` only works when FoxyProxy is pointing at Burp — it's Burp's built-in page, not a real website
- Both tools default to port 8080. If something else is on 8080, change it in the proxy listener settings first, then update FoxyProxy to match
- HTTPS requires CA cert installed — this is the most common "nothing is showing up in Burp" mistake
