# Saving and Converting Nmap Results

## Overview

While running various Nmap scans is essential, **saving the results** is equally important for:
- Documenting findings for reports
- Comparing results between different scanning methods
- Creating client-ready HTML reports
- Archiving scan data for future reference
- Non-technical stakeholder presentations

Nmap supports **3 primary output formats**, which can all be generated simultaneously using `-oA`.

---

## Output Format Options

### 1. Normal Output (-oN)
**File Extension:** `.nmap`

**Description:** Human-readable text format, ideal for manual review and command-line analysis.

**Example:**
```bash
nmap -sV -oN results.nmap 10.129.34.15
```

**Output Format:**
```
# Nmap 7.98 scan initiated Mon Feb  9 15:16:49 2026 as: /usr/lib/nmap/nmap -sT -oA tcp_connect 10.129.34.15
Nmap scan report for 10.129.34.15
Host is up (0.059s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
110/tcp   open  pop3
139/tcp   open  netbios-ssn
143/tcp   open  imap
445/tcp   open  microsoft-ds
31337/tcp open  Elite

# Nmap done at Mon Feb  9 15:16:51 2026 -- 1 IP address (1 host up) scanned in 1.60 seconds
```

**Use Case:** Quick reference, command-line review, easy grep searches

---

### 2. Grepable Output (-oG)
**File Extension:** `.gnmap`

**Description:** Columnar format designed for grep and automated parsing.

**Example:**
```bash
nmap -sV -oG results.gnmap 10.129.34.15
```

**Output Format:**
```
# Nmap 7.98 scan initiated Mon Feb  9 15:16:49 2026 as: /usr/lib/nmap/nmap -sT -oA tcp_connect 10.129.34.15
Host: 10.129.34.15 ()	Status: Up (0.059s latency)
# Not shown: 993 closed tcp ports (conn-refused)
# Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 110/open/tcp//pop3///, 139/open/tcp//netbios-ssn///, 143/open/tcp//imap///, 445/open/tcp//microsoft-ds///, 31337/open/tcp//Elite///
# Nmap done at Mon Feb  9 15:16:51 2026 -- 1 IP address (1 host up) scanned in 1.60 seconds
```

**Use Case:** Automated parsing, scripting, bulk data extraction

**Example Grep Usage:**
```bash
grep "open" results.gnmap | cut -d: -f2
```

---

### 3. XML Output (-oX)
**File Extension:** `.xml`

**Description:** Structured XML format suitable for parsing, conversion, and programmatic access.

**Example:**
```bash
nmap -sV -oX results.xml 10.129.34.15
```

**Output Format:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="/usr/lib/nmap/nmap -sT -oX tcp_connect.xml 10.129.34.15" start="1707441409" startstr="Mon Feb  9 15:16:49 2026" version="7.98" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125-139,143-144,146,161,163,179,199-100-199,201-100-201,222,254-256,259,264,280,301,306,311,340,366,389-390,420-421,443,444-445,458,464-465,481,497,500-501,502-504,510,512-515,524,541,543-545,548,556-557,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720-721,722,726,749,765,777-778,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990-992,993,995-100-995,998-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1300,1301,1309-1311,1322,1328,1334-1352,1417,1433-1434,1443,1455,1461,1494,1512-1514,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723-1775,1789-1790,1796-1797,1812-1813,1863-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030-2031,2033-2035,2038,2040-2043,2045-2049,2065-2068,2099-2100,2103-2105,2107-2110,2111,2119,2121,2126,2135-2138,2143-2144,2160-2161,2170,2179-2190,2191-2196,2200,2222,2251,2260,2288,2301-2302,2323-2324,2393-2399,2401-2410,2411-2412,2423-2627,2628-2629,2638-2640,2641-2653,2655-2662,2671-2680,2689-2692,2699-2700,2701-2702,2710-2711,2717-2719,2720-2721,2722-2723,2725-2726,2787-2788,2800,2809-2811,2869,2875-2909,2920,2967-2968,2998-3000,3001-3002,3004-3005,3007,3011-3013,3017,3030-3031,3052-3071,3077,3128,3168,3211-3212,3221-3222,3260-3261,3268-3269,3283-3294,3300-3301,3306,3322-3325,3333,3351-3352,3389-3391,3404-3405,3500,3517-3530,3546,3551,3580,3659-3689,3703-3704,3737-3746,3766,3784-3788,3800-3801,3809-3814,3826-3828,3851-3869,3871-3900,3920,3945,3971-3986,3995-3998,4000-4006,4045-4049,4069,4100-4111,4125-4126,4344,4443-4446,4449-4550,4567-4662,4662,4666-4669,4685-4688,4700,4800-4900,4949-4950,5000-5004,5009,5025-5055,5060-5061,5080-5087,5100-5102,5120-5190,5200,5214-5221,5222-5225,5226-5269,5280-5321,5400-5402,5405-5406,5500,5510-5544,5550-5559,5566,5631-5632,5666-5900-5920,5938-5963,5987-5989,5998-6007,6009,6025-6059,6100-6101,6106,6112-6123,6129,6156-6346,6389-6502,6510-6543,6547,6565-6567,6580,6646,6666-6669,6689-6696,6701,6714,6715,6723,6724-6755,6771,6777,6785-6786,6807-6817,6831-6841,6901,6969,7000-7002,7004,7007,7019,7025,7070-7100,7103-7106,7200-7201,7402-7404,7406-7411,7413-7414,7423-7424,7465-7469,7500,7510-7511,7625-7627,7676-7678,7800,7911-7920-7937,7938-7999-8000-8002,8007-8011,8021-8022,8031-8042,8045-8080-8090-8093-8099-8100-8180-8181-8192-8194-8200-8222-8254-8290-8300-8333-8383-8400-8402-8443-8500-8600-8649-8651-8652-8654-8701-8800-8873-8888-8899-8994-9000-9003-9009-9020-9030-9050-9071-9080-9090-9091-9099-9103-9110-9111-9200-9207-9220-9290-9415-9418-9485-9500-9502-9503-9535-9575-9618-9666-9876-9877-9898-9900-9917-9929-9943-9944-9968-9998-9999-10000-10001-10002-10003-10004-10009-10012-10024-10025-10082-10180-10215-10243-10566-10616-11110-11111-11967-12000-12174-12265-12345-13456-13722-13782-13783-14000-14238-14441-14442-14443-14641-15000-15002-15003-15004-15660-15666-15999-16000-16001-16012-16016-16018-16080-16113-16992-16993-17877-17988-18040-18101-18988-19101-19283-19315-19350-19780-19801-19842-20000-20005-20031-20221-20222-20828-21571-22939-23502-24444-24800-25734-25735-26214-27000-27352-27353-27355-27356-27715-28201-30000-30718-30951-31038-31337-32768-32769-32771-32785-32786-32787-32788-32789-32790-32791-32892-33354-33899-34571-34572-34573-35357-38292-40193-40911-41511-42510-44176-44442-44443-44900-45100-48080-49152-49161-49163-49165-49167-49175-49176-49400-49999-50000-50006-50300-50389-50500-50636-50800-51103-51493-52673-52822-52848-52869-54045-54328-55055-55555-55600-56737-56738-57294-57797-58080-60020-60443-61532-61900-62078-63331-64623-64680-65000-65129-65389" />
<verbose level="0" />
<debugging level="0" />
<host starttime="1707441409" endtime="1707441411">
<status state="up" reason="echo-reply" reason_ttl="0" />
<address addr="10.129.34.15" addrtype="ipv4" />
<hostnames>
</hostnames>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="0" />
<service name="ssh" method="table" conf="3" />
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="0" />
<service name="http" method="table" conf="3" />
</port>
...
</ports>
</host>
</nmaprun>
```

**Use Case:** Report generation, conversion to HTML, programmatic processing

---

### 4. All Formats at Once (-oA)
**Best Practice:** Generates all three formats simultaneously (`.nmap`, `.gnmap`, `.xml`)

**Command:**
```bash
nmap -sT -oA tcp_connect 10.129.34.15
```

**Results:** Creates three files automatically
- `tcp_connect.nmap` - Normal output
- `tcp_connect.gnmap` - Grepable output
- `tcp_connect.xml` - XML output

**Advantage:** One command, three output formats for maximum flexibility.

---

## Converting XML to HTML

### Why Convert to HTML?

HTML reports are:
- **Professional** - Easy to share with non-technical stakeholders
- **Formatted** - Color-coded results, organized tables
- **Interactive** - Toggle port states, click navigation
- **Archivable** - Single file document for reporting

### The xsltproc Tool

**Purpose:** Converts XML output to HTML using XSLT stylesheets

**Tool Location:** Typically pre-installed on Linux/macOS systems

**Command Syntax:**
```bash
xsltproc <input.xml> -o <output.html>
```

### Conversion Example

**Step 1:** Run Nmap scan and save XML output
```bash
nmap -sT -oX tcp_connect.xml 10.129.34.15
```

**Step 2:** Convert XML to HTML
```bash
xsltproc tcp_connect.xml -o tcp_connect.html
```

**Step 3:** Open in browser
```bash
open tcp_connect.html
```

### Real-World Example

**Command Run:**
```bash
nmap -sT -oA tcp_connect 10.129.34.15
xsltproc tcp_connect.xml -o tcp_connect.html
```

**Generated Files:**
- `tcp_connect.nmap` - Text-based results
- `tcp_connect.gnmap` - Grepable format
- `tcp_connect.xml` - Structured XML
- `tcp_connect.html` - Interactive HTML report

**HTML Output Features:**
- Scan summary with command and timing
- Color-coded port states (green = open, gray = closed)
- Interactive toggle buttons (collapse/expand closed ports)
- Detailed port table with service names and reasons
- Professional header and formatting
- Metric information (ping results, response times)

---

## Quick Reference: Output Formats

| Format | Extension | Use Case | Command |
|--------|-----------|----------|---------|
| Normal | `.nmap` | Quick review, grep searches | `-oN results.nmap` |
| Grepable | `.gnmap` | Automated parsing, scripting | `-oG results.gnmap` |
| XML | `.xml` | Report conversion, processing | `-oX results.xml` |
| All Three | .nmap/.gnmap/.xml | Maximum flexibility | `-oA results` |

---

## Common Workflows

### Workflow 1: Quick Scan + Grepable Output (for automation)
```bash
nmap -sV -oG results.gnmap 10.129.34.15
grep "open" results.gnmap
```

### Workflow 2: Comprehensive Scan + HTML Report (for clients)
```bash
nmap -sV -sC -O -oA comprehensive_scan 10.129.34.15
xsltproc comprehensive_scan.xml -o comprehensive_scan.html
```

### Workflow 3: Service Detection + All Formats
```bash
nmap -sV --script=default -oA detailed_scan 10.129.34.15
# Now you have:
# - detailed_scan.nmap (quick reference)
# - detailed_scan.gnmap (automated processing)
# - detailed_scan.xml (HTML conversion)
```

---

## HTML Report Reference Example

Below is the HTML output generated from converting `tcp_connect.xml` to HTML. This shows what a professional-looking Nmap report looks like for client deliverables:

```html
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html xmlns:fo="http://www.w3.org/1999/XSL/Format">
<head>
<meta charset="UTF-8">
<!--generated with nmap.xsl - version 0.9c by Benjamin Erb - http://www.benjamin-erb.de/nmap_xsl.php -->
<title>Nmap Scan Report - Scanned at Mon Feb  9 15:16:49 2026</title>
</head>
<body>
<h1>Nmap Scan Report - Scanned at Mon Feb  9 15:16:49 2026</h1>

<h2>Scan Summary</h2>
<p>Nmap 7.98 was initiated at Mon Feb  9 15:16:49 2026 with these arguments:<br>
<i>/usr/lib/nmap/nmap -sT -oA tcp_connect 10.129.34.15</i><br></p>
<p>Verbosity: 0; Debug level 0</p>
<p>Nmap done at Mon Feb  9 15:16:51 2026; 1 IP address (1 host up) scanned in 1.60 seconds</p>

<h2>10.129.34.15 (online)</h2>

<h3>Address</h3>
<ul>
  <li>10.129.34.15 (ipv4)</li>
</ul>

<h3>Ports</h3>
<p>The 993 ports scanned but not shown below are in state: <b>closed</b></p>
<ul>
  <li><p>993 ports replied with: <b>conn-refused</b></p></li>
</ul>

<table cellspacing="1">
<tr class="head">
<td colspan="2">Port</td>
<td>State</td>
<td>Service</td>
<td>Reason</td>
<td>Product</td>
<td>Version</td>
<td>Extra info</td>
</tr>

<tr class="open">
<td>22</td>
<td>tcp</td>
<td>open</td>
<td>ssh</td>
<td>syn-ack</td>
<td></td>
<td></td>
<td></td>
</tr>

<tr class="open">
<td>80</td>
<td>tcp</td>
<td>open</td>
<td>http</td>
<td>syn-ack</td>
<td></td>
<td></td>
<td></td>
</tr>

<tr class="open">
<td>110</td>
<td>tcp</td>
<td>open</td>
<td>pop3</td>
<td>syn-ack</td>
<td></td>
<td></td>
<td></td>
</tr>

<tr class="open">
<td>139</td>
<td>tcp</td>
<td>open</td>
<td>netbios-ssn</td>
<td>syn-ack</td>
<td></td>
<td></td>
<td></td>
</tr>

<tr class="open">
<td>143</td>
<td>tcp</td>
<td>open</td>
<td>imap</td>
<td>syn-ack</td>
<td></td>
<td></td>
<td></td>
</tr>

<tr class="open">
<td>445</td>
<td>tcp</td>
<td>open</td>
<td>microsoft-ds</td>
<td>syn-ack</td>
<td></td>
<td></td>
<td></td>
</tr>

<tr class="open">
<td>31337</td>
<td>tcp</td>
<td>open</td>
<td>Elite</td>
<td>syn-ack</td>
<td></td>
<td></td>
<td></td>
</tr>
</table>

<h3>Misc Metrics</h3>
<table cellspacing="1">
<tr class="head">
<td>Metric</td>
<td>Value</td>
</tr>
<tr>
<td>Ping Results</td>
<td>reset</td>
</tr>
</table>
</body>
</html>
```

### HTML Report Features Explained

**Visual Elements:**
- **Color-coded port states** - Green background for "open" ports makes them stand out
- **Clean table layout** - Easy to scan and identify open ports
- **Metric section** - Shows scan metadata and timing information

**Key Information Displayed:**
- Scan command and arguments
- Scan initiation and completion times
- Total scan duration (1.60 seconds)
- Host status and IP address
- Port count summary (993 closed vs 7 open)
- Detailed port table with service names and connection reasons

**Professional Presentation:**
- Organized sections with clear headings
- Professional styling suitable for client reports
- Contains all essential pentesting information
- Easy to print or convert to PDF

---

## Best Practices

✅ **Always use `-oA`** - Generates all three formats at once  
✅ **Name scans descriptively** - Use `scan_date_target.xml` format  
✅ **Convert to HTML for reports** - Non-technical stakeholders appreciate formatting  
✅ **Archive XML files** - Smaller than text, easily re-convertible  
✅ **Use grepable for automation** - Programmatic processing of results  
✅ **Cross-reference formats** - Use .nmap for details, .gnmap for quick parsing  

---

## Next Steps

- [NSE Scripts](NSE_Scripts.md) - Automate service enumeration with scripts
- [Firewall/IDS Evasion](Firewall_IDS_Evasion.md) - Bypass filtering to discover hidden ports
