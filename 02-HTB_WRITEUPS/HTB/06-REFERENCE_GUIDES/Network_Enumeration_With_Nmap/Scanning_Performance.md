# Scanning Performance

## Overview

**Scanning performance** is critical when dealing with:
- **Large networks** - Scanning hundreds or thousands of hosts
- **Low bandwidth environments** - Limited network capacity
- **Time-constrained assessments** - Need to complete quickly
- **Stealth requirements** - Avoiding detection while maintaining speed

Nmap provides multiple options to optimize scan speed while balancing accuracy and detection risk.

---

## Quick Reference Commands

| Command | Purpose |
|---------|---------|
| `-T 0 / -T paranoid` | Slowest, most stealthy timing |
| `-T 1 / -T sneaky` | Very slow, difficult to detect |
| `-T 2 / -T polite` | Slower, friendly to networks |
| `-T 3 / -T normal` | Default speed (recommended) |
| `-T 4 / -T aggressive` | Fast, suitable for fast networks |
| `-T 5 / -T insane` | Fastest, may lose accuracy |
| `--initial-rtt-timeout <ms>` | Set initial response timeout |
| `--max-rtt-timeout <ms>` | Set maximum response timeout |
| `--max-retries <number>` | Set packet retry limit (default: 10) |
| `--min-rate <number>` | Minimum packets per second |
| `--max-rate <number>` | Maximum packets per second |

---

## Performance Tuning Options

### 1. Timing Templates (-T)

Nmap provides **six timing templates** (0-5) that automatically configure multiple performance parameters.

**Timeline of Aggressiveness:**
```
-T 0 (Paranoid)    → Slowest, most stealthy
-T 1 (Sneaky)      → Very slow
-T 2 (Polite)      → Slower, network-friendly
-T 3 (Normal)      → Default [balanced approach]
-T 4 (Aggressive)  → Faster
-T 5 (Insane)      → Fastest, may miss data
```

**When to Use Each:**
- **T0/T1** - IDS/IPS evasion, stealth required
- **T2** - Network-friendly scans (shared connections)
- **T3** - Standard assessments (recommended default)
- **T4** - Fast networks with good bandwidth
- **T5** - Aggressive scanning, speed critical

**Documentation:** https://nmap.org/book/performance-timing-templates.html

---

### 2. Timeout Configuration

**Problem:** Nmap's default timeout of 100ms may be too high for fast networks or too low for slow/congested networks.

**Solution:** Manually tune initial and maximum RTT timeouts.

#### Initial RTT Timeout (--initial-rtt-timeout)

Sets the starting timeout value for probe responses.

**Command:**
```bash
sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms
```

**Effect:**
- Lower values = faster initial responses (but may miss packets)
- Higher values = more reliable (but slower overall)

#### Max RTT Timeout (--max-rtt-timeout)

Sets the ceiling for timeout values during the scan.

**Command:**
```bash
sudo nmap 10.129.2.0/24 -F --max-rtt-timeout 100ms
```

### Timeout Optimization Example

**Default Scan (No Optimization):**
```bash
sudo nmap 10.129.2.0/24 -F
```
**Result:** 256 IP addresses (10 hosts up) scanned in **39.44 seconds**

**Optimized RTT Scan:**
```bash
sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```
**Result:** 256 IP addresses (8 hosts up) scanned in **12.29 seconds**

### Analysis

| Metric | Default | Optimized |
|--------|---------|-----------|
| Time | 39.44s | 12.29s |
| Speedup | — | **3.2x faster** |
| Hosts Found | 10 | 8 |
| Accuracy Loss | — | 2 hosts missed |

**Key Insight:** Aggressive timeout settings dramatically improve speed but may cause you to miss hosts. Balance is critical.

---

### 3. Retry Configuration

**Problem:** By default, Nmap retries failed probes up to **10 times** per port, which slows scans significantly.

**Solution:** Reduce `--max-retries` to skip unresponsive ports faster.

#### Max Retries (--max-retries)

**Default Value:** 10 retries per port  
**Minimum Value:** 0 (no retries, skip immediately)

**Command:**
```bash
sudo nmap 10.129.2.0/24 -F --max-retries 0
```

### Retry Optimization Example

**Default Scan (10 retries):**
```bash
sudo nmap 10.129.2.0/24 -F | grep "/tcp" | wc -l
```
**Result:** **23 open ports** found

**Optimized Scan (0 retries):**
```bash
sudo nmap 10.129.2.0/24 -F --max-retries 0 | grep "/tcp" | wc -l
```
**Result:** **21 open ports** found

### Analysis

| Metric | Default | Optimized |
|--------|---------|-----------|
| Retries | 10 | 0 |
| Open Ports Found | 23 | 21 |
| Missed Ports | — | 2 |
| Speed Improvement | — | Significant |

**Key Insight:** Eliminating retries speeds up scans but costs accuracy. Use strategically for quick scans where missing 1-2 ports is acceptable.

---

### 4. Packet Rate Configuration

**Problem:** Slow port-by-port scanning wastes time.

**Solution:** Set a minimum packet rate to send multiple probes simultaneously.

#### Minimum Rate (--min-rate)

Tells Nmap to send **at least N packets per second**.

**Command:**
```bash
sudo nmap 10.129.2.0/24 -F --min-rate 300
```

**Parameters:**
- Maintains specified rate throughout scan
- Requires sufficient bandwidth
- Works best in whitelisted assessments
- Can trigger IDS/IPS alerts if too aggressive

#### Maximum Rate (--max-rate)

Limits Nmap to **at most N packets per second** to avoid overwhelming the network.

**Command:**
```bash
sudo nmap 10.129.2.0/24 -F --max-rate 100
```

### Rate Optimization Example

**Default Scan:**
```bash
sudo nmap 10.129.2.0/24 -F -oN tnet.default
# Result: 256 IP addresses (10 hosts up) scanned in 29.83 seconds
cat tnet.default | grep "/tcp" | wc -l
# Result: 23 open ports
```

**Optimized Scan with --min-rate 300:**
```bash
sudo nmap 10.129.2.0/24 -F -oN tnet.minrate300 --min-rate 300
# Result: [Output not shown, but typically faster]
cat tnet.minrate300 | grep "/tcp" | wc -l
# Result: 23 open ports (same results, faster execution)
```

**Analysis:**
- Same number of open ports discovered
- Significantly faster execution
- Better for whitelisted assessments with known bandwidth

---

## Timing Templates in Action

The timing templates automatically adjust multiple parameters for optimal performance at their aggression level.

### Default Scan (T3 - Normal)

**Command:**
```bash
sudo nmap 10.129.2.0/24 -F -oN tnet.default
```

**Result:** 256 IP addresses (10 hosts up) scanned in **32.44 seconds**

**Open Ports Found:**
```bash
cat tnet.default | grep "/tcp" | wc -l
# Result: 23
```

### Aggressive Scan (T5 - Insane)

**Command:**
```bash
sudo nmap 10.129.2.0/24 -F -oN tnet.T5 -T 5
```

**Result:** 256 IP addresses (10 hosts up) scanned in **18.07 seconds**

**Open Ports Found:**
```bash
cat tnet.T5 | grep "/tcp" | wc -l
# Result: 23
```

### Comparison

| Metric | T3 (Normal) | T5 (Insane) |
|--------|------------|-----------|
| Time | 32.44s | 18.07s |
| Speedup | — | **1.8x faster** |
| Open Ports | 23 | 23 |
| Accuracy Loss | — | **None** |

**Key Insight:** In this scenario, T5 provided significant speed improvement with **no accuracy loss**. However, this depends on network conditions and can vary.

---

## Performance Tuning Strategy

### Choose Approach Based on Scenario

#### White-Box Pentesting (Whitelisted)
```bash
# You're authorized, known bandwidth, speed critical
sudo nmap <target> -T 4 --min-rate 300 -oA <output>
```
**Focus:** Speed and completeness

#### Black-Box Pentesting (Covert)
```bash
# Need stealth, risk of detection, time flexible
sudo nmap <target> -T 1 --max-rate 50 -oA <output>
```
**Focus:** Stealth and avoid detection

#### Large Network with Good Bandwidth
```bash
# 1000+ hosts, fast network, balanced approach
sudo nmap <network> -T 4 -F --initial-rtt-timeout 50ms -oA <output>
```
**Focus:** Speed while maintaining accuracy

#### Slow/Congested Network
```bash
# Low bandwidth, unreliable connections, patience available
sudo nmap <target> -T 2 --initial-rtt-timeout 200ms --max-rtt-timeout 500ms -oA <output>
```
**Focus:** Reliability over speed

---

## Manual Parameter Fine-Tuning

For precise control, combine individual parameters:

**Conservative Scan (Speed + Stealth):**
```bash
sudo nmap 10.129.2.0/24 -p- --initial-rtt-timeout 100ms --max-rtt-timeout 300ms --max-retries 3 -T 2
```

**Aggressive Scan (Speed + Completeness):**
```bash
sudo nmap 10.129.2.0/24 -p- --initial-rtt-timeout 50ms --max-rtt-timeout 100ms --min-rate 300 -T 4
```

**Balanced Scan (Good mix):**
```bash
sudo nmap 10.129.2.0/24 -p- --initial-rtt-timeout 75ms --max-rtt-timeout 150ms --max-retries 5 -T 3
```

---

## Performance Monitoring

### Monitor Progress During Scan

**Show status with Space Bar:**
```bash
sudo nmap 10.129.2.0/24 -p-
[Press Space Bar during scan]
```

**Automatic status updates every 5 seconds:**
```bash
sudo nmap 10.129.2.0/24 -p- --stats-every 5s
```

**Very verbose with real-time port discovery:**
```bash
sudo nmap 10.129.2.0/24 -p- -vv
```

---

## Best Practices for Scanning Performance

✅ **Use timing templates first** - Start with `-T 3` (default), adjust up/down as needed  
✅ **Test small subset first** - Scan 1-2 hosts before full network with new parameters  
✅ **Monitor network impact** - Use `--stats-every` to watch for issues  
✅ **Balance speed and accuracy** - Don't sacrifice completeness for small time savings  
✅ **Document your settings** - Save commands used with `-oA` for reproducibility  
✅ **Adjust for network conditions** - Higher latency needs higher timeouts  
✅ **Know your target** - Fast networks allow aggressive settings (T4-T5)  
✅ **Use rate limiting for stealth** - `--min-rate` should be low for covert scans  
✅ **Test evasion impact** - Some tuning can trigger security systems  
✅ **Combine techniques** - Use timing templates + manual parameters for optimal results  

---

## Performance Tuning Decision Tree

```
Start with: -T 3 (Normal) + -F (top 100 ports)
    |
    ├─ Too slow?
    │   └─ Try: -T 4 or --min-rate 100
    │
    ├─ Missing hosts?
    │   └─ Try: --initial-rtt-timeout 100ms (increase)
    │
    ├─ Need stealth?
    │   └─ Try: -T 1 or -T 2 (paranoid/sneaky)
    │
    └─ Large network (1000+ hosts)?
        └─ Try: -T 4 --min-rate 300 --max-rate 1000
```

---

## Additional Resources

**Official Nmap Performance Guide:**  
https://nmap.org/book/man-performance.html

This guide covers:
- Detailed timing template parameters
- Network optimization techniques
- Scan rate calculations
- Timeout behavior under various conditions

---

## Next Steps

- [Firewall/IDS Evasion](Firewall_IDS_Evasion.md) - Techniques to bypass network defenses
