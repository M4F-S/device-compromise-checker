---
name: device-compromise-checker
description: >
  Check iPhone, iPad, and MacBook for signs of compromise, spyware, malware, and unauthorized access.
  Covers iOS/iPadOS detection (battery drain, data usage, unknown apps, configuration profiles,
  MVT/iMazing scanning, Lockdown Mode) and macOS detection (Activity Monitor, lsof, nettop,
  LaunchAgents, LaunchDaemons, network connections, persistence, codesign verification).
  Triggered by: "is my iPhone hacked", "check my Mac for malware", "iPad compromised",
  "spyware detection", "device security check", "Pegasus spyware", "check if my devices are infected".
---

# Device Compromise Checker

Check iPhone, iPad, and MacBook for signs of compromise, spyware, and malware.

## Prerequisites
- macOS device with iPhone/iPad connected via USB (for iOS deep scans)
- Admin/sudo access on macOS for system-level checks
- Terminal access for command-line checks

## Platform Overview

| Device | Primary Threats | Detection Methods |
|--------|-----------------|-------------------|
| **iPhone** | Pegasus, Predator, stalkerware, sideloaded apps | Battery/data analysis, MVT, iMazing, config profiles |
| **iPad** | Same as iPhone + jailbreak-based malware | Battery/data analysis, config profiles, app audit |
| **MacBook** | Adware, spyware, cryptominers, backdoors | Process/network analysis, persistence audit, codesign |

---

## iPhone & iPad Compromise Checks

### Quick Visual Checks (No Tools Needed)

1. **Battery Usage** — Settings > Battery > Last 10 Days
   - Look for apps consuming power without active use
   - Unexpected background activity by unfamiliar apps

2. **Data Usage** — Settings > Mobile Service > Show All
   - Unusual spikes in data usage
   - Apps you don't recognize using data

3. **Unknown Apps** — App Library > Recently Added
   - Apps you don't remember installing
   - Apps with generic icons or suspicious names

4. **App Privacy Report** — Settings > Privacy & Security > App Privacy Report
   - Which apps accessed location, mic, camera, contacts
   - Look for unexpected apps with excessive permissions

5. **Configuration Profiles** — Settings > General > VPN & Device Management
   - **ANY profile you didn't install = HIGH RISK**
   - Remove unknown profiles immediately
   - Then check: Settings > General > About > Certificate Trust Settings
   - Revoke trust for any unfamiliar certificates

6. **Camera/Microphone Indicators**
   - Green dot = camera active
   - Orange dot = microphone active
   - If you see these when not using camera/mic, investigate immediately
   - Swipe into Control Center to see which app triggered it

7. **Apple ID Activity** — Settings > [Your Name] > Devices
   - Remove any device you don't recognize
   - Check for unexpected Apple ID login alerts
   - Change Apple ID password if suspicious

8. **Messages** — Check sent messages for spam/links you didn't send

9. **Safari History** — Look for redirects to unknown sites

### Advanced: Deep Scan with iMazing (macOS Required)

iMazing can detect Pegasus/Predator indicators on iOS backups:

```bash
# Download iMazing from https://imazing.com
# Connect iPhone/iPad via USB
# Open iMazing > Device > Detect Spyware
# Run the scan (checks iTunes backup for known IOCs)
```

### Advanced: Mobile Verification Toolkit (MVT)

MVT is the gold standard for iOS spyware detection (Amnesty International tool):

```bash
# Install dependencies (macOS/Linux)
brew install python3 libusb sqlite3  # macOS
# OR: sudo apt install python3 python3-pip libusb-1.0-0 sqlite3  # Linux

# Install libimobiledevice for iOS communication
brew install libimobiledevice  # macOS
# OR: sudo apt install libimobiledevice-utils  # Linux

# Install MVT
pip3 install mvt

# Download latest IOCs
mvt-ios download-iocs

# Create encrypted backup of iPhone (connect via USB)
idevicebackup2 backup --full /path/to/backup/

# Decrypt backup
mvt-ios decrypt-backup -p [password] -d /path/to/decrypted /path/to/backup

# Check for known IOCs
mvt-ios check-backup --output /path/to/output/ /path/to/decrypted/

# Results: *_detected.json files indicate compromise
```

### Key iOS Files to Check in Backup (Manual Analysis)

| File | What to Look For |
|------|-----------------|
| `Safari_history.json` | Suspicious redirects, unknown domains |
| `Datausage.json` | Unknown processes with high data usage |
| `Os_analytics_ad_daily.json` | Suspicious processes |
| `Tcc.json` | Apps with unexpected permissions |
| `sms.db` | Messages you didn't send |
| `call_history.db` | Calls you didn't make |

### iOS Lockdown Mode (Recommended for High-Risk Users)

```bash
# Enable via Settings > Privacy & Security > Lockdown Mode
# This restricts:
# - iMessage attachments (blocks most zero-click exploits)
# - Web technologies (JIT compilation, etc.)
# - Apple services (link previews, FaceTime)
# - Wired connections (blocks accessory access when locked)
# - Configuration profiles (can't be installed remotely)
```

---

## macOS Compromise Checks

### Phase 1: System Context & Security Posture

```bash
# Check macOS version and uptime
sw_vers
uptime

# Verify native protections are active
spctl --status          # Gatekeeper status
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate  # Firewall
# Check SIP status
csrutil status
```

### Phase 2: Process Analysis (Activity Monitor + Terminal)

```bash
# Top CPU consumers
ps aux | sort -nrk 3 | head -20

# Top memory consumers
ps aux | sort -nrk 4 | head -20

# All processes with network connections
sudo lsof -i -n -P | head -50

# Active connections with process names
sudo nettop -L 0

# Or use lsof for established connections
sudo lsof -iTCP -sTCP:ESTABLISHED -n -P | head -50

# Check for processes in suspicious directories
ps aux | grep -E '/tmp/|/Users/Shared/|/private/tmp/' | grep -v grep
```

**Red flags:**
- Random-looking process names
- High CPU while idle
- Unsigned binaries (check with `codesign` below)
- Processes running from `/tmp`, `/Users/Shared`, hidden `~/Library/` dirs

### Phase 3: Binary Verification (Code Signing)

```bash
# Check if a suspicious binary is signed
BIN="/path/to/suspicious/binary"
codesign -dv --verbose=4 "$BIN" 2>&1 | head -30

# Check notarization
spctl --assess --type execute --verbose=4 "$BIN" 2>&1 | head -30

# Check file metadata
ls -lah "$BIN"
stat "$BIN"
```

### Phase 4: Persistence Mechanisms (Most Important)

```bash
# === LaunchAgents (user-level) ===
ls -lah ~/Library/LaunchAgents/

# === LaunchAgents (system-wide) ===
ls -lah /Library/LaunchAgents/

# === LaunchDaemons (system-level, requires root) ===
ls -lah /Library/LaunchDaemons/

# Inspect suspicious .plist files
PLIST="~/Library/LaunchAgents/com.suspicious.agent.plist"
plutil -p "$PLIST" 2>/dev/null | head -30

# === Cron jobs ===
crontab -l
sudo crontab -l
ls -lah /etc/periodic/

# === Login items ===
osascript -e 'tell application "System Events" to get the name of every login item'

# === Browser extensions ===
# Chrome
ls -lah ~/Library/Application\ Support/Google/Chrome/Default/Extensions/

# Safari
ls -lah ~/Library/Containers/com.apple.Safari/Data/Library/Safari/Extensions/

# === Chrome extensions manifests (check for suspicious ones) ===
find ~/Library/Application\ Support/Google/Chrome/Default/Extensions -name "manifest.json" -exec cat {} \; 2>/dev/null | grep -E "name|permissions" | head -30
```

**Red flags in LaunchAgents:**
- Binary references in `/tmp`, `/Users/Shared`, hidden dirs
- Base64-encoded command strings
- KeepAlive + RunAtLoad patterns
- Names mimicking Apple services (e.g., `com.apple.system.update`)

### Phase 5: Network Analysis

```bash
# All listening services (unexpected listeners = bad)
sudo lsof -i -n -P | grep LISTEN

# DNS configuration (check for hijacking)
scutil --dns | head -20

# Web proxy settings (common adware tactic)
networksetup -getwebproxy "Wi-Fi"
networksetup -getsecurewebproxy "Wi-Fi"

# Recent downloads with quarantine flags
xattr -l ~/Downloads/* 2>/dev/null | head -80

# Check hosts file for DNS hijacking
cat /etc/hosts
```

### Phase 6: File System Audit

```bash
# Recently modified files in user Library (7 days)
find ~/Library -type f -mtime -7 2>/dev/null | head -30

# Suspicious executables in user-writable paths
find /tmp /Users/Shared ~/Library -type f -perm +111 2>/dev/null | head -20

# Hidden files in home directory
ls -la ~ | grep "^\."

# Large files created recently (potential exfiltration staging)
find ~ -type f -size +100M -mtime -7 2>/dev/null | head -20
```

### Phase 7: SSH & Remote Access Audit

```bash
# Check SSH authorized keys
cat ~/.ssh/authorized_keys 2>/dev/null

# SSH config
cat ~/.ssh/config 2>/dev/null

# Known hosts (check for unexpected entries)
cat ~/.ssh/known_hosts 2>/dev/null | head -20

# Check for remote access enabled
sudo systemsetup -getremotelogin  # Remote Login (SSH)
sudo systemsetup -getremoteappleevents  # Remote Apple Events
```

### Phase 8: System Logs

```bash
# Console.app logs (GUI) or command-line:
log show --predicate 'eventMessage CONTAINS "error"' --last 1h | head -30

# Authentication logs
log show --predicate 'subsystem == "com.apple.opendirectoryd"' --last 24h | head -30

# Kernel messages (look for panics, suspicious kext loads)
log show --predicate 'process == "kernel"' --last 24h | head -30
```

---

## Quick Reference: Compromise Indicators by Severity

### 🔴 CRITICAL (Act Immediately)

| Indicator | Platform | Action |
|-----------|----------|--------|
| Unknown configuration profile | iOS/iPadOS | Delete immediately, change Apple ID password |
| Green/orange camera/mic indicator without using them | iOS/iPadOS | Check Control Center, force-close apps |
| Unsigned binary in LaunchDaemon | macOS | Kill process, remove plist, delete binary |
| Unknown SSH key in authorized_keys | macOS | Remove key, change passwords |
| Proxy settings you didn't set | macOS | Disable proxies, scan for malware |
| Unknown device in Apple ID | iOS/macOS | Remove device, change Apple ID password, enable 2FA |
| Messages sent you didn't write | iOS | Change Apple ID password, check for profile |

### 🟡 WARNING (Investigate Soon)

| Indicator | Platform | Action |
|-----------|----------|--------|
| Battery drain without explanation | iOS/iPadOS | Check battery usage, look for unknown apps |
| Data usage spike | iOS/iPadOS | Check data usage per app |
| Unknown app in Recently Added | iOS/iPadOS | Delete app, check when installed |
| High CPU process while idle | macOS | Inspect in Activity Monitor, check codesign |
| Unknown browser extension | macOS | Remove extension, check browser settings |
| New login item you didn't add | macOS | Remove from System Settings > General > Login Items |
| Files modified at unusual times | macOS | Check with `stat`, compare to when you used device |

### 🟢 INFO (Monitor)

| Indicator | Platform | Action |
|-----------|----------|--------|
| New app from unknown developer | macOS | Verify codesign, check reputation online |
| Firewall disabled | macOS | Re-enable in System Settings |
| Gatekeeper disabled | macOS | Re-enable: `sudo spctl --master-enable` |
| Outdated iOS/macOS | All | Update immediately |

---

## Recommended Tools

| Tool | Platform | Purpose | Cost |
|------|----------|---------|------|
| **iMazing** | macOS | iOS spyware detection (Pegasus/Predator) | Paid |
| **MVT** | macOS/Linux | Open-source iOS/Android forensic analysis | Free |
| **Malwarebytes** | macOS | Mac malware/adware scanner | Freemium |
| **Intego** | macOS | Mac-specific antivirus | Paid |
| **Bitdefender** | macOS/iOS | Cross-platform antivirus | Paid |
| **Little Snitch** | macOS | Egress firewall (network monitoring) | Paid |
| **feelgoodbot** | macOS | File integrity monitoring + AI agent protection | Free |
| **MacOSThreatTrack** | macOS | Bash-based security reconnaissance | Free |
| **Lockdown Mode** | iOS 16+ | Apple's extreme security mode | Free (built-in) |

---

## Emergency Response If Compromised

### iPhone/iPad
1. Disconnect from Wi-Fi and cellular
2. Change Apple ID password from a clean device
3. Enable Lockdown Mode (Settings > Privacy & Security > Lockdown Mode)
4. Remove all unknown profiles and apps
5. Update to latest iOS
6. If still suspicious, erase and restore from a clean backup

### MacBook
1. Disconnect from internet (Wi-Fi off, unplug Ethernet)
2. Boot into Safe Mode (hold Shift on Intel, hold power on Apple Silicon)
3. Kill suspicious processes, remove persistence mechanisms
4. Run Malwarebytes or Intego scan
5. Change all passwords from a clean device
6. If still suspicious, erase and reinstall macOS

---

## Important Notes

1. **iOS is highly sandboxed** — Non-jailbroken iPhones are very difficult to compromise. Most "hacks" are actually: compromised Apple ID, phishing, or malicious configuration profiles.
2. **Pegasus is extremely rare** — It's a multi-million-dollar tool used against high-profile targets. If you're not a journalist, politician, or activist, you're unlikely to be targeted by Pegasus specifically.
3. **Stalkerware is more common** — Partners, employers, or family members may install monitoring apps. Check for MDM profiles and unknown apps.
4. **Don't reboot immediately** — If you suspect compromise, collect evidence first (processes, network connections, logs). Reboot can destroy volatile evidence.
5. **Use a clean device to change passwords** — If your Mac is compromised, don't use it to change passwords. Use a different, trusted device.
