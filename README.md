# macshield

```
  ╔══════════════════════════════════════════════════════════════════════╗
  ║                                                                      ║
  ║  ███╗   ███╗ █████╗  ██████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗  ║
  ║  ████╗ ████║██╔══██╗██╔════╝ ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗ ║
  ║  ██╔████╔██║███████║██║      ███████╗███████║██║█████╗  ██║     ██║  ██║ ║
  ║  ██║╚██╔╝██║██╔══██║██║      ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║ ║
  ║  ██║ ╚═╝ ██║██║  ██║╚██████╗ ███████║██║  ██║██║███████╗██████╗ ██████╔╝ ║
  ║  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═════╝╚═════╝  ║
  ║                                                                      ║
  ║              [ by qinnovate // github.com/qinnovates ]               ║
  ║                                                                      ║
  ║         >> network-aware macos security hardening <<                 ║
  ║         >> auto-harden on untrusted wifi networks <<                 ║
  ║                                                                      ║
  ╚══════════════════════════════════════════════════════════════════════╝
```

Network-aware macOS security hardening. Auto-hardens your Mac on untrusted WiFi, relaxes on trusted networks.

## Table of contents

- [Why it exists](#why-it-exists)
- [What it does](#what-it-does)
- [Threat model](#threat-model)
- [Understanding DNS, VPNs, proxies, and where macshield fits](#understanding-dns-vpns-proxies-and-where-macshield-fits)
- [Install](#install)
- [Verify it works](#verify-it-works)
- [How it works](#how-it-works)
- [Commands](#commands)
- [Port scanning](#port-scanning)
- [Optional security commands](#optional-security-commands)
- [Security model](#security-model)
- [Do it manually](#do-it-manually-no-script-needed)
- [Build your own VPN](#build-your-own-vpn-students--researchers)
- [Comparison](#comparison)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)

---

> **If you work in an enterprise, institution, or clinical setting**, you MUST use your organization's corporate VPN, managed devices, and enterprise security policies. macshield is not a substitute for enterprise security infrastructure. If your organization handles PII, neural recordings, HIPAA-covered data, or any sensitive research data, adhere to your corporate device and security policies at all times. **Qinnovates is not liable for any security compromises resulting from the use of macshield in lieu of proper enterprise or institutional security controls.**

macshield is for **students, independent researchers, and individuals** who want baseline device hardening on public WiFi. It is not a VPN, does not encrypt traffic, and does not replace enterprise security. See [Build your own VPN](#build-your-own-vpn-students--researchers) if you need traffic encryption on a budget.

## Why it exists

Your digital identity deserves the same protection as your cognitive identity. macshield is part of a broader commitment to [neurorights and privacy](https://github.com/qinnovates/qinnovate): the principle that individuals should control what information leaves their devices and their minds.

When you connect to public WiFi (cafes, airports, hotels), your Mac broadcasts its hostname over mDNS/Bonjour, responds to ICMP pings, and announces itself via NetBIOS. VPNs encrypt your traffic but don't hide your hostname or stop these broadcasts on the local network. Free VPNs are arguably worse: they give you a false sense of security while the provider harvests your traffic.

**Commercial tools** (Little Snitch, Intego NetBarrier) handle profile switching but are closed-source and expensive. **Open-source hardening scripts** (ALBATOR, drduh's macOS-Security-and-Privacy-Guide) are thorough but static, with no network-aware auto-switching.

macshield fills the gap: automatic, network-aware, open-source, fully auditable. Built for students and individuals who care about privacy but don't have access to corporate VPNs or enterprise security tools. macshield is not a substitute for enterprise security infrastructure.

## What it does

| Untrusted network | Trusted network |
|---|---|
| Stealth mode ON (blocks ICMP pings, port scans) | Stealth mode OFF (AirDrop, Spotify Connect work) |
| Hostname set to generic "MacBook Pro" | Personal hostname restored |
| NetBIOS disabled (ports 137/138 closed) | NetBIOS re-enabled |

macshield detects network changes via a LaunchAgent (runs as your user, not root) and applies the right profile automatically.

## Threat model

**Protects against:**
- Passive reconnaissance on shared WiFi (hostname enumeration, ping sweeps, NetBIOS probes)
- Targeted attacks where attacker identifies your machine by hostname
- Location correlation via consistent hostname across networks

**Does not protect against:**
- Traffic interception (use a VPN)
- MAC address tracking (use macOS private WiFi address, enabled by default since Sonoma)
- Kernel-level attacks, rootkits, or exploits targeting macOS services
- Physical access attacks

## Understanding DNS, VPNs, proxies, and where macshield fits

These terms get thrown around together but they do completely different things. Here is what each one actually does, what it protects, and what it does not.

### DNS (Domain Name System)

**What it does:** Translates domain names (like `google.com`) into IP addresses (like `142.250.80.46`). Every time you visit a website, your device asks a DNS server "where is this?"

**Who sees your queries:** By default, your ISP's DNS server. They see every domain you visit, when you visited it, and from which IP. Many ISPs log this data and some sell it to advertisers.

**What changing DNS does:** Switching to a privacy-focused DNS (Cloudflare 1.1.1.1, Quad9 9.9.9.9) means your ISP no longer sees your DNS queries. The DNS provider sees them instead, so you are choosing who you trust.

**What it does NOT do:** Changing DNS does not encrypt your traffic. It does not hide your IP address. It does not prevent your ISP from seeing which IP addresses you connect to (they just can't see the domain name if you use encrypted DNS). It is not a VPN.

### VPN (Virtual Private Network)

**What it does:** Creates an encrypted tunnel between your device and a VPN server. All your internet traffic goes through this tunnel. Websites see the VPN server's IP address instead of yours.

**What it protects:** Encrypts all traffic between you and the VPN server. Hides your real IP from websites. Prevents your ISP from seeing what you are doing (they only see encrypted traffic going to the VPN server).

**What it does NOT do:** A VPN does not make you anonymous. The VPN provider can see all your traffic (you are trusting them instead of your ISP). It does not protect you from malware, phishing, or local network attacks. It does not hide your hostname, stop mDNS broadcasts, or prevent NetBIOS probes on the local network. Free VPNs are arguably worse than no VPN: you get a false sense of security while the provider harvests your data to pay for the service.

### Proxy (SOCKS/HTTP)

**What it does:** Routes your traffic through an intermediary server. A SOCKS proxy works at the network level (any TCP/UDP traffic). An HTTP proxy only handles web traffic.

**What it protects:** Hides your IP from the destination. Can bypass geographic restrictions. An SSH SOCKS tunnel (`ssh -D 1080`) encrypts traffic between you and the SSH server.

**What it does NOT do:** A proxy does not encrypt traffic by itself (only SSH tunnels and some SOCKS5 implementations do). It does not protect DNS queries unless explicitly configured. It does not hide your hostname on the local network.

### macshield

**What it does:** Reduces your local network footprint. Enables stealth mode (blocks pings and port scans), sets a generic hostname (so you don't broadcast "Kevin's MacBook Pro" to everyone on the WiFi), and disables NetBIOS (closes ports 137/138).

**What it protects:** Prevents passive reconnaissance on the local network. Stops your real name from leaking via hostname. Makes your Mac less visible to anyone scanning the same WiFi.

**What it does NOT do:** macshield does not encrypt your traffic, does not hide your IP address, does not replace a VPN, and does not make you anonymous. It operates at the local network layer only.

### How they work together

```
Layer 4 - VPN          Encrypts all traffic, hides your IP from websites
Layer 3 - Proxy        Routes traffic through intermediary (optional)
Layer 2 - DNS          Controls who resolves your domain lookups
Layer 1 - macshield    Hides your identity on the local network
```

Each layer protects something different. Using a VPN without macshield still broadcasts your hostname to everyone on the local WiFi. Using macshield without a VPN still exposes your traffic to your ISP. They are complementary, not interchangeable.

In OSI terms, VPNs operate at Layer 3+ (Network and above). In the [QIF security model](https://github.com/qinnovates/qinnovate/blob/main/qif-framework/QIF-TRUTH.md), VPNs operate at the **S3 band** (Application). The attacks macshield blocks happen at the **S1 band** (Analog Front-End), below the VPN tunnel. In BCI systems, compromising S1 can propagate upward through S2, S3, through I0 (the neural interface), and into the neural domain. macshield defends the silicon domain floor.

The macshield installer optionally configures DNS and SOCKS proxy settings during setup, but these are standard macOS system settings. macshield does not provide or run a VPN, DNS server, or proxy server. It just helps you configure the ones you choose.

## Install

### Homebrew (recommended)

```bash
brew tap qinnovates/tools
brew install macshield
```

After install, Homebrew will print setup instructions. Run these:

```bash
# Trust your home network
macshield trust

# Confirm everything is working
macshield --check
```

### Manual install

```bash
git clone https://github.com/qinnovates/macshield.git
cd macshield
chmod +x install.sh macshield.sh
./install.sh
```

The installer walks through each step with explicit yes/no consent. It will:

1. Copy `macshield` to `/usr/local/bin/`
2. Install a sudoers authorization for exact privileged commands (you approve this)
3. Install a LaunchAgent that triggers on WiFi changes (runs as your user, not root)
4. Optionally trust your current network

After installation:

```bash
macshield trust            # Trust your current WiFi network
macshield --check          # See current state
```

## Verify it works

Run these commands in order to confirm everything is working:

```bash
# 1. Check current state. Shows WiFi status, trust level, stealth mode,
#    hostname, and whether the LaunchAgent is installed.
macshield --check

# 2. Manually harden. Enables stealth mode (blocks ICMP pings and port scans),
#    sets your hostname to a generic model name like "MacBook Pro" so you blend
#    in on public networks, and disables NetBIOS (closes ports 137/138).
macshield harden

# 3. Confirm hardened state. Stealth mode should be ON, hostname should show
#    as generic, and state should read "hardened".
macshield --check

# 4. Relax protections. Disables stealth mode (AirDrop, Spotify Connect, etc.
#    will work again), restores your personal hostname from Keychain, and
#    re-enables NetBIOS.
macshield relax

# 5. Confirm relaxed state. Your personal hostname should be back, stealth
#    mode OFF, state "relaxed".
macshield --check
```

From here, macshield runs automatically. When you connect to an untrusted network, the LaunchAgent triggers `macshield harden`. When you connect to a trusted network, it triggers `macshield relax`. No manual intervention needed.

## How it works

```
WiFi network changes
        |
        v
LaunchAgent fires (WatchPaths on system network plists)
        |
        v
macshield --trigger (runs as your user)
        |
        v
Read current SSID via networksetup
        |
        v
Compute HMAC-SHA256(hardware_uuid, ssid)
        |
        v
Check Keychain for matching hash
        |
    +---+---+
    |       |
 TRUSTED  UNTRUSTED
    |       |
  relax   harden
    |       |
    v       v
sudo exact commands (via sudoers fragment)
```

**Network detection:** A LaunchAgent watches `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist` and `preferences.plist`. Any WiFi change triggers macshield. The agent runs as your user. Privileged commands (stealth mode, hostname, NetBIOS) are elevated via a scoped sudoers fragment that you explicitly approve during installation.

**Trust storage:** Trusted networks are stored as `HMAC-SHA256(hardware_uuid, ssid)` hashes in macOS Keychain under the service `com.macshield.trusted`. The hardware UUID (IOPlatformUUID) is the HMAC key, making hashes machine-bound. Even if Keychain contents are extracted, an attacker sees only hex hashes, not SSID names.

**Why HMAC, not plain SHA-256?** Without a machine-bound key, an attacker could brute-force hashes against the WiGLE database (hundreds of millions of SSIDs). The hardware UUID as HMAC key makes this infeasible without physical access to the machine.

**Post-quantum resistance:** HMAC-SHA256 is considered quantum-resistant. Grover's algorithm reduces hash security from 256-bit to 128-bit effective, but 128-bit remains computationally infeasible. HMAC's keyed construction provides additional resistance beyond raw hash functions. No migration to post-quantum primitives is needed.

## Commands

```
macshield --check          Show current state (no changes)
macshield --status         Alias for --check
macshield trust            Add current WiFi network as trusted
macshield trust --paranoid Remove all trusted networks, always harden
macshield untrust          Remove current network from trusted list
macshield harden           Manually harden now
macshield relax            Manually relax (re-applies on next network change)
macshield relax --for 2h   Temporarily relax for a duration (2h, 30m, 300s)
macshield scan             Scan open ports and generate a local report
macshield scan --purge 5m  Scan and auto-delete the report after a duration
macshield purge            Delete all macshield logs, reports, and temp files
macshield audit            System security posture check (read-only)
macshield connections      Show active TCP connections
macshield persistence      List non-Apple LaunchAgents, LaunchDaemons, login items
macshield permissions      Show apps with sensitive permissions (camera, mic, etc.)
macshield --install        Run the installer
macshield --uninstall      Run the uninstaller
macshield --version        Print version
macshield --help           Print help
```

## Port scanning

`macshield scan` generates a local-only report of all open TCP and UDP ports on your machine. Each port is labeled with what it does (DNS, Bonjour, CUPS, etc.) or flagged as `** REVIEW **` if it's non-standard.

```bash
# Scan and save report to /tmp/macshield-port-report.txt
macshield scan

# Scan and auto-delete the report after 5 minutes
macshield scan --purge 5m

# Delete all macshield logs, reports, and temp files
macshield purge
```

The report is stored at `/tmp/macshield-port-report.txt` with `600` permissions (owner-read only). It is never sent over the network. macshield makes zero network calls, ever.

**Be careful closing ports.** Some ports are required for system features (AirDrop, printing, iCloud sync, screen sharing). The report labels known system ports so you can make informed decisions. Ports marked `** REVIEW **` are worth investigating but may be legitimate (dev servers, Docker, Spotify, etc.).

## Optional security commands

These commands are not run by default and do not modify anything. They are read-only checks to help you understand your system's security posture.

### `macshield audit`

Checks system security settings: SIP, FileVault, Gatekeeper, Application Firewall, stealth mode, Lockdown Mode, Secure Boot, XProtect version, sharing services (SSH, screen sharing, file sharing, remote management, AirDrop), privacy settings (analytics, Siri, Spotlight Suggestions), WiFi security type, DNS servers, ARP table for duplicate MACs (possible MitM), and file hygiene (.ssh permissions, exposed credentials).

Inspired by [Lynis](https://cisofy.com/lynis/), [mOSL](https://github.com/0xmachos/mOSL), and [drduh's macOS Security Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide).

```bash
macshield audit
```

### `macshield connections`

Lists all established TCP connections with process names. Shows which apps are actively communicating and with what remote addresses.

```bash
macshield connections
```

### `macshield persistence`

Lists non-Apple LaunchAgents, LaunchDaemons, login items, cron jobs, and kernel extensions. These are mechanisms that run code automatically at startup or login. Review any entries you don't recognize.

```bash
macshield persistence
```

### `macshield permissions`

Shows which apps have been granted sensitive permissions: screen recording, accessibility, microphone, camera, full disk access, and automation (Apple Events). Reads from the macOS TCC (Transparency, Consent, and Control) database.

Revoke permissions in System Settings > Privacy & Security.

```bash
macshield permissions
```

## Verbose output

macshield prints every action it takes, including the exact commands it runs:

```
[macshield] Network change detected
[macshield] Current SSID: (hidden from logs)
[macshield] Computing network fingerprint...
[macshield] Checking trusted networks in Keychain...
[macshield] Result: UNTRUSTED network
[macshield]
[macshield] Applying protections:
[macshield]   [1/3] Enabling stealth mode (blocks ICMP pings and port scans)
[macshield]         Running: socketfilterfw --setstealthmode on
[macshield]         Done.
[macshield]   [2/3] Setting hostname to generic "MacBook Pro" (hides identity on local network)
[macshield]         Running: scutil --set ComputerName "MacBook Pro"
[macshield]         Running: scutil --set LocalHostName "MacBook-Pro"
[macshield]         Running: scutil --set HostName "MacBook-Pro"
[macshield]         Done.
[macshield]   [3/3] Disabling NetBIOS (closes ports 137/138, stops name broadcast)
[macshield]         Running: launchctl bootout system/com.apple.netbiosd
[macshield]         Done.
[macshield]
[macshield] All protections active. Your Mac is hardened.
```

## Security model

- **No root daemon.** macshield runs as your user via a LaunchAgent. Privileged commands are elevated through a scoped sudoers fragment that you explicitly approve during installation. No process runs persistently as root.
- **Pure bash.** Every line is readable and auditable. No compiled binaries, no helper tools, no frameworks.
- **No network calls.** macshield never phones home, never auto-updates, never sends telemetry.
- **No plaintext secrets.** SSIDs are stored as HMAC hashes in Keychain, never written to disk as cleartext.
- **Ephemeral logs.** All output goes to `/tmp/` and is cleared on reboot. Logs never contain SSIDs.
- **Scoped sudo.** The sudoers fragment grants NOPASSWD for exact commands only (stealth mode on/off, hostname set, NetBIOS control). You can revoke it anytime with `sudo rm /etc/sudoers.d/macshield`.
- **SIP-compatible.** macshield does not modify protected system files. NetBIOS control may be limited on some macOS versions due to SIP, and macshield handles this gracefully.

## Comparison

| Feature | macshield | Little Snitch | Intego NetBarrier | LuLu | ALBATOR |
|---|---|---|---|---|---|
| Network profiles | Auto | Manual rules | Auto | No | No |
| Hostname protection | Yes | No | No | No | Yes (static) |
| Stealth mode toggle | Yes | Yes | Yes | No | Yes (static) |
| NetBIOS control | Yes | No | No | No | No |
| Open source | Yes | No | No | Yes | Yes |
| Price | Free | $69 | $50/yr | Free | Free |
| Network-aware auto-switch | Yes | Via rules | Yes | No | No |
| Pure bash / auditable | Yes | No | No | No | Yes |
| Runs as user (not root) | Yes | No | No | Yes | N/A |

## Do it manually (no script needed)

If you prefer not to install macshield at all, here are the exact commands it runs. You can copy-paste these into Terminal yourself:

**Harden (on untrusted WiFi):**

```bash
# 1. Enable stealth mode (blocks ICMP pings and port scans)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# 2. Set hostname to something generic (replace "MacBook Pro" with your model)
sudo scutil --set ComputerName "MacBook Pro"
sudo scutil --set LocalHostName "MacBook-Pro"
sudo scutil --set HostName "MacBook-Pro"

# 3. Disable NetBIOS (closes ports 137/138)
sudo launchctl bootout system/com.apple.netbiosd
```

**Relax (back on your home network):**

```bash
# 1. Disable stealth mode
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off

# 2. Restore your personal hostname
sudo scutil --set ComputerName "Your Name MacBook"
sudo scutil --set LocalHostName "Your-Name-MacBook"
sudo scutil --set HostName "Your-Name-MacBook"

# 3. Re-enable NetBIOS
sudo launchctl enable system/com.apple.netbiosd
sudo launchctl kickstart system/com.apple.netbiosd
```

**Scan open ports (no install needed):**

```bash
# List all listening TCP ports
lsof -iTCP -sTCP:LISTEN -P -n

# List all UDP ports
lsof -iUDP -P -n
```

**Change DNS (no install needed):**

```bash
# See your current DNS servers
networksetup -getdnsservers Wi-Fi

# Set DNS to Cloudflare (fast, no logging)
networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1

# Set DNS to Quad9 (blocks malware domains, Swiss privacy law)
networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112

# Set DNS to Mullvad (only works if connected to Mullvad VPN)
networksetup -setdnsservers Wi-Fi 100.64.0.7

# Reset DNS to your ISP's default
networksetup -setdnsservers Wi-Fi empty
```

**Configure SOCKS proxy (no install needed):**

```bash
# Route traffic through Tor (install Tor first: brew install tor && tor)
networksetup -setsocksfirewallproxy Wi-Fi localhost 9050
networksetup -setsocksfirewallproxystate Wi-Fi on

# Route traffic through an SSH tunnel
# First, open the tunnel: ssh -D 1080 -N user@your-server.com
networksetup -setsocksfirewallproxy Wi-Fi localhost 1080
networksetup -setsocksfirewallproxystate Wi-Fi on

# Disable SOCKS proxy
networksetup -setsocksfirewallproxystate Wi-Fi off
```

**Check sharing services (no install needed):**

```bash
# See what sharing services are enabled
sudo launchctl list | grep -E "com.apple\.(screensharing|Remote|smbd|ftpd)"

# Check if SSH (Remote Login) is enabled
systemsetup -getremotelogin

# Check if screen sharing is enabled
defaults read /var/db/launchd.db/com.apple.launchd/overrides.plist \
    com.apple.screensharing 2>/dev/null || echo "not configured"
```

**Security audit (no install needed):**

```bash
# Check if SIP is enabled
csrutil status

# Check if FileVault is enabled
fdesetup status

# Check if Gatekeeper is enabled
spctl --status

# Check firewall and stealth mode
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode

# List enabled sharing services (SSH, screen sharing, etc.)
systemsetup -getremotelogin
sudo launchctl list | grep -E "com.apple\.(screensharing|Remote|smbd)"

# Check ARP table for duplicate MACs (possible MitM)
arp -a | awk '{print $4}' | sort | uniq -d

# List non-Apple LaunchAgents
ls ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null | grep -v "^com.apple\."

# Check which apps have microphone access (user TCC database)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```

macshield just automates the hardening commands with network-aware triggering and trusted network detection. That's it. No magic, no binaries, no network calls.

## Build your own VPN (students / researchers)

If you cannot afford a commercial VPN subscription, you can build your own for under $5/month (or free if you already have a server or Raspberry Pi at home). Full control, no third-party provider, no jurisdiction concerns.

**Option 1: Raspberry Pi at home (~$35-75 one-time)**

Run a VPN server on a Raspberry Pi connected to your home network. Traffic tunnels through your home internet when you connect from a cafe or campus.

1. Install [PiVPN](https://pivpn.io) on any Raspberry Pi (Zero 2 W or newer):
   ```bash
   curl -L https://install.pivpn.io | bash
   ```
2. Choose **WireGuard** (faster) or **OpenVPN** (wider compatibility).
3. Generate a client profile: `pivpn add`
4. Transfer the config to your Mac and import into WireGuard or Tunnelblick.
5. Set up port forwarding on your home router (PiVPN tells you which port).
6. Optional: use a free dynamic DNS (DuckDNS, No-IP) if your ISP changes your IP.

Full guide: [PiVPN documentation](https://docs.pivpn.io)

**Option 2: Cloud VPS ($3-5/month)**

Rent a cheap VPS (DigitalOcean, Vultr, Linode, Oracle Cloud free tier) and install WireGuard:

```bash
# On Ubuntu/Debian VPS:
curl -O https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
sudo ./wireguard-install.sh
```

**Option 3: SSH SOCKS tunnel (free)**

If you have SSH access to any server (university, home, cloud):

```bash
ssh -D 1080 -N -f user@your-server.com
networksetup -setsocksfirewallproxy Wi-Fi localhost 1080
networksetup -setsocksfirewallproxystate Wi-Fi on
```

Not as comprehensive as a full VPN (only covers apps that respect the SOCKS proxy), but takes 30 seconds.

**Option 4: OpenVPN on your home router**

Many consumer routers (Asus, Netgear, TP-Link with OpenWrt) support running a VPN server directly. Check your router admin panel under "VPN Server."

**Connecting from macOS:**

```bash
# WireGuard
brew install --cask wireguard-tools

# OpenVPN
brew install --cask tunnelblick
```

**Verify it works:**
```bash
curl -s ifconfig.me    # Should show VPN server IP, not your real IP
```

## A note on security trade-offs

Any security tool introduces its own attack surface. This is sometimes called the **paradox of protection**: the mechanism you install to defend yourself becomes a new thing to defend. A firewall has bugs. A VPN provider sees your traffic. A sudoers fragment grants privilege.

macshield is no exception. By installing it, you add a sudoers fragment, a LaunchAgent, and a bash script to your system. Each is a potential vector. We mitigate this by keeping the tool minimal (pure bash, no dependencies, no network calls, no compiled code), but we won't pretend the risk is zero.

The question is always: does the protection outweigh the surface it introduces? For macshield, the alternative is broadcasting your identity on every public network you join. We think the trade-off is worth it. But you should decide for yourself, and you have every line of code to audit.

## Uninstall

```bash
macshield --uninstall
```

Or run the uninstall script directly:

```bash
./uninstall.sh
```

This removes the binary, LaunchAgent, sudoers fragment, Keychain entries, and ephemeral state files. Your hostname and firewall settings are left as currently set.

## Troubleshooting

### "Not connected to any WiFi network" but I am connected

macshield uses multiple detection methods (`ipconfig`, `networksetup`, `system_profiler`). If none work, check that your WiFi interface is `en0`:

```bash
networksetup -listallhardwareports | grep -A2 "Wi-Fi"
```

If your WiFi is on a different interface, macshield will still detect it. If the issue persists, run `ipconfig getsummary en0` and check if SSID appears in the output.

### LaunchAgent not triggering on network changes

Check if it's loaded:

```bash
launchctl list | grep macshield
```

If not listed, load it:

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.qinnovates.macshield.plist
```

Check the logs after switching networks:

```bash
cat /tmp/macshield.stdout.log
```

### NetBIOS commands fail with SIP error

On some macOS versions, the NetBIOS daemon (`netbiosd`) is protected by System Integrity Protection. macshield handles this gracefully and logs a note. Stealth mode and hostname protection still work normally.

### "macshield: command not found" after Homebrew install

Make sure Homebrew's bin directory is in your PATH:

```bash
echo $PATH | tr ':' '\n' | grep brew
```

If missing, add to your shell profile (`~/.zshrc`):

```bash
eval "$(/opt/homebrew/bin/brew shellenv)"
```

### How do I see which networks are trusted?

Trusted networks are stored as HMAC hashes in Keychain, not as SSID names. You can list the hashes:

```bash
security dump-keychain | grep -A4 "com.macshield.trusted"
```

To check if your current network is trusted:

```bash
macshield --check
```

### How do I revoke macshield's sudo access?

```bash
sudo rm /etc/sudoers.d/macshield
```

macshield will still work but will prompt for your password on each network change.

### Upgrading from v0.2.0 (LaunchDaemon)

The installer automatically removes the old LaunchDaemon when you upgrade. If you want to do it manually:

```bash
sudo launchctl bootout system/com.qinnovates.macshield
sudo rm -f /Library/LaunchDaemons/com.qinnovates.macshield.plist
```

### Uninstall completely

Homebrew:

```bash
brew uninstall macshield
brew untap qinnovates/macshield
sudo rm -f /etc/sudoers.d/macshield
rm -f ~/Library/LaunchAgents/com.qinnovates.macshield.plist
```

Manual:

```bash
macshield --uninstall
```

Or run `./uninstall.sh` from the cloned repo.

## Changelog

### v0.3.0

**No more root daemon. LaunchAgent + scoped sudo.**

The v0.2.0 LaunchDaemon ran as root persistently. Even though the script was auditable, a persistent root process is a larger attack surface than necessary. v0.3.0 replaces it with a LaunchAgent (runs as your user) plus a scoped sudoers fragment that grants NOPASSWD for exact commands only. You explicitly approve the sudoers installation, and you can revoke it anytime with `sudo rm /etc/sudoers.d/macshield`.

### v0.2.0

**Replaced sudoers fragment with LaunchDaemon.**

The v0.1.0 design installed a sudoers file with wildcard permissions. v0.2.0 replaced it with a LaunchDaemon running as root. v0.3.0 further improves this.

### v0.1.0

Initial release. Network-aware auto-hardening with stealth mode, hostname protection, NetBIOS control, HMAC-SHA256 trust storage in Keychain, Homebrew tap.

Full changelog: [CHANGELOG.md](CHANGELOG.md)

## Requirements

- macOS 12 (Monterey) or later
- Admin account (member of the `admin` group)
- WiFi interface

## License

Apache 2.0. See [LICENSE](LICENSE).

## Contributing

Issues and pull requests welcome at [github.com/qinnovates/macshield](https://github.com/qinnovates/macshield).
