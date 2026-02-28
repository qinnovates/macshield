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
  ║        >> macos security analyzer & best practices report <<         ║
  ║        >> read-only | zero attack surface | pure bash <<             ║
  ║                                                                      ║
  ╚══════════════════════════════════════════════════════════════════════╝
```

Current version: 0.5.0

Read-only macOS security analyzer. Checks your system security posture, scans ports, lists persistence items, audits app permissions. No system modifications. No background processes. No sudo. Zero attack surface.

## Table of contents

- [Why it exists](#why-it-exists)
- [What it does](#what-it-does)
- [Install](#install)
- [Commands](#commands)
- [Port scanning](#port-scanning)
- [Security audit](#security-audit)
- [Persistence check](#persistence-check)
- [Harden your Mac manually](#harden-your-mac-manually)
- [Understanding DNS, VPNs, proxies, and where macshield fits](#understanding-dns-vpns-proxies-and-where-macshield-fits)
- [Free VPN: Cloudflare WARP vs ProtonVPN](#free-vpn-cloudflare-warp-vs-protonvpn)
- [Build your own VPN](#build-your-own-vpn-students--researchers)
- [Security model](#security-model)
- [Comparison](#comparison)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)

---

> **If you work in an enterprise, institution, or clinical setting**, you MUST use your organization's corporate VPN, managed devices, and enterprise security policies. macshield is not a substitute for enterprise security infrastructure. **Qinnovates is not liable for any security compromises resulting from the use of macshield in lieu of proper enterprise or institutional security controls.**

macshield is for **students, independent researchers, and individuals** who want visibility into their Mac's security posture. It tells you what's exposed and teaches you how to fix it. macshield does not modify your system -- you decide what to change and run the commands yourself.

## Why it exists

Any security tool that modifies your system introduces its own attack surface. This is the **paradox of protection**: the mechanism you install to defend yourself becomes a new thing to defend. A LaunchAgent can be hijacked. A sudoers fragment grants privilege. An automated trigger runs without your knowledge.

Previous versions of macshield included a LaunchAgent that auto-hardened on network changes. We removed it because dynamic security automation is itself an attack vector. A compromised plist can swap the binary target, and automated SSID detection runs without user interaction.

macshield v0.5.0 takes a different approach: **analyze and educate, don't automate**. It tells you exactly what's wrong and gives you the commands to fix it. You run them yourself. The tool's attack surface is zero because it never modifies anything.

## What it does

| Command | What it checks |
|---|---|
| `macshield audit` | SIP, FileVault, Gatekeeper, firewall, stealth mode, Lockdown Mode, Secure Boot, XProtect, sharing services, privacy settings, WiFi security, ARP table, file hygiene |
| `macshield scan` | Open TCP/UDP ports, listening processes, firewall status |
| `macshield connections` | Active TCP connections with process names and remote endpoints |
| `macshield persistence` | Non-Apple LaunchAgents, LaunchDaemons, login items, cron jobs, kernel extensions |
| `macshield permissions` | TCC database: screen recording, accessibility, microphone, camera, full disk access, automation |

All commands are **read-only**. No sudo. No Keychain writes. No state files. No background processes. No network calls.

## Install

### Homebrew (recommended)

```bash
brew tap qinnovates/tools
brew install macshield
```

### Manual

```bash
git clone https://github.com/qinnovates/macshield.git
cd macshield
chmod +x install.sh macshield.sh
./install.sh
```

The installer copies `macshield.sh` to `/usr/local/bin/macshield`. That's it.

## Commands

```
macshield scan             Scan open ports (display only, nothing saved to disk)
macshield scan --purge 5m  Scan, save report to disk, auto-delete after duration
macshield scan --quiet     Scan without prompts, display only
macshield audit            System security posture check (read-only)
macshield connections      Show active TCP connections
macshield persistence      List non-Apple LaunchAgents, LaunchDaemons, login items
macshield permissions      Show apps with sensitive permissions (camera, mic, etc.)
macshield purge            Delete all macshield logs, reports, and temp files
macshield --version        Print version
macshield --help           Print help
```

## Port scanning

`macshield scan` scans all open TCP and UDP ports on your machine using `lsof`. Each port is labeled with what it does (DNS, Bonjour, CUPS, AirPlay, etc.) or flagged as `** REVIEW **` if it's non-standard.

**Before the scan runs, macshield tells you exactly what it will do, what it will not do, and asks for your explicit permission.** Nothing happens without your consent.

**What port scanning tells you:** Which services on your Mac are listening for incoming connections. Useful for spotting unexpected listeners (a dev server you forgot, a service you didn't enable, or something you don't recognize).

**What it does NOT do:** It does not close ports, disable services, or change anything. It does not scan other machines. It reads local state from `lsof` and `socketfilterfw` only. Zero packets leave your machine.

Example output:

```
================================================================
  macshield Port Scan Report
  Generated: 2026-02-28 09:30:15
  Host: MacBook Pro
================================================================

--- TCP LISTENING PORTS ---

  PORT     PROCESS                  PID      NOTE
  ----------------------------------------------------------------------
  631      cupsd                    442      CUPS (printing)
  5000     ControlCe                1203     AirPlay / UPnP
  7000     ControlCe                1203     AirPlay streaming

  Total TCP listeners: 3
  Ports to review: 0

--- UDP PORTS ---

  PORT     PROCESS                  PID      NOTE
  ----------------------------------------------------------------------
  53       mDNSRespo                312      DNS (domain name resolution)
  5353     mDNSRespo                312      mDNS / Bonjour
  137      netbiosd                 445      NetBIOS name service

  Total UDP ports: 3

--- FIREWALL STATUS ---

  Firewall: Firewall is enabled. (State = 1)
  Stealth mode: Stealth mode enabled.

================================================================
```

### Safe on any network

You can run `macshield scan` on any network, including public WiFi, without risk. It sends zero packets to the network. Nothing for a network monitor to detect.

### Saving reports

```bash
macshield scan --purge 5m    # Save report, auto-delete after 5 minutes
macshield scan --quiet       # Display only, no prompts
```

## Security audit

`macshield audit` runs a full security posture check with color-coded PASS/WARN/FAIL results.

**What it checks:**

| Category | Checks |
|----------|--------|
| System Protection | SIP, FileVault, Gatekeeper, Firewall, Stealth mode, Lockdown Mode, Secure Boot, XProtect |
| Sharing Services | Remote Login (SSH), Screen Sharing, File Sharing (SMB), Remote Management (ARD), Remote Apple Events, Bluetooth, AirDrop |
| Privacy Settings | Mac Analytics, Siri, Spotlight Suggestions, Personalized Ads |
| WiFi Security | Encryption type (WPA3/WPA2/WEP/Open), Private WiFi Address (MAC randomization), DNS servers |
| ARP Table | Duplicate MAC addresses (possible ARP spoofing / man-in-the-middle attack) |
| File Hygiene | .ssh directory permissions, SSH key permissions, .env files near home, plaintext .git-credentials, .netrc permissions |

## Persistence check

`macshield persistence` lists everything that runs code automatically on your Mac that isn't from Apple:

- **User LaunchAgents** (`~/Library/LaunchAgents/`)
- **System LaunchAgents** (`/Library/LaunchAgents/`)
- **System LaunchDaemons** (`/Library/LaunchDaemons/`)
- **Login Items**
- **Cron Jobs**
- **Non-Apple Kernel Extensions**

Review any entries you don't recognize. This is one of the most useful checks for spotting unwanted software.

## Harden your Mac manually

macshield tells you what's exposed. Here are the commands to fix it yourself:

**Enable stealth mode** (blocks ICMP pings and port scans):

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
```

**Set hostname to generic** (prevents identity leaking on public WiFi):

```bash
sudo scutil --set ComputerName "MacBook Pro"
sudo scutil --set LocalHostName "MacBook-Pro"
sudo scutil --set HostName "MacBook-Pro"
```

**Disable NetBIOS** (closes ports 137/138):

```bash
sudo launchctl bootout system/com.apple.netbiosd
```

**Set privacy-focused DNS** (Quad9, blocks malware domains):

```bash
networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112
```

**Undo everything:**

```bash
# Disable stealth mode
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off

# Restore your personal hostname
sudo scutil --set ComputerName "Your Name MacBook"
sudo scutil --set LocalHostName "Your-Name-MacBook"
sudo scutil --set HostName "Your-Name-MacBook"

# Re-enable NetBIOS
sudo launchctl enable system/com.apple.netbiosd
sudo launchctl kickstart system/com.apple.netbiosd

# Reset DNS to ISP default
networksetup -setdnsservers Wi-Fi empty
sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder
```

## Understanding DNS, VPNs, proxies, and where macshield fits

### DNS (Domain Name System)

**What it does:** Translates domain names into IP addresses. Every time you visit a website, your device asks a DNS server "where is this?"

**Who sees your queries:** By default, your ISP's DNS server. They see every domain you visit and may sell it to advertisers.

**What changing DNS does:** Switching to Cloudflare (1.1.1.1) or Quad9 (9.9.9.9) means your ISP no longer sees your DNS queries. Quad9 also blocks known malware domains.

**What it does NOT do:** Changing DNS does not encrypt your traffic or hide your IP address. It is not a VPN.

### VPN (Virtual Private Network)

**What it does:** Encrypts all traffic between your device and the VPN server. Your ISP sees encrypted data going to one IP address.

**What it does NOT do:** A VPN does not hide your hostname on the local network. It does not block local network reconnaissance (ARP, mDNS, NetBIOS). It does not protect against malware on your device.

### Where macshield fits

macshield is an analyzer. It checks whether your system is configured securely and tells you what to fix. It doesn't overlap with DNS providers or VPNs -- it checks whether you're using them properly.

### DNS providers

| Provider | Addresses | Malware blocking | Jurisdiction | Organization |
|----------|-----------|-----------------|--------------|-------------|
| Quad9 | 9.9.9.9, 149.112.112.112 | Yes | Switzerland | Non-profit |
| Cloudflare | 1.1.1.1, 1.0.0.1 | No | United States | For-profit |
| Mullvad | 100.64.0.7 | No | Sweden | For-profit (VPN company) |

### Free VPN: Cloudflare WARP vs ProtonVPN

| | Cloudflare WARP | ProtonVPN Free |
|---|---|---|
| **Best for** | **Security** | **Privacy** |
| **Jurisdiction** | United States (Cloudflare Inc.) | Switzerland (Proton AG) |
| **Speed** | Fastest (300+ global edge nodes) | Good (5 free server locations) |
| **Malware-blocking DNS** | Free (1.1.1.2) | Paid only (NetShield) |
| **Bandwidth cap** | None | None |
| **Open-source client** | No | Yes (independently audited) |
| **No-logs verification** | Metadata deleted in 24h | Court-tested: subpoenaed in 2019, had nothing to hand over |
| **Install** | `brew install --cask cloudflare-warp` | `brew install --cask protonvpn` |

## Build your own VPN (students / researchers)

If you cannot afford a commercial VPN subscription, you can build your own for under $5/month.

**Option 1: Raspberry Pi at home (~$35-75 one-time)**

Install [PiVPN](https://pivpn.io) on any Raspberry Pi. Traffic tunnels through your home internet.

**Option 2: Cloud VPS ($3-5/month)**

Rent a cheap VPS (DigitalOcean, Vultr, Oracle Cloud free tier) and install WireGuard.

**Option 3: SSH SOCKS tunnel (free)**

```bash
ssh -D 1080 -N -f user@your-server.com
networksetup -setsocksfirewallproxy Wi-Fi localhost 1080
networksetup -setsocksfirewallproxystate Wi-Fi on
```

## Security model

- **Zero attack surface.** macshield is read-only. No sudo, no Keychain writes, no state files, no background processes. Nothing to compromise.
- **Pure bash.** Every line is readable and auditable. No compiled binaries, no helper tools, no frameworks.
- **No network calls.** macshield never phones home, never auto-updates, never sends telemetry.
- **No persistence.** No LaunchAgent, no daemon, no cron job. macshield runs only when you invoke it.

## Comparison

| Feature | macshield | Little Snitch | Intego NetBarrier | LuLu | ALBATOR |
|---|---|---|---|---|---|
| Security audit | Yes | No | No | No | Yes (static) |
| Port scanning | Yes | No | No | No | No |
| Persistence check | Yes | No | No | No | No |
| Permissions audit | Yes | No | No | No | No |
| Connection monitor | Yes | Yes | Yes | Yes | No |
| Open source | Yes | No | No | Yes | Yes |
| Price | Free | $69 | $50/yr | Free | Free |
| Pure bash / auditable | Yes | No | No | No | Yes |
| Modifies system | No | Yes | Yes | Yes | Yes |
| Background process | No | Yes | Yes | Yes | N/A |

## Uninstall

```bash
macshield --uninstall
```

Or manually:

```bash
sudo rm /usr/local/bin/macshield
```

Homebrew:

```bash
brew uninstall macshield
brew untap qinnovates/tools
```

The uninstaller also cleans up legacy artifacts from older macshield versions (LaunchAgents, LaunchDaemons, sudoers fragments, Keychain entries).

## Troubleshooting

### "macshield: command not found" after Homebrew install

```bash
eval "$(/opt/homebrew/bin/brew shellenv)"
```

### Upgrading from v0.4.x or earlier

Older versions installed a LaunchAgent, sudoers fragment, and Keychain entries. Run the new uninstaller to clean up:

```bash
./uninstall.sh
```

Or clean up manually:

```bash
launchctl bootout gui/$(id -u)/com.qinnovates.macshield 2>/dev/null
rm -f ~/Library/LaunchAgents/com.qinnovates.macshield.plist
sudo rm -f /Library/LaunchDaemons/com.qinnovates.macshield.plist
sudo rm -f /etc/sudoers.d/macshield
```

## Changelog

### v0.5.0

**Analyzer-only. Removed all system modifications.**

Any security tool that modifies your system introduces its own attack surface -- the paradox of protection. Previous versions included a LaunchAgent, sudoers fragment, HMAC-based trust storage, and automated triggering on network changes. Each was a potential vector: a compromised plist could swap the binary target, the sudoers fragment granted privilege, and automated SSID detection ran without user interaction.

v0.5.0 strips macshield down to pure read-only analysis with zero attack surface. The tool tells you what's wrong and teaches you how to fix it. You run the commands yourself.

- Removed: `harden`, `relax`, `trust`, `untrust`, `--trigger`, `--check`, `setup`
- Removed: LaunchAgent, LaunchDaemon, sudoers fragment, Keychain writes, HMAC trust storage, integrity check, state tracking
- Removed: `install.sh` setup wizard (8 steps reduced to 1: copy the binary)
- Kept: `scan`, `audit`, `connections`, `persistence`, `permissions`, `purge`
- Added: Manual hardening commands in help text and README
- Uninstaller cleans up all legacy artifacts from older versions

### v0.4.1

**Self-integrity check.**

- On install, macshield stored a SHA-256 hash in Keychain and verified on launch

### v0.4.0

**Free VPN options. Full-stack protection for students on public WiFi.**

- Added Cloudflare WARP and ProtonVPN to installer
- DNS step context-aware based on VPN choice

### v0.3.0

**LaunchAgent + scoped sudo. Color output. Security reports.**

- Added: `scan`, `audit`, `connections`, `persistence`, `permissions`

### v0.2.0

**Replaced sudoers fragment with LaunchDaemon.**

### v0.1.0

Initial release. Stealth mode, hostname protection, NetBIOS control, HMAC-SHA256 trust storage, Homebrew tap.

Full changelog: [CHANGELOG.md](CHANGELOG.md)
