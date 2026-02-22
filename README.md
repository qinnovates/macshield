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
- [Free VPN: Cloudflare WARP vs ProtonVPN](#free-vpn-cloudflare-warp-vs-protonvpn)
- [Verify it works](#verify-it-works)
- [How it works](#how-it-works)
- [Commands](#commands)
- [Port scanning](#port-scanning)
- [Timed relax](#timed-relax)
- [Paranoid mode](#paranoid-mode)
- [Optional security commands](#optional-security-commands)
- [Security model](#security-model)
- [Do it manually](#do-it-manually-no-script-needed)
- [Build your own VPN](#build-your-own-vpn-students--researchers)
- [Comparison](#comparison)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)
- [Upcoming: Menu bar app](#upcoming-menu-bar-app)

---

> **If you work in an enterprise, institution, or clinical setting**, you MUST use your organization's corporate VPN, managed devices, and enterprise security policies. macshield is not a substitute for enterprise security infrastructure. If your organization handles PII, neural recordings, HIPAA-covered data, or any sensitive research data, adhere to your corporate device and security policies at all times. **Qinnovates is not liable for any security compromises resulting from the use of macshield in lieu of proper enterprise or institutional security controls.**

macshield is for **students, independent researchers, and individuals** who want baseline device hardening on public WiFi. It secures your local network identity (Layer 2), reduces potential for malware (with Quad9 DNS), and avoids routing your DNS queries through unknown public WiFi infrastructure where you have no visibility into where they go. It is not a VPN, does not encrypt traffic, and does not replace enterprise security. See [Build your own VPN](#build-your-own-vpn-students--researchers) if you need traffic encryption on a budget.

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

**What it does:** Secures your local network identity (Layer 2). Enables stealth mode (blocks pings and port scans), sets a generic hostname (so you don't broadcast "Kevin's MacBook Pro" to everyone on the WiFi), and disables NetBIOS (closes ports 137/138). With Quad9 DNS configured, it also blocks known malware domains and avoids routing your DNS queries through the public WiFi's own DNS infrastructure, which you have no control over or visibility into.

**What it protects:** Prevents passive reconnaissance on the local network. Stops your real name from leaking via hostname. Makes your Mac less visible to anyone scanning the same WiFi. Reduces potential for malware by blocking malicious domains at the DNS level.

**What it does NOT do:** macshield does not encrypt your traffic, does not hide your IP address, does not replace a VPN, and does not make you anonymous.

### How they work together

```
Layer 4 - VPN          Encrypts all traffic, hides your IP from websites
Layer 3 - WARP/Proxy   Routes traffic through encrypted tunnel (optional)
Layer 2 - DNS          Controls who resolves your domain lookups
Layer 1 - macshield    Secures your identity on the local network (L2)
```

Each layer protects something different. Using a VPN without macshield still broadcasts your hostname to everyone on the local WiFi. Using macshield without a VPN still exposes your traffic to your ISP. They are complementary, not interchangeable. The macshield installer optionally installs Cloudflare WARP (a free VPN) to cover Layers 3-4 alongside macshield's Layer 2 protection.

In OSI terms, VPNs operate at Layer 3+ (Network and above). In the [QIF security model](https://github.com/qinnovates/qinnovate/blob/main/qif-framework/QIF-TRUTH.md), VPNs operate at the **S3 band** (Application). The attacks macshield blocks happen at the **S1 band** (Analog Front-End), below the VPN tunnel. In BCI systems, compromising S1 can propagate upward through S2, S3, through I0 (the neural interface), and into the neural domain. macshield defends the silicon domain floor.

The macshield installer optionally configures DNS and SOCKS proxy settings during setup, but these are standard macOS system settings. macshield does not provide or run a VPN, DNS server, or proxy server. It just helps you configure the ones you choose.

## Install

### Homebrew (recommended)

```bash
brew tap qinnovates/tools
brew install macshield
```

After install, run the interactive setup:

```bash
macshield setup
```

The setup walks you through 8 steps with explicit yes/no consent at each:

1. **Binary install** (skipped if Homebrew already installed it)
2. **Sudoers authorization** for exact privileged commands (stealth mode, hostname, NetBIOS)
3. **LaunchAgent** that auto-triggers on WiFi changes (runs as your user, not root)
4. **Trust current network** (optional)
5. **Hostname consent** with warning about what changes and how restoration works
6. **Free VPN** (optional): Cloudflare WARP (best for security) or ProtonVPN (best for privacy). See [VPN comparison](#free-vpn-cloudflare-warp-vs-protonvpn) below.
7. **DNS configuration** (optional, context-aware): adapts based on your VPN choice. Recommends Quad9 if you picked ProtonVPN (free tier has no malware blocking).
8. **SOCKS proxy** (optional): SSH tunnel, custom, or skip. If you don't know what a SOCKS proxy is, skip this step.

### DNS providers

The installer offers three privacy-focused DNS providers:

| Provider | Addresses | Malware blocking | Jurisdiction | Organization |
|----------|-----------|-----------------|--------------|-------------|
| Quad9 | 9.9.9.9, 149.112.112.112 | Yes | Switzerland | Non-profit |
| Cloudflare | 1.1.1.1, 1.0.0.1 | No | United States | For-profit |
| Mullvad | 100.64.0.7 | No | Sweden | For-profit (VPN company) |

Quad9 is listed first because it actively blocks known malware domains at the DNS level and operates under Swiss privacy law, which is stronger than US law for data protection. Cloudflare is the fastest. Mullvad DNS only works if you are connected to Mullvad VPN.

All three are significant improvements over your ISP's default DNS, which typically logs your browsing history.

### Free VPN: Cloudflare WARP vs ProtonVPN

macshield covers Layer 2 (local network identity). A VPN covers Layer 3+ (traffic encryption). Together they give you both layers of protection for free. The installer offers two options:

| | Cloudflare WARP | ProtonVPN Free |
|---|---|---|
| **Best for** | **Security** | **Privacy** |
| **Jurisdiction** | United States (Cloudflare Inc.) | Switzerland (Proton AG) |
| **Speed** | Fastest (300+ global edge nodes) | Good (5 free server locations) |
| **Malware-blocking DNS** | Free (1.1.1.2) | Paid only (NetShield) |
| **Bandwidth cap** | None | None |
| **Open-source client** | No | Yes (independently audited) |
| **Device limit** | None | 1 on free tier |
| **No-logs verification** | Metadata deleted in 24h | Court-tested: subpoenaed in 2019, had nothing to hand over |
| **Protocol** | WireGuard | WireGuard (Stealth) |
| **Independent audits** | 4 annual audits (Securitum) | 4 annual audits (Securitum) |
| **Install** | `brew install --cask cloudflare-warp` | `brew install --cask protonvpn` |
| **Download** | [https://1.1.1.1](https://1.1.1.1) | [https://protonvpn.com](https://protonvpn.com/download) |

**WARP** is the better choice if you want the fastest connection with built-in malware blocking at no cost. **ProtonVPN** is the better choice if jurisdiction matters to you (Swiss privacy law) and you want an open-source, court-proven no-logs client.

Both run as menu bar apps. You toggle them on/off yourself. macshield does not manage or interact with either VPN. They are independent tools.

**DNS behavior with each VPN:**

When a VPN is connected, it handles DNS through its own tunnel, bypassing whatever system DNS you set in Step 7. Your Step 7 DNS choice kicks back in automatically whenever you disconnect the VPN.

- **WARP connected:** DNS goes through Cloudflare (1.1.1.2 with malware blocking if enabled, 1.1.1.1 without)
- **ProtonVPN connected (free):** DNS goes through Proton's servers, no malware blocking
- **VPN disconnected:** Your Step 7 DNS choice applies (Quad9, Cloudflare, Mullvad, or ISP default)

The installer is context-aware: if you pick ProtonVPN, it recommends Quad9 in Step 7 so you have malware-blocking DNS at least when ProtonVPN is off.

**WARP malware blocking:**

The installer automatically configures malware blocking after installing WARP. If you skipped it or want to change it later:

```bash
# Block known malware domains (recommended)
warp-cli dns families malware

# Block malware + adult content
warp-cli dns families full

# Disable filtering (default)
warp-cli dns families off
```

| Profile | DNS | What it blocks |
|---------|-----|----------------|
| Default | 1.1.1.1 | Nothing (privacy only) |
| Malware | 1.1.1.2 | Known malware domains |
| Family | 1.1.1.3 | Malware + adult content |

### Manual install

```bash
git clone https://github.com/qinnovates/macshield.git
cd macshield
chmod +x install.sh macshield.sh
./install.sh
```

The installer walks through the same 8 interactive steps described above.

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
macshield setup            Run the interactive setup (DNS, proxy, trust, hostname)
macshield --check          Show current state (no changes)
macshield --status         Alias for --check
macshield trust            Add current WiFi network as trusted
macshield trust --paranoid Remove all trusted networks, always harden
macshield untrust          Remove current network from trusted list
macshield harden           Manually harden now
macshield relax            Manually relax (re-applies on next network change)
macshield relax --for 2h   Temporarily relax for a duration (2h, 30m, 300s)
macshield scan             Scan open ports (display only, nothing saved to disk)
macshield scan --purge 5m  Scan, save report to disk, auto-delete after duration
macshield scan --quiet     Scan without prompts (display only, no save)
macshield purge            Delete all macshield logs, reports, and temp files
macshield audit            System security posture check (read-only)
macshield connections      Show active TCP connections
macshield persistence      List non-Apple LaunchAgents, LaunchDaemons, login items
macshield permissions      Show apps with sensitive permissions (camera, mic, etc.)
macshield --install        Run the installer (alias for setup)
macshield --uninstall      Run the uninstaller
macshield --version        Print version
macshield --help           Print help
```

## Port scanning

`macshield scan` scans all open TCP and UDP ports on your machine using `lsof`. Each port is labeled with what it does (DNS, Bonjour, CUPS, AirPlay, etc.) or flagged as `** REVIEW **` if it's non-standard.

**Before the scan runs, macshield tells you exactly what it will do, what it will not do, and asks for your explicit permission.** Nothing happens without your consent. Here is the preamble you see:

```
[macshield] === Port Scan ===

[macshield] What this does:
[macshield]   Scans your Mac for all open TCP and UDP ports using 'lsof'.
[macshield]   Labels each port with what it does (DNS, Bonjour, AirPlay, etc.).
[macshield]   Flags non-standard ports as ** REVIEW ** for your attention.

[macshield] What this does NOT do:
[macshield]   - No network calls. The scan reads local system state only.
[macshield]   - No data leaves your machine. Ever.

[macshield] What happens to the results:
[macshield]   Results are displayed to your terminal and never saved to disk.
[macshield]   Once you close or scroll past the output, they are gone.
[macshield]   No files are created. No traces are left.

[macshield] Proceed with port scan? [y/N]:
```

If you type anything other than `y`, the scan does not run.

**What port scanning tells you:** Which services on your Mac are listening for incoming connections. This is useful for spotting unexpected listeners (a dev server you forgot, a service you did not enable, or something you do not recognize). It does not scan other machines, does not probe remote hosts, and does not send any packets. It reads local state from `lsof` and `socketfilterfw`.

**What port scanning does not do:** It does not close ports, disable services, or change anything. It is read-only. Closing a port requires you to manually stop the service behind it, and the report warns you that doing so may break system features (AirDrop, printing, iCloud sync, screen sharing, etc.).

**Risks:** None from the scan itself. The only risk is if you act on the results without understanding what a service does. For example, closing port 5353 disables Bonjour/mDNS, which breaks AirDrop and local device discovery. The report labels known system ports so you can make informed decisions before changing anything.

### Default behavior (display only, nothing saved to disk)

```bash
macshield scan
```

Reports are **never saved to disk** by default. The scan displays results to your terminal and that's it. No files are created, no traces are left. This is the security-first default.

Example output:

```
================================================================
  macshield Port Scan Report
  Generated: 2026-02-21 09:30:15
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

--- WARNINGS ---

  Closing ports may break system features (AirDrop, printing,
  iCloud sync, screen sharing, etc). Research each port before
  disabling the service behind it.

  Ports marked ** REVIEW ** are non-standard and worth investigating.
  They may be legitimate (dev servers, Docker, etc.) or unexpected.

================================================================
```

### Saving reports (scripting only, always self-destructs)

If you need a temporary file for scripting or automation, use the `--purge` flag. The report is saved to disk and **always auto-deletes** after the duration you specify. There is no option to keep reports permanently.

```bash
macshield scan --purge 5m    # Save report, auto-delete after 5 minutes
macshield scan --purge 30m   # Save report, auto-delete after 30 minutes
```

The saved report is at `/tmp/macshield-port-report.txt` with `600` permissions (owner-read only). It is never sent over the network. It self-destructs after your chosen duration.

### Scripting / non-interactive modes

```bash
# Display only, no prompts, no save
macshield scan --quiet

# Save report, auto-delete after 5 minutes (no prompts)
macshield scan --purge 5m
```

### Manual cleanup

```bash
# Delete all macshield logs, reports, and temp files
macshield purge
```

`macshield purge` removes: scan reports, audit reports, stdout/stderr logs, state files, and lock files. macshield itself stays installed.

**Be careful closing ports.** Some ports are required for system features (AirDrop, printing, iCloud sync, screen sharing). The report labels known system ports so you can make informed decisions. Ports marked `** REVIEW **` are worth investigating but may be legitimate (dev servers, Docker, Spotify, etc.).

### Safe on any network (zero network calls)

**You can run `macshield scan` on any network, including public WiFi, without risk of alerting network administrators.** The scan uses only `lsof` (reads your own machine's kernel state) and `socketfilterfw` (checks local firewall status). It sends zero packets to the network. No ARP requests, no SYN probes, no ICMP, no DNS lookups. There is nothing for a network monitor to detect because nothing leaves your machine.

This is fundamentally different from network scanners like `nmap` or `masscan`, which send packets to remote hosts and can trigger intrusion detection systems. `macshield scan` never touches the network.

You can verify this yourself:

```bash
grep -n 'curl\|wget\|nc ' $(which macshield)
```

## Timed relax

Temporarily relax protections for a set duration. Useful when you need AirDrop or Spotify Connect on an untrusted network:

```bash
macshield relax --for 2h    # Relax for 2 hours, then auto-harden
macshield relax --for 30m   # Relax for 30 minutes
macshield relax --for 300s  # Relax for 300 seconds
```

When the timer expires, macshield automatically re-hardens. If you just run `macshield relax` without `--for`, protections stay relaxed until the next network change.

## Paranoid mode

Remove all trusted networks and treat every network as untrusted:

```bash
macshield trust --paranoid
```

This clears all trusted network hashes from Keychain and immediately hardens. macshield will never auto-relax until you explicitly trust a network again with `macshield trust`.

## Optional security commands

These commands are not run by default and do not modify anything. They are read-only checks to help you understand your system's security posture. No data leaves your machine.

### `macshield audit`

Full system security posture check with color-coded PASS/WARN/FAIL results.

```bash
macshield audit
```

**What it checks:**

| Category | Checks |
|----------|--------|
| System Protection | SIP, FileVault, Gatekeeper, Firewall, Stealth mode, Lockdown Mode, Secure Boot, XProtect |
| Sharing Services | Remote Login (SSH), Screen Sharing, File Sharing (SMB), Remote Management (ARD), Remote Apple Events, Bluetooth, AirDrop |
| Privacy Settings | Mac Analytics, Siri, Spotlight Suggestions, Personalized Ads |
| WiFi Security | Encryption type (WPA3/WPA2/WEP/Open), Private WiFi Address (MAC randomization), DNS servers |
| ARP Table | Duplicate MAC addresses (possible ARP spoofing / man-in-the-middle attack) |
| File Hygiene | .ssh directory permissions, SSH key permissions, .env files near home, plaintext .git-credentials, .netrc permissions |

Example output:

```
[macshield] --- System Protection ---

  [PASS] System Integrity Protection (SIP) - enabled
  [PASS] FileVault disk encryption - enabled
  [PASS] Gatekeeper - enabled
  [PASS] Application Firewall - enabled
  [PASS] Stealth mode - enabled
  [INFO] Lockdown Mode - not enabled (extreme protection, breaks many features)

[macshield] --- Sharing Services ---

  [PASS] Remote Login (SSH) - disabled
  [PASS] Screen Sharing - disabled
  [PASS] File Sharing (SMB) - disabled
  [PASS] Remote Management (ARD) - disabled
  [PASS] Remote Apple Events - disabled
  [PASS] AirDrop - contacts only

[macshield] --- Privacy Settings ---

  [WARN] Share Mac Analytics - enabled (sends usage data to Apple)
  [INFO] Siri - enabled (sends voice data to Apple for processing)
  [PASS] Spotlight Suggestions - disabled (queries stay local)
  [PASS] Personalized Ads - disabled

[macshield] --- WiFi Security ---

  [PASS] WiFi security - WPA3 Personal
  [PASS] Private WiFi Address - enabled (MAC randomization)

[macshield] --- ARP Table (MitM Detection) ---

  [PASS] ARP table - no duplicate MAC addresses (no obvious ARP spoofing)

[macshield] --- File Hygiene ---

  [PASS] .ssh directory - permissions 700
  [PASS] SSH key permissions - all 2 private keys have correct permissions
  [WARN] .env files found - 3 file(s) near home directory (may contain secrets)

[macshield] --- Summary ---

  PASS: 16  |  WARN: 2  |  FAIL: 0
```

Inspired by [Lynis](https://cisofy.com/lynis/), [mOSL](https://github.com/0xmachos/mOSL), and [drduh's macOS Security Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide).

### `macshield connections`

Lists all established TCP connections with process names and remote addresses. Shows exactly who your Mac is talking to right now.

```bash
macshield connections
```

Example output:

```
[macshield] === Active Connections ===

  PROCESS              PID      REMOTE                                   LOCAL PORT
  ------------------------------------------------------------------------------------------
  Safari               1842     17.253.144.10:443                        52301
  Spotify              2103     35.186.224.25:4070                       55102
  cloudphotod          487      17.248.133.60:443                        51204

  Total unique connections: 3
```

### `macshield persistence`

Lists non-Apple LaunchAgents, LaunchDaemons, login items, cron jobs, and kernel extensions. These are mechanisms that run code automatically at startup or login. Review any entries you don't recognize.

```bash
macshield persistence
```

Example output:

```
[macshield] --- User LaunchAgents (~/Library/LaunchAgents) ---

  com.qinnovates.macshield                    /opt/homebrew/bin/macshield
  com.spotify.webhelper                       /Applications/Spotify.app/...

[macshield] --- System LaunchAgents (/Library/LaunchAgents) ---

  (none)

[macshield] --- System LaunchDaemons (/Library/LaunchDaemons) ---

  com.docker.vmnetd                           /Library/PrivilegedHelperTools/...

[macshield] --- Login Items ---

  (none or could not read)

[macshield] --- Cron Jobs ---

  (none)

[macshield] --- Non-Apple Kernel Extensions ---

  (none)

  Total non-Apple persistence items: 3
```

### `macshield permissions`

Shows which apps have been granted sensitive permissions by reading the macOS TCC (Transparency, Consent, and Control) database. Covers: screen recording, accessibility, microphone, camera, full disk access, and automation (Apple Events).

```bash
macshield permissions
```

Example output:

```
[macshield] === Permissions Audit (TCC) ===

  Screen Recording:
    - com.loom.desktop
    - us.zoom.xos

  Accessibility:
    - com.raycast.macos
    - com.1password.1password

  Microphone:
    - us.zoom.xos
    - com.spotify.client

  Camera:
    - us.zoom.xos

  Full Disk Access:
    - com.apple.Terminal

  Automation (Apple Events):
    - com.googlecode.iterm2
```

Revoke permissions in System Settings > Privacy & Security.

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
- **Self-integrity check.** On install, macshield stores a SHA-256 hash of itself in Keychain. On every launch, it verifies the hash matches before executing. If the binary has been modified, macshield refuses to run and warns you. Re-install to store a new hash.
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

# Set DNS to Quad9 (blocks malware domains, Swiss privacy law, non-profit)
networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112

# Set DNS to Cloudflare (fastest, no logging, US-based)
networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1

# Set DNS to Mullvad (only works if connected to Mullvad VPN)
networksetup -setdnsservers Wi-Fi 100.64.0.7

# Reset DNS to your ISP's default
networksetup -setdnsservers Wi-Fi empty
```

**Configure SOCKS proxy (no install needed):**

Skip this if you don't know what a SOCKS proxy is. Misconfiguring a proxy will break your internet connection.

```bash
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

## Reverting changes

If you configured DNS or a SOCKS proxy during setup and are experiencing issues (websites not loading, slow browsing, connection errors), here is how to revert each change:

### Reset DNS to default

If websites won't load or DNS resolution is slow after changing DNS:

```bash
# Reset DNS to your ISP's default
networksetup -setdnsservers Wi-Fi empty

# Flush the DNS cache
sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder
```

### Disable SOCKS proxy

If web traffic is broken after configuring a SOCKS proxy:

```bash
# Turn off the SOCKS proxy
networksetup -setsocksfirewallproxystate Wi-Fi off
```

A SOCKS proxy routes all traffic through a tunnel. If the tunnel is not running (e.g., your SSH session ended, or Tor is not installed), all traffic will fail. Disabling the proxy restores normal direct connections.

### Revert hostname

If you want your personal hostname back immediately without waiting for a trusted network:

```bash
macshield relax
```

Or manually:

```bash
sudo scutil --set ComputerName "Your Name MacBook"
sudo scutil --set LocalHostName "Your-Name-MacBook"
sudo scutil --set HostName "Your-Name-MacBook"
```

### Revert all macshield changes

To completely undo everything macshield has done:

```bash
macshield relax                              # Restore hostname, stealth, NetBIOS
networksetup -setdnsservers Wi-Fi empty      # Reset DNS
networksetup -setsocksfirewallproxystate Wi-Fi off  # Disable proxy
macshield --uninstall                        # Remove macshield entirely
```

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
brew untap qinnovates/tools
sudo rm -f /etc/sudoers.d/macshield
rm -f ~/Library/LaunchAgents/com.qinnovates.macshield.plist
```

Manual:

```bash
macshield --uninstall
```

Or run `./uninstall.sh` from the cloned repo.

## Changelog

### v0.4.1

**Self-integrity check.**

- On install, macshield stores a SHA-256 hash of itself in macOS Keychain
- On every launch, the hash is verified before executing any privileged commands
- If the binary has been modified (by an attacker, a rogue process, or an update without re-running setup), macshield refuses to run and prints a clear warning with fix instructions
- `--help` and `--version` bypass the check so they remain usable for debugging
- `brew upgrade` triggers `post_install` which re-runs setup, so the hash updates automatically

### v0.4.0

**Free VPN options. Full-stack protection for students on public WiFi.**

macshield has always secured your local network identity (Layer 2). For the sake of protecting other layers, the installer now offers two free VPNs that encrypt your traffic and DNS (Layer 3+):

- **Cloudflare WARP** (best for security): fastest (300+ edge nodes), free malware-blocking DNS (1.1.1.2), US-based
- **ProtonVPN** (best for privacy): Swiss jurisdiction, open-source client, court-tested no-logs (subpoenaed in 2019, had nothing to hand over)

The installer automatically applies malware-blocking DNS when you pick WARP. If you pick ProtonVPN (free tier has no malware blocking), the installer recommends Quad9 DNS so you still have malware protection when ProtonVPN is disconnected. If you want extra privacy, both VPNs route all traffic through encrypted WireGuard tunnels at no cost.

Together, macshield + a free VPN offers adequate protection with minimum requirements for students looking to stay secure in cafes, libraries, and campus WiFi. You can use `macshield setup` to toggle DNS configuration and proxy settings, and run security reports for hardening. Reports can be set to self-destruct after a configurable duration.

- Added free VPN step with side-by-side WARP vs ProtonVPN comparison in installer
- WARP: auto-configures malware blocking via `warp-cli dns families malware` (DNS 1.1.1.2)
- ProtonVPN: installer warns about free tier DNS limitation, prompts for Quad9
- Reordered installer steps: VPN (Step 6) before DNS (Step 7) before SOCKS proxy (Step 8)
- DNS step is now context-aware (adapts messaging based on VPN choice)
- Updated layer diagram and README with full VPN comparison table
- Documented `warp-cli` commands for malware/family DNS profiles

### v0.3.0

**No more root daemon. LaunchAgent + scoped sudo. Color output. Security reports. Privacy improvements.**

- Replaced root LaunchDaemon with user LaunchAgent + scoped sudoers fragment
- Added color output throughout with terminal detection
- Added security commands: `scan`, `audit`, `connections`, `persistence`, `permissions`
- SSID masked in installer (first 2 chars + asterisks) to prevent shoulder surfing
- DNS reordered: Quad9 first (blocks malware, Swiss privacy law, non-profit)
- Tor removed from SOCKS proxy options
- Homebrew `post_install` auto-launches interactive installer in new Terminal window
- Added `macshield setup` command, beginner warnings, revert instructions
- Homebrew tap renamed to `qinnovates/tools` for cleaner install command
- Updated messaging: macshield secures Layer 2, reduces malware potential with Quad9, avoids unknown WiFi DNS

### v0.2.0

**Replaced sudoers fragment with LaunchDaemon.**

The v0.1.0 design installed a sudoers file with wildcard permissions. v0.2.0 replaced it with a LaunchDaemon running as root. v0.3.0 further improves this.

### v0.1.0

Initial release. Network-aware auto-hardening with stealth mode, hostname protection, NetBIOS control, HMAC-SHA256 trust storage in Keychain, Homebrew tap.

Full changelog: [CHANGELOG.md](CHANGELOG.md)

## Upcoming: Menu bar app

A native macOS menu bar app is in development. The app will give you a shield icon in your top bar with quick access to everything macshield does today via the CLI:

- Shield icon shows green (hardened) / yellow (relaxed) / red (no protection) at a glance
- One-click harden / relax toggle
- Trust / untrust current network
- Run security reports (scan, audit, connections, persistence, permissions) from a dropdown
- Configure self-destruct timers on reports
- Switch DNS provider on the fly (Quad9, Cloudflare, Mullvad, ISP default) with one click
- Shows which DNS is active right now (system DNS vs VPN DNS)
- VPN status indicator (WARP / ProtonVPN connected or not)
- Quick link to `macshield setup` for full reconfiguration

The app will be a lightweight Swift wrapper around the existing bash CLI. No new dependencies, no telemetry, no network calls. Same pure-bash engine underneath.

Track progress: [github.com/qinnovates/macshield/issues](https://github.com/qinnovates/macshield/issues)

## Requirements

- macOS 12 (Monterey) or later
- Admin account (member of the `admin` group)
- WiFi interface

## License

Apache 2.0. See [LICENSE](LICENSE).

## Contributing

Issues and pull requests welcome at [github.com/qinnovates/macshield](https://github.com/qinnovates/macshield).
