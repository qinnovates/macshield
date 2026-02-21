# macshield

Network-aware macOS security hardening. Auto-hardens your Mac on untrusted WiFi, relaxes on trusted networks.

## What it does

| Untrusted network | Trusted network |
|---|---|
| Stealth mode ON (blocks ICMP pings, port scans) | Stealth mode OFF (AirDrop, Spotify Connect work) |
| Hostname set to generic "MacBook Pro" | Personal hostname restored |
| NetBIOS disabled (ports 137/138 closed) | NetBIOS re-enabled |

macshield detects network changes via a LaunchAgent and applies the right profile automatically.

## Why it exists

When you connect to public WiFi (cafes, airports, hotels), your Mac broadcasts its hostname over mDNS/Bonjour, responds to ICMP pings, and announces itself via NetBIOS. VPNs encrypt your traffic but don't hide your hostname or stop these broadcasts on the local network.

**Commercial tools** (Little Snitch, Intego NetBarrier) handle profile switching but are closed-source and expensive. **Open-source hardening scripts** (ALBATOR, drduh's macOS-Security-and-Privacy-Guide) are thorough but static, with no network-aware auto-switching.

macshield fills the gap: automatic, network-aware, open-source, fully auditable.

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

## Quick start

```bash
git clone https://github.com/qinnovates/macshield.git
cd macshield
chmod +x install.sh macshield.sh
./install.sh
```

The installer walks through each step with explicit yes/no consent.

After installation:

```bash
macshield trust            # Trust your current WiFi network
macshield --check          # See current state
```

## Verify it works

Run these commands in order to confirm everything is working:

```bash
# 1. Check current state. Shows WiFi status, trust level, stealth mode,
#    hostname, and whether the LaunchAgent/sudoers are installed.
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
macshield --trigger
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
```

**Network detection:** LaunchAgent watches `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist` and `preferences.plist`. Any WiFi change triggers macshield.

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
macshield --install        Run the installer
macshield --uninstall      Run the uninstaller
macshield --version        Print version
macshield --help           Print help
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
[macshield]         Running: sudo socketfilterfw --setstealthmode on
[macshield]         Done.
[macshield]   [2/3] Setting hostname to generic "MacBook Pro" (hides identity on local network)
[macshield]         Running: sudo scutil --set ComputerName "MacBook Pro"
[macshield]         Running: sudo scutil --set LocalHostName "MacBook-Pro"
[macshield]         Running: sudo scutil --set HostName "MacBook-Pro"
[macshield]         Done.
[macshield]   [3/3] Disabling NetBIOS (closes ports 137/138, stops name broadcast)
[macshield]         Running: sudo launchctl bootout system/com.apple.netbiosd
[macshield]         Done.
[macshield]
[macshield] All protections active. Your Mac is hardened.
```

## Sudoers fragment

The installer places a sudoers file at `/etc/sudoers.d/macshield` granting passwordless sudo for exactly 8 commands:

```
Cmnd_Alias MACSHIELD_CMDS = \
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on, \
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off, \
    /usr/sbin/scutil --set ComputerName *, \
    /usr/sbin/scutil --set LocalHostName *, \
    /usr/sbin/scutil --set HostName *, \
    /bin/launchctl bootout system/com.apple.netbiosd, \
    /bin/launchctl enable system/com.apple.netbiosd, \
    /bin/launchctl kickstart system/com.apple.netbiosd

%admin ALL=(root) NOPASSWD: MACSHIELD_CMDS
```

This is required because the LaunchAgent runs non-interactively (cannot prompt for a password). The fragment is validated with `visudo -c` before installation.

## Security model

- **Pure bash.** Every line is readable and auditable. No compiled binaries, no helper tools, no frameworks.
- **No network calls.** macshield never phones home, never auto-updates, never sends telemetry.
- **No plaintext secrets.** SSIDs are stored as HMAC hashes in Keychain, never written to disk as cleartext.
- **Ephemeral logs.** All output goes to `/tmp/` and is cleared on reboot. Logs never contain SSIDs.
- **Minimal sudo.** Only 8 specific commands are granted passwordless sudo, each scoped to exact paths.
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

## Uninstall

```bash
macshield --uninstall
```

Or run the uninstall script directly:

```bash
./uninstall.sh
```

This removes the binary, sudoers fragment, LaunchAgent, Keychain entries, and ephemeral state files. Your hostname and firewall settings are left as currently set.

## Requirements

- macOS 12 (Monterey) or later
- Admin account (member of the `admin` group)
- WiFi interface

## License

Apache 2.0. See [LICENSE](LICENSE).

## Contributing

Issues and pull requests welcome at [github.com/qinnovates/macshield](https://github.com/qinnovates/macshield).
