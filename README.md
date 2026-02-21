# macshield

Network-aware macOS security hardening. Auto-hardens your Mac on untrusted WiFi, relaxes on trusted networks.

## What it does

| Untrusted network | Trusted network |
|---|---|
| Stealth mode ON (blocks ICMP pings, port scans) | Stealth mode OFF (AirDrop, Spotify Connect work) |
| Hostname set to generic "MacBook Pro" | Personal hostname restored |
| NetBIOS disabled (ports 137/138 closed) | NetBIOS re-enabled |

macshield detects network changes via a LaunchDaemon and applies the right profile automatically.

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

## Install

### Homebrew (recommended)

```bash
brew tap qinnovates/macshield
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
2. Install a LaunchDaemon that triggers on WiFi changes (runs as root, no sudoers needed)
3. Optionally trust your current network

After installation:

```bash
macshield trust            # Trust your current WiFi network
macshield --check          # See current state
```

## Verify it works

Run these commands in order to confirm everything is working:

```bash
# 1. Check current state. Shows WiFi status, trust level, stealth mode,
#    hostname, and whether the LaunchDaemon is installed.
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

From here, macshield runs automatically. When you connect to an untrusted network, the LaunchDaemon triggers `macshield harden`. When you connect to a trusted network, it triggers `macshield relax`. No manual intervention needed.

## How it works

```
WiFi network changes
        |
        v
LaunchDaemon fires (WatchPaths on system network plists)
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

**Network detection:** A LaunchDaemon watches `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist` and `preferences.plist`. Any WiFi change triggers macshield. The daemon runs as root, so no sudoers fragment is needed.

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

- **Pure bash.** Every line is readable and auditable. No compiled binaries, no helper tools, no frameworks.
- **No network calls.** macshield never phones home, never auto-updates, never sends telemetry.
- **No plaintext secrets.** SSIDs are stored as HMAC hashes in Keychain, never written to disk as cleartext.
- **Ephemeral logs.** All output goes to `/tmp/` and is cleared on reboot. Logs never contain SSIDs.
- **No sudoers fragment.** macshield uses a LaunchDaemon (runs as root) instead of a sudoers fragment with wildcard permissions. This eliminates the risk of a compromised user process leveraging passwordless sudo commands.
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

This removes the binary, LaunchDaemon, Keychain entries, and ephemeral state files. Your hostname and firewall settings are left as currently set.

## Troubleshooting

### "Not connected to any WiFi network" but I am connected

macshield uses multiple detection methods (`ipconfig`, `networksetup`, `system_profiler`). If none work, check that your WiFi interface is `en0`:

```bash
networksetup -listallhardwareports | grep -A2 "Wi-Fi"
```

If your WiFi is on a different interface, macshield will still detect it. If the issue persists, run `ipconfig getsummary en0` and check if SSID appears in the output.

### LaunchDaemon not triggering on network changes

Check if it's loaded:

```bash
sudo launchctl list | grep macshield
```

If not listed, load it:

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/com.qinnovates.macshield.plist
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

### Uninstall completely

Homebrew:

```bash
brew uninstall macshield
brew untap qinnovates/macshield
sudo rm -f /Library/LaunchDaemons/com.qinnovates.macshield.plist
```

Manual:

```bash
macshield --uninstall
```

Or run `./uninstall.sh` from the cloned repo.

## Changelog

### v0.2.0

**Replaced sudoers fragment with LaunchDaemon.**

The previous design installed a sudoers file at `/etc/sudoers.d/macshield` granting passwordless sudo for 8 commands. The problem: several commands used wildcards (e.g., `scutil --set ComputerName *`), meaning any process running as your user could invoke them without a password. If an attacker gained local code execution, they could leverage those wildcards to change your hostname or toggle stealth mode silently.

The fix: a LaunchDaemon runs as root directly, so no sudoers fragment is needed at all. The daemon executes the same pure bash script, which is fully auditable. This eliminates wildcard sudo as an attack surface.

Also fixed: WiFi detection now uses `ipconfig getsummary` as the primary method. The previous `networksetup -getairportnetwork` is unreliable on modern macOS versions (incorrectly reports "not associated" while connected).

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
