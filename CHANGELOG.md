# Changelog

All notable changes to macshield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-02-28

### Changed
- **Complete rewrite from Bash to Swift 6.0 with SwiftPM.** 32 source files, 8 test files, 42 unit tests, zero warnings.
- **Type-safe risk scoring** with weighted categories (0-100 composite score, A-F grade). Category weights: System Protection (30%), Firewall/Network (20%), Sharing Services (15%), Persistence Integrity (15%), Privacy/Permissions (10%), File Hygiene (10%).
- **Weighted confidence metric.** Inconclusive checks degrade confidence proportional to category importance. A failed SIP check degrades confidence more than a failed file hygiene check.

### Added
- `--format json` for CI/CD integration, `--format human` for terminal output.
- INCONCLUSIVE status for checks that fail to run (replaces silent PASS).
- AMFI status check with value parsing (not just key presence).
- XProtect version extraction, non-Apple kernel extension detection, unsigned persistence items.
- Code signing self-verification at launch (SecStaticCode + team ID validation).
- TCC queries via parameterized sqlite3 C API with OS version guardrail (macOS 14+).
- Hardened ProcessRunner with async pipe draining, real timeout enforcement, SIGKILL fallback, clamped timeout range.

### Fixed
- SIP substring false positive (`"disabled".contains("enabled")` was `true`).
- All string-based categories replaced with compiler-enforced enums.

### Dependencies
- Single dependency: `swift-argument-parser` (Apple-maintained).

## [0.5.0] - 2026-02-25

### Changed
- **Stripped to read-only analyzer with zero attack surface.** Any security tool that modifies your system introduces its own attack surface. v0.5.0 removes all system modifications and teaches users to harden manually.

### Removed
- `harden`, `relax`, `trust`, `untrust`, `--trigger`, `--check`, `setup` commands.
- LaunchAgent, LaunchDaemon, sudoers fragment, Keychain writes, HMAC trust storage, integrity check, state tracking.
- `install.sh` setup wizard (8 steps reduced to 1: copy the binary).

### Added
- Manual hardening commands in help text and README.
- Uninstaller cleans up all legacy artifacts from v0.4.x and earlier.

## [0.4.1] - 2026-02-23

### Added
- **Self-integrity check.** On install, macshield stores a SHA-256 hash in Keychain and verifies on launch. Tampered binaries refuse to run.

## [0.4.0] - 2026-02-22

### Added
- **Free VPN step (Step 6) with WARP vs ProtonVPN comparison.** Side-by-side table in installer comparing Cloudflare WARP (best for security: fastest, free malware-blocking DNS, US-based) vs ProtonVPN Free (best for privacy: Swiss jurisdiction, open-source, court-tested no-logs). Both installed via Homebrew.
- **Automatic malware-blocking DNS for WARP.** After WARP install, the installer runs `warp-cli dns families malware` to set DNS to 1.1.1.2, blocking known malicious domains out of the box.
- **Context-aware DNS step (Step 7).** DNS configuration now adapts based on VPN choice: explains WARP DNS override behavior, recommends Quad9 for ProtonVPN users (free tier has no malware-blocking DNS), shows when system DNS applies vs VPN DNS.
- **ProtonVPN free tier DNS warning.** Installer explicitly warns that ProtonVPN free does not include malware-blocking DNS (NetShield requires paid plan) and nudges toward Quad9.
- **Full VPN comparison in README.** Jurisdiction, speed, malware blocking, open-source status, device limits, audit history, install commands, DNS behavior per VPN.

### Changed
- Version bumped to 0.4.0.
- **Reordered installer steps:** VPN (Step 6) before DNS (Step 7) before SOCKS proxy (Step 8). DNS depends on VPN choice, proxy is most advanced and comes last.
- README changelog updated with student-focused messaging: macshield + free VPN = adequate cafe/campus protection at zero cost.

## [0.3.0] - 2026-02-21

### Added
- **Color output** throughout macshield.sh and install.sh with terminal detection (`[[ -t 1 ]]`) for graceful degradation.
- **ASCII art banner** in the installer.
- **Security report commands in installer completion message.** After setup, users now see all available commands: `scan`, `audit`, `connections`, `persistence`, `permissions`.
- **SSID masking** in installer. Shows first 2 characters + asterisks (e.g., `"My********"`) to prevent shoulder surfing and screen recording exposure.
- **Malware reduction messaging.** Installer and README now communicate that Quad9 DNS blocks known malware domains.
- **Untrusted WiFi DNS warning.** Explains that public WiFi routes DNS through infrastructure you don't control.
- **Beginner warning** on SOCKS proxy step: "Skip this if you don't know what a SOCKS proxy is."
- **Reverting changes section** in README: how to reset DNS, disable proxy, revert hostname, and undo all macshield changes.
- **DNS comparison table** in README (Quad9/Cloudflare/Mullvad with jurisdiction, malware blocking, org type).
- **Homebrew `post_install`** launches interactive installer in a new Terminal window via `open -a Terminal`.
- **`macshield setup`** command as alias for `--install`.
- **Homebrew symlink resolution** via `realpath` so `macshield setup` finds `libexec/install.sh` through the Cellar path.

### Changed
- **DNS order:** Quad9 listed first (blocks malware, Swiss privacy law, non-profit). Cloudflare second, Mullvad third.
- **Layer 2 messaging:** Disclaimer updated from "reduces your local network footprint only" to "secures your local network identity (Layer 2)."
- **Homebrew tap renamed** from `homebrew-macshield` to `homebrew-tools` for cleaner `brew install qinnovates/tools/macshield`.

### Removed
- **Tor from SOCKS proxy options.** Tor exit nodes are frequently flagged, blocked, or associated with malicious traffic. Removed to avoid giving users a false sense of security.

### Architecture
- **Replaced root LaunchDaemon with user LaunchAgent + scoped sudoers.** The v0.2.0 LaunchDaemon ran as root persistently. v0.3.0 runs the LaunchAgent as your user (`~/Library/LaunchAgents/`). Privileged commands (stealth mode, hostname, NetBIOS) are elevated via a sudoers fragment at `/etc/sudoers.d/macshield` that the user explicitly approves during installation. No process runs persistently as root.
- **Installer prompts for explicit consent** before installing the sudoers authorization. Users see the exact commands being authorized and can revoke anytime with `sudo rm /etc/sudoers.d/macshield`.
- **Uninstaller cleans up** LaunchAgent, sudoers fragment, and legacy LaunchDaemon (v0.2.0 upgrade path).
- **README updated** with neurorights and privacy motivation, free VPN warning, and security model reflecting no-root architecture.

### Added
- **`macshield scan`** command: scans all open TCP and UDP ports, labels known system ports, flags non-standard ports as `** REVIEW **`, saves a local-only report to `/tmp/macshield-port-report.txt` with `600` permissions.
- **`macshield scan --purge <duration>`**: scan with auto-delete timer (e.g., `5m`, `1h`). Report is deleted automatically after the duration.
- **`macshield purge`** command: deletes all macshield logs, port reports, state files, and lock files. Zero traces on disk. Script remains installed and functional.
- `run_privileged()` helper in macshield.sh that uses sudo when not root, passes through when root. Enables the same script to work with both LaunchAgent (user) and manual invocation.
- Upgrade path from v0.2.0: installer and uninstaller detect and remove the old `/Library/LaunchDaemons/` plist.
- `--check` now reports LaunchAgent, sudoers authorization, and DNS server status.
- DNS provider selection during install (Cloudflare, Quad9, Mullvad). Applied directly via `networksetup` to system configuration.
- SOCKS proxy configuration during install (Tor, SSH tunnel, custom). Applied directly via `networksetup` to system configuration.
- Scan command clearly communicates that results are wiped by default and shows alternative parameters (`--purge`, `--quiet`) for non-interactive use.
- **`macshield audit`** command: read-only system security posture check. Covers SIP, FileVault, Gatekeeper, Application Firewall, stealth mode, Lockdown Mode, Secure Boot, XProtect, sharing services, privacy settings, WiFi security, ARP table MitM detection, and file hygiene. Inspired by Lynis, mOSL, and drduh's macOS Security Guide.
- **`macshield connections`** command: lists all established TCP connections with process names.
- **`macshield persistence`** command: lists non-Apple LaunchAgents, LaunchDaemons, login items, cron jobs, and kernel extensions.
- **`macshield permissions`** command: shows apps with sensitive TCC permissions (screen recording, accessibility, microphone, camera, full disk access, automation).
- **Hostname change warning.** Installer and `harden` command now explicitly warn users that macshield changes their computer name, which affects AirDrop, Bluetooth, Terminal prompt, and Sharing preferences. Users must accept this before proceeding.
- **Legal disclaimer.** Installer requires explicit acceptance before proceeding. Help text includes disclaimer.
- README: "Do it manually" section with exact commands for users who prefer not to install.
- README: "A note on security trade-offs" section on the paradox of protection.

### Removed
- Root LaunchDaemon (`/Library/LaunchDaemons/com.qinnovates.macshield.plist` with `UserName: root`). Replaced by user LaunchAgent.

## [0.2.0] - 2026-02-21

### Changed
- **Replaced LaunchAgent + sudoers with LaunchDaemon.** The previous design installed a sudoers fragment granting passwordless sudo for 8 commands with wildcards (e.g., `scutil --set ComputerName *`). If an attacker gained local code execution as your user, they could leverage those wildcards without a password. A LaunchDaemon runs as root directly, eliminating the sudoers file entirely. The script is pure bash and fully auditable.
- **Improved WiFi detection.** `networksetup -getairportnetwork` is unreliable on modern macOS (reports "not associated" while connected). Added `ipconfig getsummary` as the primary detection method with `networksetup` and `system_profiler` as fallbacks.

### Removed
- Sudoers fragment (`/etc/sudoers.d/macshield`). No longer needed.

## [0.1.0] - 2026-02-21

### Added
- Initial release
- Network-aware auto-hardening via LaunchDaemon
- Stealth mode toggle (macOS Application Firewall)
- Hostname randomization on untrusted networks
- NetBIOS daemon control
- Trusted network storage as HMAC-SHA256 hashes in macOS Keychain (post-quantum resistant)
- Installer with explicit per-step consent
- Clean uninstaller
- Homebrew tap (`brew tap qinnovates/tools`)
- `trust`, `untrust`, `harden`, `relax`, `--check` commands
- Timed relax (`relax --for 2h`)
- Paranoid mode (`trust --paranoid`)
