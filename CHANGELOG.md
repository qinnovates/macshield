# Changelog

All notable changes to macshield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
- Homebrew tap (`brew tap qinnovates/macshield`)
- `trust`, `untrust`, `harden`, `relax`, `--check` commands
- Timed relax (`relax --for 2h`)
- Paranoid mode (`trust --paranoid`)
