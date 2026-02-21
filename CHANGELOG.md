# Changelog

All notable changes to macshield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-02-21

### Added
- Initial release
- Network-aware auto-hardening via LaunchAgent
- Stealth mode toggle (macOS Application Firewall)
- Hostname randomization on untrusted networks
- NetBIOS daemon control
- Trusted network storage as HMAC-SHA256 hashes in macOS Keychain
- Installer with explicit per-step consent
- Clean uninstaller
- `trust`, `untrust`, `harden`, `relax`, `--check` commands
- Timed relax (`relax --for 2h`)
- Paranoid mode (`trust --paranoid`)
