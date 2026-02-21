# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in macshield, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: security@qinnovate.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 72 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Scope

macshield is a local hardening tool. Its security surface includes:
- The sudoers fragment (privilege escalation risk if misconfigured)
- Keychain storage (trusted network hashes)
- The LaunchAgent (runs on network change events)
- The bash script itself (command injection if inputs are unsanitized)

## Design Decisions

- **Pure bash**: Fully auditable, no compiled binaries
- **No network calls**: macshield never phones home, never auto-updates, never sends telemetry
- **Minimal sudo**: Only 8 specific commands are granted passwordless sudo
- **No plaintext secrets**: SSIDs are stored as HMAC hashes, never in cleartext
- **Post-quantum resistant**: HMAC-SHA256 retains 128-bit effective security under Grover's algorithm, well above the infeasibility threshold. No PQC migration needed.
- **Ephemeral logs**: All logs go to `/tmp/` and are cleared on reboot
