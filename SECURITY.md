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
- The sudoers fragment (`/etc/sudoers.d/macshield`) granting NOPASSWD for exact commands
- The LaunchAgent (runs as your user, triggers on network change events)
- Keychain storage (trusted network hashes)
- The bash script itself (command injection if inputs are unsanitized)

## Design Decisions

- **No root daemon**: macshield runs as your user via a LaunchAgent. Privileged commands are elevated through a scoped sudoers fragment, not a persistent root process. This follows the principle of least privilege.
- **Scoped sudoers, no wildcards on sensitive commands**: The sudoers fragment grants NOPASSWD for exact commands only (e.g., `socketfilterfw --setstealthmode on`, `launchctl bootout system/com.apple.netbiosd`). The `scutil --set` commands do use wildcards for the hostname value, which is necessary for the hostname to be dynamic. These commands only change the local hostname, which is a low-impact operation.
- **User consent**: The sudoers fragment is installed only with explicit user approval. Users can revoke it anytime with `sudo rm /etc/sudoers.d/macshield`.
- **Pure bash**: Fully auditable, no compiled binaries
- **No network calls**: macshield never phones home, never auto-updates, never sends telemetry
- **No plaintext secrets**: SSIDs are stored as HMAC hashes, never in cleartext
- **Post-quantum resistant**: HMAC-SHA256 retains 128-bit effective security under Grover's algorithm, well above the infeasibility threshold. No PQC migration needed.
- **Ephemeral logs**: All logs go to `/tmp/` and are cleared on reboot

## Privilege Evolution

| Version | Privilege Model | Trade-off |
|---------|----------------|-----------|
| v0.1.0 | Sudoers with wildcards | Wildcard sudo was exploitable by local attackers |
| v0.2.0 | Root LaunchDaemon | No wildcards, but persistent root process |
| v0.3.0 | User LaunchAgent + scoped sudoers | No root process, user consents to exact commands |
