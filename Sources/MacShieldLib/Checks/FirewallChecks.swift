import Foundation

private let firewallPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// MARK: - Firewall Enabled

public struct FirewallEnabledCheck: SecurityCheck {
    public let id = "firewall"
    public let category = RiskScore.Category.firewallNetwork

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: firewallPath,
            arguments: ["--getglobalstate"],
            timeout: 5.0
        )

        let output = result.stdout.lowercased()
        // Check "disabled" BEFORE "enabled" to avoid substring false positive
        if output.contains("state = 0") || output.contains("disabled") && !output.contains("not disabled") {
            return [Finding(
                id: id, check: "Application Firewall", category: category,
                status: .warn, severity: .medium,
                detail: "disabled",
                remediation: "Enable in System Settings > Network > Firewall"
            )]
        } else if output.contains("state = 1") || output.contains("state = 2") || output.contains("enabled") {
            return [Finding(
                id: id, check: "Application Firewall", category: category,
                status: .pass, severity: .info, detail: "enabled"
            )]
        }

        return [Finding(
            id: id, check: "Application Firewall", category: category,
            status: .inconclusive, severity: .medium,
            detail: "Could not determine firewall status"
        )]
    }
}

// MARK: - Stealth Mode

public struct StealthModeCheck: SecurityCheck {
    public let id = "stealth_mode"
    public let category = RiskScore.Category.firewallNetwork

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: firewallPath,
            arguments: ["--getstealthmode"],
            timeout: 5.0
        )

        let output = result.stdout.lowercased()
        // socketfilterfw outputs "Stealth mode enabled" or "Stealth mode disabled"
        if output.contains("mode disabled") {
            return [Finding(
                id: id, check: "Stealth Mode", category: category,
                status: .info, severity: .low,
                detail: "disabled",
                remediation: "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
            )]
        } else if output.contains("mode enabled") {
            return [Finding(
                id: id, check: "Stealth Mode", category: category,
                status: .pass, severity: .info, detail: "enabled"
            )]
        }

        return [Finding(
            id: id, check: "Stealth Mode", category: category,
            status: .inconclusive, severity: .low,
            detail: "Could not determine stealth mode status"
        )]
    }
}
