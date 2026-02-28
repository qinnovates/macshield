import Foundation

// MARK: - SSH

public struct SSHCheck: SecurityCheck {
    public let id = "ssh"
    public let category = RiskScore.Category.sharingServices

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/sbin/systemsetup",
            arguments: ["-getremotelogin"],
            timeout: 5.0
        )

        let output = result.stdout
        if output.contains("Off") {
            return [Finding(
                id: id, check: "Remote Login (SSH)", category: category,
                status: .pass, severity: .info, detail: "disabled"
            )]
        } else if output.contains("On") {
            return [Finding(
                id: id, check: "Remote Login (SSH)", category: category,
                status: .warn, severity: .medium,
                detail: "enabled (port 22 open to network)",
                remediation: "Disable via System Settings > General > Sharing > Remote Login"
            )]
        }

        return [Finding(
            id: id, check: "Remote Login (SSH)", category: category,
            status: .inconclusive, severity: .medium,
            detail: "Could not determine SSH status"
        )]
    }
}

// MARK: - Screen Sharing

public struct ScreenSharingCheck: SecurityCheck {
    public let id = "screen_sharing"
    public let category = RiskScore.Category.sharingServices

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/bin/launchctl",
            arguments: ["list"],
            timeout: 5.0
        )

        if result.stdout.contains("com.apple.screensharing") {
            return [Finding(
                id: id, check: "Screen Sharing", category: category,
                status: .warn, severity: .medium,
                detail: "enabled (remote desktop access open)",
                remediation: "Disable via System Settings > General > Sharing"
            )]
        }

        return [Finding(
            id: id, check: "Screen Sharing", category: category,
            status: .pass, severity: .info, detail: "disabled"
        )]
    }
}

// MARK: - SMB File Sharing

public struct SMBCheck: SecurityCheck {
    public let id = "smb"
    public let category = RiskScore.Category.sharingServices

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/bin/launchctl",
            arguments: ["list"],
            timeout: 5.0
        )

        if result.stdout.contains("com.apple.smbd") {
            return [Finding(
                id: id, check: "File Sharing (SMB)", category: category,
                status: .warn, severity: .medium,
                detail: "enabled (network file shares open)",
                remediation: "Disable via System Settings > General > Sharing"
            )]
        }

        return [Finding(
            id: id, check: "File Sharing (SMB)", category: category,
            status: .pass, severity: .info, detail: "disabled"
        )]
    }
}

// MARK: - ARD

public struct ARDCheck: SecurityCheck {
    public let id = "ard"
    public let category = RiskScore.Category.sharingServices

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/bin/launchctl",
            arguments: ["list"],
            timeout: 5.0
        )

        if result.stdout.contains("com.apple.RemoteDesktop") {
            return [Finding(
                id: id, check: "Remote Management (ARD)", category: category,
                status: .warn, severity: .medium,
                detail: "enabled",
                remediation: "Disable via System Settings > General > Sharing"
            )]
        }

        return [Finding(
            id: id, check: "Remote Management (ARD)", category: category,
            status: .pass, severity: .info, detail: "disabled"
        )]
    }
}

// MARK: - Remote Apple Events

public struct RemoteAppleEventsCheck: SecurityCheck {
    public let id = "remote_apple_events"
    public let category = RiskScore.Category.sharingServices

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/sbin/systemsetup",
            arguments: ["-getremoteappleevents"],
            timeout: 5.0
        )

        if result.stdout.contains("Off") {
            return [Finding(
                id: id, check: "Remote Apple Events", category: category,
                status: .pass, severity: .info, detail: "disabled"
            )]
        } else if result.stdout.contains("On") {
            return [Finding(
                id: id, check: "Remote Apple Events", category: category,
                status: .warn, severity: .medium,
                detail: "enabled",
                remediation: "Disable via System Settings > General > Sharing"
            )]
        }

        return [Finding(
            id: id, check: "Remote Apple Events", category: category,
            status: .inconclusive, severity: .medium,
            detail: "Could not determine status"
        )]
    }
}

// MARK: - Bluetooth

public struct BluetoothCheck: SecurityCheck {
    public let id = "bluetooth"
    public let category = RiskScore.Category.sharingServices

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/bin/defaults",
            arguments: ["read", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState"],
            timeout: 5.0
        )

        if result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "0" {
            return [Finding(
                id: id, check: "Bluetooth", category: category,
                status: .pass, severity: .info, detail: "disabled"
            )]
        }

        return [Finding(
            id: id, check: "Bluetooth", category: category,
            status: .info, severity: .info,
            detail: "enabled (disable on untrusted networks if not needed)"
        )]
    }
}

// MARK: - AirDrop

public struct AirDropCheck: SecurityCheck {
    public let id = "airdrop"
    public let category = RiskScore.Category.sharingServices

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/bin/defaults",
            arguments: ["read", "com.apple.sharingd", "DiscoverableMode"],
            timeout: 5.0
        )

        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        switch value {
        case "Off":
            return [Finding(
                id: id, check: "AirDrop", category: category,
                status: .pass, severity: .info, detail: "receiving disabled"
            )]
        case "Contacts Only", "ContactsOnly":
            return [Finding(
                id: id, check: "AirDrop", category: category,
                status: .pass, severity: .info, detail: "contacts only"
            )]
        case "Everyone":
            return [Finding(
                id: id, check: "AirDrop", category: category,
                status: .warn, severity: .medium,
                detail: "set to Everyone (anyone nearby can send you files)",
                remediation: "Set to Contacts Only in AirDrop settings"
            )]
        default:
            return [Finding(
                id: id, check: "AirDrop", category: category,
                status: .info, severity: .info,
                detail: "could not determine setting"
            )]
        }
    }
}
