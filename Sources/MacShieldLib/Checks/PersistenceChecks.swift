import Foundation

/// Internal protocol for persistence-specific checks (reuses SecurityCheck interface).
typealias PersistenceCheck = SecurityCheck

// MARK: - User LaunchAgents

public struct UserLaunchAgentsCheck: SecurityCheck {
    public let id = "user_launch_agents"
    public let category = RiskScore.Category.persistence

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let dir = NSHomeDirectory() + "/Library/LaunchAgents"
        return await scanPlistDirectory(
            dir, label: "User LaunchAgent", runner: runner,
            validateOwnership: false
        )
    }
}

// MARK: - System LaunchAgents

public struct SystemLaunchAgentsCheck: SecurityCheck {
    public let id = "system_launch_agents"
    public let category = RiskScore.Category.persistence

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        return await scanPlistDirectory(
            "/Library/LaunchAgents", label: "System LaunchAgent", runner: runner,
            validateOwnership: false
        )
    }
}

// MARK: - System LaunchDaemons

public struct SystemLaunchDaemonsCheck: SecurityCheck {
    public let id = "system_launch_daemons"
    public let category = RiskScore.Category.persistence

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        return await scanPlistDirectory(
            "/Library/LaunchDaemons", label: "System LaunchDaemon", runner: runner,
            validateOwnership: true  // Daemons should be root:wheel
        )
    }
}

// MARK: - Login Items

public struct LoginItemsCheck: SecurityCheck {
    public let id = "login_items"
    public let category = RiskScore.Category.persistence

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/bin/osascript",
            arguments: ["-e", "tell application \"System Events\" to get the name of every login item"],
            timeout: 10.0
        )

        if result.succeeded && !result.stdout.isEmpty {
            return [Finding(
                id: id, check: "Login Items", category: category,
                status: .info, severity: .info,
                detail: Sanitizer.sanitizeOutput(result.stdout, maxLength: 500)
            )]
        }

        return [Finding(
            id: id, check: "Login Items", category: category,
            status: .info, severity: .info, detail: "none or could not read"
        )]
    }
}

// MARK: - Cron Jobs

public struct CronJobsCheck: SecurityCheck {
    public let id = "cron_jobs"
    public let category = RiskScore.Category.persistence

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/bin/crontab",
            arguments: ["-l"],
            timeout: 5.0
        )

        if result.succeeded && !result.stdout.isEmpty {
            let lineCount = result.stdout.components(separatedBy: "\n")
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }.count
            return [Finding(
                id: id, check: "Cron Jobs", category: category,
                status: lineCount > 0 ? .warn : .info,
                severity: lineCount > 0 ? .low : .info,
                detail: "\(lineCount) active cron job(s)",
                remediation: lineCount > 0 ? "Review with 'crontab -l'" : nil
            )]
        }

        return [Finding(
            id: id, check: "Cron Jobs", category: category,
            status: .info, severity: .info, detail: "none"
        )]
    }
}

// MARK: - Kernel Extensions

public struct KernelExtensionsCheck: SecurityCheck {
    public let id = "kernel_extensions"
    public let category = RiskScore.Category.persistence

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/sbin/kextstat",
            arguments: [],
            timeout: 10.0
        )

        guard result.succeeded else {
            return [Finding(
                id: id, check: "Kernel Extensions", category: category,
                status: .inconclusive, severity: .medium,
                detail: "Could not query kextstat"
            )]
        }

        var nonAppleKexts: [String] = []
        for line in result.stdout.components(separatedBy: "\n") {
            guard !line.contains("com.apple") else { continue }
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            if parts.count >= 6 {
                nonAppleKexts.append(String(parts[5]))
            }
        }

        if nonAppleKexts.isEmpty {
            return [Finding(
                id: id, check: "Kernel Extensions", category: category,
                status: .pass, severity: .info, detail: "no non-Apple kexts loaded"
            )]
        }

        return [Finding(
            id: id, check: "Kernel Extensions", category: category,
            status: .warn, severity: .medium,
            detail: "\(nonAppleKexts.count) non-Apple kext(s): \(nonAppleKexts.joined(separator: ", "))",
            remediation: "Review each kernel extension for legitimacy"
        )]
    }
}

// MARK: - Shared Plist Scanner

private func scanPlistDirectory(
    _ dir: String,
    label: String,
    runner: ProcessRunning,
    validateOwnership: Bool
) async -> [Finding] {
    let fm = FileManager.default
    guard fm.fileExists(atPath: dir) else { return [] }

    guard let contents = try? fm.contentsOfDirectory(atPath: dir) else { return [] }

    let plists = contents.filter { $0.hasSuffix(".plist") }
    var findings: [Finding] = []

    for plist in plists {
        let name = plist.replacingOccurrences(of: ".plist", with: "")
        // Skip Apple items
        guard !name.hasPrefix("com.apple.") else { continue }

        let fullPath = dir + "/" + plist

        // Read the program from plist
        var program = "(could not read)"
        if let dict = try? PlistReader.read(at: fullPath) {
            if let prog = dict["Program"] as? String {
                program = prog
            } else if let args = dict["ProgramArguments"] as? [String], let first = args.first {
                program = first
            }
        }

        // Check code signing of the target binary
        var signingStatus = ""
        if program != "(could not read)" && fm.fileExists(atPath: program) {
            let sigResult = await runner.run(
                executable: "/usr/bin/codesign",
                arguments: ["-v", program],
                timeout: 5.0
            )
            if !sigResult.succeeded {
                signingStatus = " [UNSIGNED]"
            }
        }

        // Validate ownership for LaunchDaemons
        var ownershipIssue = ""
        if validateOwnership {
            let statResult = await runner.run(
                executable: "/usr/bin/stat",
                arguments: ["-f", "%Su:%Sg", fullPath],
                timeout: 5.0
            )
            let owner = statResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if !owner.isEmpty && owner != "root:wheel" {
                ownershipIssue = " [OWNER: \(owner), expected root:wheel]"
            }
        }

        let hasIssues = !signingStatus.isEmpty || !ownershipIssue.isEmpty
        findings.append(Finding(
            id: "persist_\(name)",
            check: "\(label): \(name)",
            category: .persistence,
            status: hasIssues ? .warn : .info,
            severity: hasIssues ? .medium : .info,
            detail: "\(program)\(signingStatus)\(ownershipIssue)",
            remediation: hasIssues ? "Investigate this persistence item" : nil
        ))
    }

    return findings
}
