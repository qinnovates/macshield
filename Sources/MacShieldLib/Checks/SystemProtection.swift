import Foundation

// MARK: - SIP

public struct SIPCheck: SecurityCheck {
    public let id = "sip"
    public let category = RiskScore.Category.systemProtection

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/bin/csrutil",
            arguments: ["status"],
            timeout: 5.0
        )

        if result.timedOut {
            return [Finding(
                id: id, check: "System Integrity Protection (SIP)", category: category,
                status: .inconclusive, severity: .critical,
                detail: "csrutil timed out",
                remediation: "Run 'csrutil status' manually"
            )]
        }

        let output = result.stdout.lowercased()
        // Must check "disabled" BEFORE "enabled" — "disabled" contains "enabled" as substring
        if output.contains("status: disabled") || output.hasPrefix("disabled") {
            return [Finding(
                id: id, check: "System Integrity Protection (SIP)", category: category,
                status: .fail, severity: .critical,
                detail: "disabled",
                remediation: "Boot to Recovery Mode and run 'csrutil enable'"
            )]
        } else if output.contains("status: enabled") || output.hasPrefix("enabled") {
            // "enabled (Custom Configuration)" still counts as enabled
            let customConfig = output.contains("custom configuration")
            return [Finding(
                id: id, check: "System Integrity Protection (SIP)", category: category,
                status: customConfig ? .warn : .pass,
                severity: customConfig ? .high : .info,
                detail: customConfig ? "enabled (custom configuration — partial protection)" : "enabled",
                remediation: customConfig ? "Boot to Recovery Mode and run 'csrutil enable' for full protection" : nil
            )]
        }

        return [Finding(
            id: id, check: "System Integrity Protection (SIP)", category: category,
            status: .inconclusive, severity: .critical,
            detail: "Could not determine SIP status: \(Sanitizer.sanitizeOutput(result.stdout, maxLength: 200))"
        )]
    }
}

// MARK: - FileVault

public struct FileVaultCheck: SecurityCheck {
    public let id = "filevault"
    public let category = RiskScore.Category.systemProtection

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/bin/fdesetup",
            arguments: ["status"],
            timeout: 5.0
        )

        let output = result.stdout
        if output.contains("On") {
            return [Finding(
                id: id, check: "FileVault Disk Encryption", category: category,
                status: .pass, severity: .info, detail: "enabled"
            )]
        } else if output.contains("Off") {
            return [Finding(
                id: id, check: "FileVault Disk Encryption", category: category,
                status: .warn, severity: .high,
                detail: "not enabled",
                remediation: "Enable in System Settings > Privacy & Security > FileVault"
            )]
        }

        return [Finding(
            id: id, check: "FileVault Disk Encryption", category: category,
            status: .inconclusive, severity: .high,
            detail: "Could not determine FileVault status"
        )]
    }
}

// MARK: - Gatekeeper

public struct GatekeeperCheck: SecurityCheck {
    public let id = "gatekeeper"
    public let category = RiskScore.Category.systemProtection

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/sbin/spctl",
            arguments: ["--status"],
            timeout: 5.0
        )

        // Check both stdout and stderr — spctl writes to stderr on some versions
        // Check "disabled" BEFORE "enabled" to avoid substring false positive
        let combined = (result.stdout + "\n" + result.stderr).lowercased()
        if combined.contains("assessments disabled") || combined.contains("not enabled") {
            return [Finding(
                id: id, check: "Gatekeeper", category: category,
                status: .fail, severity: .high,
                detail: "disabled",
                remediation: "Run 'sudo spctl --master-enable'"
            )]
        } else if combined.contains("assessments enabled") {
            return [Finding(
                id: id, check: "Gatekeeper", category: category,
                status: .pass, severity: .info, detail: "enabled"
            )]
        }

        return [Finding(
            id: id, check: "Gatekeeper", category: category,
            status: .inconclusive, severity: .high,
            detail: "Could not determine Gatekeeper status"
        )]
    }
}

// MARK: - AMFI (new check, not in Bash)

public struct AMFICheck: SecurityCheck {
    public let id = "amfi"
    public let category = RiskScore.Category.systemProtection

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        // AMFI status via nvram: if amfi_get_out_of_my_way=1, AMFI is disabled
        let result = await runner.run(
            executable: "/usr/sbin/nvram",
            arguments: ["-p"],
            timeout: 5.0
        )

        if result.timedOut || !result.succeeded {
            return [Finding(
                id: id, check: "Apple Mobile File Integrity (AMFI)", category: category,
                status: .inconclusive, severity: .critical,
                detail: "Could not read NVRAM"
            )]
        }

        if result.stdout.contains("amfi_get_out_of_my_way") {
            return [Finding(
                id: id, check: "Apple Mobile File Integrity (AMFI)", category: category,
                status: .fail, severity: .critical,
                detail: "AMFI is disabled (amfi_get_out_of_my_way set in NVRAM)",
                remediation: "Boot to Recovery and run 'nvram -d amfi_get_out_of_my_way'"
            )]
        }

        return [Finding(
            id: id, check: "Apple Mobile File Integrity (AMFI)", category: category,
            status: .pass, severity: .info, detail: "enabled (default)"
        )]
    }
}

// MARK: - Secure Boot

public struct SecureBootCheck: SecurityCheck {
    public let id = "secure_boot"
    public let category = RiskScore.Category.systemProtection

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        // Try system_profiler first (short timeout — this can hang)
        let result = await runner.run(
            executable: "/usr/sbin/system_profiler",
            arguments: ["SPiBridgeDataType"],
            timeout: 5.0
        )

        if result.succeeded {
            for line in result.stdout.components(separatedBy: "\n") {
                if line.contains("Secure Boot") {
                    let value = line.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespaces) ?? ""
                    if value.contains("Full") {
                        return [Finding(
                            id: id, check: "Secure Boot", category: category,
                            status: .pass, severity: .info, detail: value
                        )]
                    } else {
                        return [Finding(
                            id: id, check: "Secure Boot", category: category,
                            status: .warn, severity: .high,
                            detail: value,
                            remediation: "Set Full Security in Recovery Mode startup options"
                        )]
                    }
                }
            }
        }

        // Apple Silicon: try bputil
        let bpResult = await runner.run(
            executable: "/usr/bin/bputil",
            arguments: ["-d"],
            timeout: 5.0
        )

        if bpResult.succeeded {
            for line in bpResult.stdout.components(separatedBy: "\n") {
                if line.contains("Security Mode") {
                    let value = line.components(separatedBy: " ").last ?? ""
                    if value.contains("Full") {
                        return [Finding(
                            id: id, check: "Secure Boot", category: category,
                            status: .pass, severity: .info, detail: "Full Security"
                        )]
                    }
                }
            }
        }

        // Could not determine — not a failure, could be unsupported hardware
        return [Finding(
            id: id, check: "Secure Boot", category: category,
            status: .info, severity: .info,
            detail: "Could not determine Secure Boot status"
        )]
    }
}

// MARK: - Lockdown Mode

public struct LockdownModeCheck: SecurityCheck {
    public let id = "lockdown_mode"
    public let category = RiskScore.Category.systemProtection

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/bin/defaults",
            arguments: ["read", ".GlobalPreferences", "LDMGlobalEnabled"],
            timeout: 5.0
        )

        if result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
            return [Finding(
                id: id, check: "Lockdown Mode", category: category,
                status: .pass, severity: .info, detail: "enabled"
            )]
        }

        return [Finding(
            id: id, check: "Lockdown Mode", category: category,
            status: .info, severity: .info,
            detail: "not enabled (extreme protection, breaks many features)"
        )]
    }
}

// MARK: - XProtect Version (new: extracts version, not just presence)

public struct XProtectVersionCheck: SecurityCheck {
    public let id = "xprotect_version"
    public let category = RiskScore.Category.systemProtection

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        // Read XProtect plist for version info
        let plistPath = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
        do {
            let version = try PlistReader.readString(at: plistPath, key: "CFBundleShortVersionString")
            return [Finding(
                id: id, check: "XProtect", category: category,
                status: .info, severity: .info,
                detail: "version \(version)"
            )]
        } catch {
            // Fallback: check the bundle exists (skip system_profiler — too slow)
            let bundlePath = "/Library/Apple/System/Library/CoreServices/XProtect.bundle"
            if FileManager.default.fileExists(atPath: bundlePath) {
                return [Finding(
                    id: id, check: "XProtect", category: category,
                    status: .info, severity: .info,
                    detail: "present (version unavailable)"
                )]
            }

            return [Finding(
                id: id, check: "XProtect", category: category,
                status: .inconclusive, severity: .medium,
                detail: "Could not determine XProtect version"
            )]
        }
    }
}
