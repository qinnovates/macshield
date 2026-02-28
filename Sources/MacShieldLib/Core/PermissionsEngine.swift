import Foundation

/// Queries TCC database for permission grants.
public struct PermissionsEngine: Sendable {

    private let runner: ProcessRunning

    public init(runner: ProcessRunning = SystemProcessRunner()) {
        self.runner = runner
    }

    public func scan() async -> Report {
        var findings: [Finding] = []
        let capabilities = SystemCapabilities.detect()

        if !capabilities.hasFullDiskAccess {
            findings.append(Finding(
                id: "tcc_no_fda",
                check: "TCC Database Access",
                category: .privacyPermissions,
                status: .inconclusive, severity: .medium,
                detail: "Full Disk Access not granted — cannot read TCC.db",
                remediation: "Grant Full Disk Access in System Settings > Privacy & Security"
            ))
        } else {
            let tccServices: [(String, String)] = [
                ("kTCCServiceScreenCapture", "Screen Recording"),
                ("kTCCServiceAccessibility", "Accessibility"),
                ("kTCCServiceMicrophone", "Microphone"),
                ("kTCCServiceCamera", "Camera"),
                ("kTCCServiceSystemPolicyAllFiles", "Full Disk Access"),
                ("kTCCServiceAppleEvents", "Automation (Apple Events)"),
            ]

            for (service, label) in tccServices {
                let apps = TCCReader.queryGrantedApps(service: service)
                if let apps, !apps.isEmpty {
                    findings.append(Finding(
                        id: "tcc_\(service)",
                        check: "\(label) Permissions",
                        category: .privacyPermissions,
                        status: .info, severity: .info,
                        detail: "\(apps.count) app(s): \(apps.joined(separator: ", "))"
                    ))
                } else if apps == nil {
                    findings.append(Finding(
                        id: "tcc_\(service)",
                        check: "\(label) Permissions",
                        category: .privacyPermissions,
                        status: .inconclusive, severity: .low,
                        detail: "Could not query TCC for \(label)"
                    ))
                }
            }
        }

        let score = RiskScore.compute(from: findings)
        let hostname = await getHostname()

        return Report(
            version: "1.0.0",
            hostname: hostname,
            findings: findings,
            riskScore: score,
            capabilities: capabilities
        )
    }

    private func getHostname() async -> String {
        let result = await runner.run(
            executable: "/usr/sbin/scutil",
            arguments: ["--get", "ComputerName"],
            timeout: 5.0
        )
        return result.succeeded ? result.stdout : "unknown"
    }
}
