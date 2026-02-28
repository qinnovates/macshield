import Foundation

/// Protocol that all security checks conform to.
public protocol SecurityCheck: Sendable {
    var id: String { get }
    var category: RiskScore.Category { get }
    func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding]
}

/// Runs all audit checks and produces a Report.
public struct AuditEngine: Sendable {

    public let version = "1.0.0"
    private let runner: ProcessRunning
    private let capabilities: SystemCapabilities
    private let checks: [SecurityCheck]

    public init(
        runner: ProcessRunning = SystemProcessRunner(),
        capabilities: SystemCapabilities? = nil,
        checks: [SecurityCheck]? = nil
    ) {
        self.runner = runner
        self.capabilities = capabilities ?? SystemCapabilities.detect()
        self.checks = checks ?? Self.defaultChecks()
    }

    /// All default audit checks.
    public static func defaultChecks() -> [SecurityCheck] {
        [
            SIPCheck(),
            FileVaultCheck(),
            GatekeeperCheck(),
            AMFICheck(),
            SecureBootCheck(),
            LockdownModeCheck(),
            XProtectVersionCheck(),
            FirewallEnabledCheck(),
            StealthModeCheck(),
            SSHCheck(),
            ScreenSharingCheck(),
            SMBCheck(),
            ARDCheck(),
            RemoteAppleEventsCheck(),
            BluetoothCheck(),
            AirDropCheck(),
            AnalyticsCheck(),
            SiriCheck(),
            SpotlightSuggestionsCheck(),
            PersonalizedAdsCheck(),
            WiFiSecurityCheck(),
            PrivateWiFiAddressCheck(),
            DNSCheck(),
            ARPSpoofingCheck(),
            SSHDirectoryCheck(),
            SSHKeyPermissionsCheck(),
            EnvFilesCheck(),
            GitCredentialsCheck(),
            NetrcCheck(),
        ]
    }

    /// Run all checks and return a Report.
    public func audit() async -> Report {
        var allFindings: [Finding] = []

        for check in checks {
            let findings = await check.run(runner: runner, capabilities: capabilities)
            allFindings.append(contentsOf: findings)
        }

        let score = RiskScore.compute(from: allFindings)
        let hostname = await getHostname()

        return Report(
            version: version,
            hostname: hostname,
            findings: allFindings,
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
