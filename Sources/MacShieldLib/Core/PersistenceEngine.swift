import Foundation

/// Checks persistence mechanisms: LaunchAgents, LaunchDaemons, login items,
/// cron jobs, kernel extensions. Validates ownership and code signing.
public struct PersistenceEngine: Sendable {

    private let runner: ProcessRunning

    public init(runner: ProcessRunning = SystemProcessRunner()) {
        self.runner = runner
    }

    public func scan() async -> Report {
        var findings: [Finding] = []
        let capabilities = SystemCapabilities.detect()

        // Check all persistence locations
        let checks: [PersistenceCheck] = [
            UserLaunchAgentsCheck(),
            SystemLaunchAgentsCheck(),
            SystemLaunchDaemonsCheck(),
            LoginItemsCheck(),
            CronJobsCheck(),
            KernelExtensionsCheck(),
        ]

        for check in checks {
            let result = await check.run(runner: runner, capabilities: capabilities)
            findings.append(contentsOf: result)
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
