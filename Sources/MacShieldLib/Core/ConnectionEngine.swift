import Foundation

/// Shows active TCP connections with process names.
public struct ConnectionEngine: Sendable {

    private let runner: ProcessRunning

    public init(runner: ProcessRunning = SystemProcessRunner()) {
        self.runner = runner
    }

    public func scan() async -> Report {
        var findings: [Finding] = []
        let capabilities = SystemCapabilities.detect()

        let result = await runner.run(
            executable: "/usr/bin/lsof",
            arguments: ["-i", "-nP"],
            timeout: 10.0
        )

        if result.succeeded {
            var seen = Set<String>()

            for line in result.stdout.components(separatedBy: "\n") {
                guard line.contains("ESTABLISHED") else { continue }
                let parts = line.split(separator: " ", omittingEmptySubsequences: true)
                guard parts.count >= 9 else { continue }

                let cmd = String(parts[0])
                let pid = String(parts[1])
                let nameField = String(parts[8])

                var remote = nameField
                var localPort = ""

                if nameField.contains("->") {
                    let halves = nameField.components(separatedBy: "->")
                    localPort = halves[0].components(separatedBy: ":").last ?? ""
                    remote = halves.count > 1 ? halves[1] : nameField
                }

                let key = "\(cmd):\(remote)"
                guard !seen.contains(key) else { continue }
                seen.insert(key)

                findings.append(Finding(
                    id: "conn_\(cmd)_\(pid)",
                    check: "Connection: \(cmd)",
                    category: .firewallNetwork,
                    status: .info, severity: .info,
                    detail: "PID \(pid) -> \(Sanitizer.redactIPv4(remote)) (local port: \(localPort))"
                ))
            }
        } else {
            findings.append(Finding(
                id: "connections_scan", check: "Active Connections", category: .firewallNetwork,
                status: .inconclusive, severity: .medium,
                detail: "lsof failed"
            ))
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
