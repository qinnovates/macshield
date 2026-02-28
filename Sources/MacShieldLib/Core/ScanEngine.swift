import Foundation

/// Port scan engine — lists TCP/UDP listeners with process info and signing status.
public struct ScanEngine: Sendable {

    private let runner: ProcessRunning

    public init(runner: ProcessRunning = SystemProcessRunner()) {
        self.runner = runner
    }

    public func scan() async -> Report {
        var findings: [Finding] = []
        let capabilities = SystemCapabilities.detect()

        // TCP listeners
        let tcpResult = await runner.run(
            executable: "/usr/bin/lsof",
            arguments: ["-iTCP", "-sTCP:LISTEN", "-P", "-n"],
            timeout: 10.0
        )

        if tcpResult.succeeded {
            let tcpFindings = parseLsofOutput(tcpResult.stdout, protocol: "TCP")
            findings.append(contentsOf: tcpFindings)
        } else {
            findings.append(Finding(
                id: "tcp_scan", check: "TCP Port Scan", category: .firewallNetwork,
                status: .inconclusive, severity: .medium,
                detail: "lsof failed: \(Sanitizer.sanitizeOutput(tcpResult.stderr, maxLength: 200))"
            ))
        }

        // UDP listeners
        let udpResult = await runner.run(
            executable: "/usr/bin/lsof",
            arguments: ["-iUDP", "-P", "-n"],
            timeout: 10.0
        )

        if udpResult.succeeded {
            let udpFindings = parseLsofOutput(udpResult.stdout, protocol: "UDP")
            findings.append(contentsOf: udpFindings)
        }

        // Check signing status for non-standard port listeners
        let unsignedFindings = await checkSigningForListeners(findings)
        findings.append(contentsOf: unsignedFindings)

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

    private func parseLsofOutput(_ output: String, protocol proto: String) -> [Finding] {
        var findings: [Finding] = []
        var seen = Set<String>()

        for line in output.components(separatedBy: "\n") {
            guard !line.hasPrefix("COMMAND") else { continue }
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 9 else { continue }

            let cmd = String(parts[0])
            let pid = String(parts[1])
            let addr = String(parts[8])
            let port = addr.components(separatedBy: ":").last ?? "?"

            let key = "\(proto):\(port):\(cmd)"
            guard !seen.contains(key) else { continue }
            seen.insert(key)

            let note = portNote(port)
            let isReviewable = note == "REVIEW"

            findings.append(Finding(
                id: "port_\(proto.lowercased())_\(port)",
                check: "\(proto) Port \(port)",
                category: .firewallNetwork,
                status: isReviewable ? .warn : .info,
                severity: isReviewable ? .low : .info,
                detail: "\(cmd) (PID \(pid)) - \(note)"
            ))
        }

        return findings
    }

    private func portNote(_ port: String) -> String {
        guard let p = Int(port) else { return "unbound" }
        switch p {
        case 53:    return "DNS"
        case 80:    return "HTTP"
        case 88:    return "Kerberos"
        case 123:   return "NTP"
        case 137:   return "NetBIOS name"
        case 138:   return "NetBIOS datagram"
        case 443:   return "HTTPS"
        case 500:   return "IKE/VPN"
        case 631:   return "CUPS/printing"
        case 1900:  return "SSDP/UPnP"
        case 3722:  return "DeviceLink2/iOS sync"
        case 5000:  return "AirPlay/UPnP"
        case 5353:  return "mDNS/Bonjour"
        case 7000:  return "AirPlay streaming"
        case 49152...65535: return "ephemeral"
        default:    return "REVIEW"
        }
    }

    /// Check code signing for binaries listening on non-standard ports.
    private func checkSigningForListeners(_ findings: [Finding]) async -> [Finding] {
        var unsignedFindings: [Finding] = []

        for finding in findings where finding.status == .warn {
            // Extract PID from detail
            let detail = finding.detail
            guard let pidRange = detail.range(of: #"PID (\d+)"#, options: .regularExpression),
                  let pid = detail[pidRange].split(separator: " ").last else { continue }

            let result = await runner.run(
                executable: "/usr/bin/codesign",
                arguments: ["-v", "--pid", String(pid)],
                timeout: 5.0
            )

            if !result.succeeded {
                unsignedFindings.append(Finding(
                    id: "\(finding.id)_unsigned",
                    check: "\(finding.check) - Code Signing",
                    category: .firewallNetwork,
                    status: .warn, severity: .medium,
                    detail: "Binary is unsigned or has invalid signature",
                    remediation: "Investigate the process listening on this port"
                ))
            }
        }

        return unsignedFindings
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
