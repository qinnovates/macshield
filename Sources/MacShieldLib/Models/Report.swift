import Foundation

/// Complete audit report with findings, score, and metadata.
public struct Report: Codable, Sendable {
    public let version: String
    public let timestamp: String
    public let hostname: String
    public let findings: [Finding]
    public let riskScore: RiskScore
    public let capabilities: SystemCapabilities

    public init(
        version: String,
        hostname: String,
        findings: [Finding],
        riskScore: RiskScore,
        capabilities: SystemCapabilities
    ) {
        self.version = version
        let formatter = ISO8601DateFormatter()
        self.timestamp = formatter.string(from: Date())
        self.hostname = hostname
        self.findings = findings
        self.riskScore = riskScore
        self.capabilities = capabilities
    }

    public var passCount: Int { findings.filter { $0.status == .pass }.count }
    public var failCount: Int { findings.filter { $0.status == .fail }.count }
    public var warnCount: Int { findings.filter { $0.status == .warn }.count }
    public var infoCount: Int { findings.filter { $0.status == .info }.count }
    public var inconclusiveCount: Int { findings.filter { $0.status == .inconclusive }.count }
}
