import Foundation

/// A single security finding produced by a check.
public struct Finding: Codable, Sendable {
    public let id: String
    public let check: String
    public let category: RiskScore.Category
    public let status: CheckStatus
    public let severity: Severity
    public let detail: String
    public let remediation: String?

    public init(
        id: String,
        check: String,
        category: RiskScore.Category,
        status: CheckStatus,
        severity: Severity,
        detail: String,
        remediation: String? = nil
    ) {
        self.id = id
        self.check = check
        self.category = category
        self.status = status
        self.severity = severity
        self.detail = detail
        self.remediation = remediation
    }
}
