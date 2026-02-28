import Foundation

/// Severity level for a security finding. Used in risk score calculation.
public enum Severity: String, Codable, Sendable, Comparable {
    case critical
    case high
    case medium
    case low
    case info

    /// Points deducted from the risk score when this severity is triggered.
    public var pointsDeducted: Double {
        switch self {
        case .critical: return 15.0
        case .high:     return 10.0
        case .medium:   return 5.0
        case .low:      return 2.0
        case .info:     return 0.0
        }
    }

    private var sortOrder: Int {
        switch self {
        case .critical: return 4
        case .high:     return 3
        case .medium:   return 2
        case .low:      return 1
        case .info:     return 0
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.sortOrder < rhs.sortOrder
    }
}
