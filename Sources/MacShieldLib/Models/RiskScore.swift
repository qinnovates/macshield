import Foundation

/// Weighted composite risk score (0-100). Higher = more secure.
///
/// Category weights:
///   System Protection: 30%
///   Firewall/Network:  20%
///   Sharing Services:  15%
///   Persistence:       15%
///   Privacy/Perms:     10%
///   File Hygiene:      10%
public struct RiskScore: Codable, Sendable {

    public enum Category: String, Codable, Sendable, CaseIterable {
        case systemProtection
        case firewallNetwork
        case sharingServices
        case persistence
        case privacyPermissions
        case fileHygiene

        public var weight: Double {
            switch self {
            case .systemProtection:   return 0.30
            case .firewallNetwork:    return 0.20
            case .sharingServices:    return 0.15
            case .persistence:        return 0.15
            case .privacyPermissions: return 0.10
            case .fileHygiene:        return 0.10
            }
        }

        public var displayName: String {
            switch self {
            case .systemProtection:   return "System Protection"
            case .firewallNetwork:    return "Firewall & Network"
            case .sharingServices:    return "Sharing Services"
            case .persistence:        return "Persistence Integrity"
            case .privacyPermissions: return "Privacy & Permissions"
            case .fileHygiene:        return "File Hygiene"
            }
        }
    }

    public let composite: Double
    public let categoryScores: [Category: Double]
    /// Percentage of checks that ran successfully (not inconclusive). 0.0-1.0.
    /// A low confidence means the score may not reflect actual security posture.
    public let confidence: Double
    /// Number of checks that returned inconclusive per category.
    public let inconclusiveCounts: [Category: Int]

    /// Compute the risk score from findings.
    /// Each category starts at 100, deductions applied per finding severity.
    /// Composite = weighted average of category scores, clamped to 0-100.
    /// Confidence = weighted by category importance so an inconclusive critical
    /// check (e.g., SIP in systemProtection @ 30%) degrades confidence more than
    /// a trivial check (e.g., file hygiene @ 10%).
    public static func compute(from findings: [Finding]) -> RiskScore {
        var categoryDeductions: [Category: Double] = [:]
        var categoryTotalChecks: [Category: Int] = [:]
        var categoryInconclusiveCounts: [Category: Int] = [:]

        for cat in Category.allCases {
            categoryDeductions[cat] = 0.0
            categoryTotalChecks[cat] = 0
            categoryInconclusiveCounts[cat] = 0
        }

        for finding in findings {
            let cat = finding.category
            categoryTotalChecks[cat, default: 0] += 1

            if finding.status == .inconclusive {
                categoryInconclusiveCounts[cat, default: 0] += 1
            }

            guard finding.status == .fail || finding.status == .warn else { continue }
            categoryDeductions[cat, default: 0.0] += finding.severity.pointsDeducted
        }

        var scores: [Category: Double] = [:]
        var composite = 0.0

        for cat in Category.allCases {
            let score = max(0.0, min(100.0, 100.0 - categoryDeductions[cat, default: 0.0]))
            scores[cat] = score
            composite += score * cat.weight
        }

        // Weighted confidence: each category's contribution is proportional to its weight.
        // If a high-weight category (systemProtection=30%) has all inconclusive checks,
        // that degrades confidence more than a low-weight category (fileHygiene=10%).
        var weightedConfidenceSum = 0.0
        var totalActiveWeight = 0.0

        for cat in Category.allCases {
            let total = categoryTotalChecks[cat, default: 0]
            guard total > 0 else { continue }  // Category not tested = excluded from confidence
            let inconclusive = categoryInconclusiveCounts[cat, default: 0]
            let categoryConfidence = Double(total - inconclusive) / Double(total)
            weightedConfidenceSum += categoryConfidence * cat.weight
            totalActiveWeight += cat.weight
        }

        let confidence: Double
        if totalActiveWeight > 0 {
            confidence = weightedConfidenceSum / totalActiveWeight
        } else {
            confidence = 0.0  // No checks ran = zero confidence
        }

        return RiskScore(
            composite: max(0.0, min(100.0, composite)),
            categoryScores: scores,
            confidence: confidence,
            inconclusiveCounts: categoryInconclusiveCounts
        )
    }

    public var grade: String {
        switch composite {
        case 90...100: return "A"
        case 80..<90:  return "B"
        case 70..<80:  return "C"
        case 60..<70:  return "D"
        default:       return "F"
        }
    }

    /// Human-readable confidence level.
    public var confidenceLabel: String {
        switch confidence {
        case 0.9...1.0: return "High"
        case 0.7..<0.9: return "Medium"
        case 0.5..<0.7: return "Low"
        default:        return "Very Low"
        }
    }
}
