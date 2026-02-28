import Testing
@testable import MacShieldLib

@Suite("Risk Score Tests")
struct RiskScoreTests {

    @Test("Perfect score with no findings")
    func perfectScore() {
        let score = RiskScore.compute(from: [])
        #expect(score.composite == 100.0)
        #expect(score.grade == "A")
        #expect(score.confidence == 0.0)  // No checks = zero confidence
    }

    @Test("Perfect score with all pass findings")
    func allPassFindings() {
        let findings = [
            Finding(id: "1", check: "SIP", category: .systemProtection,
                    status: .pass, severity: .info, detail: "ok"),
            Finding(id: "2", check: "FV", category: .systemProtection,
                    status: .pass, severity: .info, detail: "ok"),
        ]
        let score = RiskScore.compute(from: findings)
        #expect(score.composite == 100.0)
        #expect(score.confidence == 1.0)  // All checks ran successfully
    }

    @Test("Score decreases with failures")
    func failureDeduction() {
        let findings = [
            Finding(id: "1", check: "SIP", category: .systemProtection,
                    status: .fail, severity: .critical, detail: "disabled"),
        ]
        let score = RiskScore.compute(from: findings)
        // System protection weight = 0.30, critical deduction = 15
        // System protection score = 85, all others = 100
        // Composite = 85 * 0.30 + 100 * 0.70 = 25.5 + 70 = 95.5
        #expect(score.composite == 95.5)
        #expect(score.grade == "A")
        #expect(score.confidence == 1.0)
    }

    @Test("Multiple failures across categories")
    func multipleFailures() {
        let findings = [
            Finding(id: "1", check: "SIP", category: .systemProtection,
                    status: .fail, severity: .critical, detail: "disabled"),
            Finding(id: "2", check: "FW", category: .firewallNetwork,
                    status: .warn, severity: .medium, detail: "disabled"),
            Finding(id: "3", check: "SSH", category: .sharingServices,
                    status: .warn, severity: .medium, detail: "enabled"),
            Finding(id: "4", check: "env", category: .fileHygiene,
                    status: .warn, severity: .medium, detail: "found"),
        ]
        let score = RiskScore.compute(from: findings)
        #expect(score.composite < 100.0)
        #expect(score.composite > 0.0)
    }

    @Test("Score floors at 0")
    func scoreFloor() {
        // Generate enough critical failures to blow past 0
        var findings: [Finding] = []
        for i in 0..<20 {
            findings.append(Finding(
                id: "\(i)", check: "check_\(i)", category: .systemProtection,
                status: .fail, severity: .critical, detail: "bad"
            ))
        }
        let score = RiskScore.compute(from: findings)
        #expect(score.categoryScores[.systemProtection] == 0.0)
    }

    @Test("Grade boundaries")
    func gradeBoundaries() {
        // Test grade calculation directly
        let a = RiskScore(composite: 95, categoryScores: [:], confidence: 1.0, inconclusiveCounts: [:])
        #expect(a.grade == "A")

        let b = RiskScore(composite: 85, categoryScores: [:], confidence: 1.0, inconclusiveCounts: [:])
        #expect(b.grade == "B")

        let c = RiskScore(composite: 75, categoryScores: [:], confidence: 1.0, inconclusiveCounts: [:])
        #expect(c.grade == "C")

        let d = RiskScore(composite: 65, categoryScores: [:], confidence: 1.0, inconclusiveCounts: [:])
        #expect(d.grade == "D")

        let f = RiskScore(composite: 55, categoryScores: [:], confidence: 1.0, inconclusiveCounts: [:])
        #expect(f.grade == "F")
    }

    @Test("Category weights sum to 1.0")
    func weightSum() {
        let sum = RiskScore.Category.allCases.reduce(0.0) { $0 + $1.weight }
        #expect(abs(sum - 1.0) < 0.001)
    }

    @Test("Info findings don't affect score")
    func infoNoEffect() {
        let findings = [
            Finding(id: "1", check: "BT", category: .sharingServices,
                    status: .info, severity: .info, detail: "enabled"),
        ]
        let score = RiskScore.compute(from: findings)
        #expect(score.composite == 100.0)
    }

    @Test("Inconclusive findings reduce confidence")
    func inconclusiveReducesConfidence() {
        let findings = [
            Finding(id: "1", check: "SIP", category: .systemProtection,
                    status: .pass, severity: .info, detail: "ok"),
            Finding(id: "2", check: "TCC", category: .privacyPermissions,
                    status: .inconclusive, severity: .medium, detail: "no FDA"),
        ]
        let score = RiskScore.compute(from: findings)
        // Weighted confidence: systemProtection(1.0) * 0.30 + privacyPermissions(0.0) * 0.10
        // = 0.30 / 0.40 = 0.75 (floating point: use approximate comparison)
        #expect(abs(score.confidence - 0.75) < 0.001)
        #expect(score.inconclusiveCounts[.privacyPermissions] == 1)
        #expect(score.confidenceLabel == "Medium")
    }

    @Test("All inconclusive means zero confidence")
    func allInconclusiveZeroConfidence() {
        let findings = [
            Finding(id: "1", check: "TCC", category: .privacyPermissions,
                    status: .inconclusive, severity: .medium, detail: "no FDA"),
            Finding(id: "2", check: "SIP", category: .systemProtection,
                    status: .inconclusive, severity: .critical, detail: "timeout"),
        ]
        let score = RiskScore.compute(from: findings)
        #expect(score.confidence == 0.0)
        #expect(score.composite == 100.0)  // No deductions from inconclusive
    }
}
