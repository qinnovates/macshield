import Foundation
import Testing
@testable import MacShieldLib

@Suite("Integration Tests")
struct IntegrationTests {

    @Test("Report serializes to valid JSON")
    func reportJSON() throws {
        let findings = [
            Finding(id: "sip", check: "SIP", category: .systemProtection,
                    status: .pass, severity: .info, detail: "enabled"),
            Finding(id: "fv", check: "FileVault", category: .systemProtection,
                    status: .fail, severity: .high, detail: "disabled"),
        ]
        let score = RiskScore.compute(from: findings)
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let report = Report(
            version: "1.0.0", hostname: "TestMac",
            findings: findings, riskScore: score, capabilities: caps
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(report)
        let json = String(data: data, encoding: .utf8)!

        // Verify it's valid JSON by decoding
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(Report.self, from: data)

        #expect(decoded.findings.count == 2)
        #expect(decoded.version == "1.0.0")
        #expect(decoded.hostname == "TestMac")
        #expect(json.contains("systemProtection"))
    }

    @Test("Human output formatter produces readable output")
    func humanOutput() {
        let findings = [
            Finding(id: "sip", check: "SIP", category: .systemProtection,
                    status: .pass, severity: .info, detail: "enabled"),
        ]
        let score = RiskScore.compute(from: findings)
        let caps = SystemCapabilities(
            hasFullDiskAccess: true, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let report = Report(
            version: "1.0.0", hostname: "TestMac",
            findings: findings, riskScore: score, capabilities: caps
        )

        let output = OutputFormatter.format(report, as: .human, color: false)

        #expect(output.contains("macshield v1.0.0"))
        #expect(output.contains("PASS"))
        #expect(output.contains("SIP"))
        #expect(output.contains("100"))  // Perfect score
        #expect(output.contains("Grade: A"))
        #expect(output.contains("Confidence:"))
    }

    @Test("System capabilities detection runs without crashing")
    func capabilitiesDetection() {
        let caps = SystemCapabilities.detect()
        #expect(!caps.osVersion.isEmpty)
        #expect(!caps.architecture.isEmpty)
    }

    @Test("OutputFormatter auto-detects format")
    func formatDetection() {
        // Explicit override
        #expect(OutputFormatter.detectFormat(explicit: "json") == .json)
        #expect(OutputFormatter.detectFormat(explicit: "human") == .human)
    }
}
