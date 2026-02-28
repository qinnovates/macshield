import Foundation
import Testing
@testable import MacShieldLib

@Suite("Finding Model Tests")
struct FindingTests {

    @Test("Finding encodes to JSON correctly")
    func findingEncodesJSON() throws {
        let finding = Finding(
            id: "test_1",
            check: "Test Check",
            category: .systemProtection,
            status: .pass,
            severity: .info,
            detail: "all good"
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(finding)
        let json = String(data: data, encoding: .utf8)!

        #expect(json.contains("test_1"))
        #expect(json.contains("pass"))
        #expect(json.contains("all good"))
    }

    @Test("Finding decodes from JSON correctly")
    func findingDecodesJSON() throws {
        let json = """
        {
            "id": "test_2",
            "check": "FileVault",
            "category": "systemProtection",
            "status": "fail",
            "severity": "high",
            "detail": "not enabled",
            "remediation": "Enable FileVault"
        }
        """

        let decoder = JSONDecoder()
        let finding = try decoder.decode(Finding.self, from: json.data(using: .utf8)!)

        #expect(finding.id == "test_2")
        #expect(finding.status == CheckStatus.fail)
        #expect(finding.severity == Severity.high)
        #expect(finding.remediation == "Enable FileVault")
        #expect(finding.category == .systemProtection)
    }

    @Test("CheckStatus symbols are correct")
    func checkStatusSymbols() {
        #expect(CheckStatus.pass.symbol == "PASS")
        #expect(CheckStatus.fail.symbol == "FAIL")
        #expect(CheckStatus.warn.symbol == "WARN")
        #expect(CheckStatus.info.symbol == "INFO")
        #expect(CheckStatus.inconclusive.symbol == "UNKN")
    }

    @Test("Severity ordering is correct")
    func severityOrdering() {
        #expect(Severity.info < Severity.low)
        #expect(Severity.low < Severity.medium)
        #expect(Severity.medium < Severity.high)
        #expect(Severity.high < Severity.critical)
    }

    @Test("Severity points deducted are correct")
    func severityPoints() {
        #expect(Severity.critical.pointsDeducted == 15.0)
        #expect(Severity.high.pointsDeducted == 10.0)
        #expect(Severity.medium.pointsDeducted == 5.0)
        #expect(Severity.low.pointsDeducted == 2.0)
        #expect(Severity.info.pointsDeducted == 0.0)
    }
}
