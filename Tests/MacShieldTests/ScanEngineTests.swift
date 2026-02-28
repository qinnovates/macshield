import Testing
@testable import MacShieldLib

@Suite("Scan Engine Tests")
struct ScanEngineTests {

    @Test("Scan parses TCP listeners from lsof output")
    func parseTCPListeners() async {
        let mock = MockProcessRunner()
        mock.registerSuccess(
            executable: "/usr/bin/lsof",
            arguments: ["-iTCP", "-sTCP:LISTEN", "-P", "-n"],
            stdout: "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nrapportd 123 user 3u IPv4 0x1234 0t0 TCP *:443 (LISTEN)\nmDNSRespon 456 _mdns 7u IPv4 0x1234 0t0 TCP *:5353 (LISTEN)\nnode 789 user 5u IPv4 0x1234 0t0 TCP *:3000 (LISTEN)"
        )
        mock.registerSuccess(
            executable: "/usr/bin/lsof",
            arguments: ["-iUDP", "-P", "-n"],
            stdout: ""
        )
        mock.registerSuccess(
            executable: "/usr/sbin/scutil",
            arguments: ["--get", "ComputerName"],
            stdout: "TestMac"
        )

        let engine = ScanEngine(runner: mock)
        let report = await engine.scan()

        // Should have findings for the 3 TCP ports
        let portFindings = report.findings.filter { $0.id.hasPrefix("port_tcp") }
        #expect(portFindings.count == 3)

        // Port 3000 should be flagged for review
        let reviewable = portFindings.filter { $0.status == .warn }
        #expect(reviewable.count >= 1)
    }

    @Test("Scan handles lsof failure gracefully")
    func lsofFailure() async {
        let mock = MockProcessRunner()
        mock.registerFailure(
            executable: "/usr/bin/lsof",
            arguments: ["-iTCP", "-sTCP:LISTEN", "-P", "-n"],
            stderr: "permission denied"
        )
        mock.registerSuccess(
            executable: "/usr/bin/lsof",
            arguments: ["-iUDP", "-P", "-n"],
            stdout: ""
        )
        mock.registerSuccess(
            executable: "/usr/sbin/scutil",
            arguments: ["--get", "ComputerName"],
            stdout: "TestMac"
        )

        let engine = ScanEngine(runner: mock)
        let report = await engine.scan()

        let inconclusive = report.findings.filter { $0.status == .inconclusive }
        #expect(!inconclusive.isEmpty)
    }
}
