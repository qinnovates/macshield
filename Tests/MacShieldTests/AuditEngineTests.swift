import Testing
@testable import MacShieldLib

@Suite("Audit Engine Tests")
struct AuditEngineTests {

    @Test("SIP check returns pass when enabled")
    func sipEnabled() async {
        let mock = MockProcessRunner()
        mock.registerSuccess(
            executable: "/usr/bin/csrutil",
            arguments: ["status"],
            stdout: "System Integrity Protection status: enabled."
        )

        let check = SIPCheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        #expect(findings.count == 1)
        #expect(findings[0].status == .pass)
    }

    @Test("SIP check returns fail when disabled")
    func sipDisabled() async {
        let mock = MockProcessRunner()
        mock.registerSuccess(
            executable: "/usr/bin/csrutil",
            arguments: ["status"],
            stdout: "System Integrity Protection status: disabled."
        )

        let check = SIPCheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        #expect(findings.count == 1)
        #expect(findings[0].status == .fail)
        #expect(findings[0].severity == .critical)
    }

    @Test("SIP check returns warn for custom configuration")
    func sipCustomConfig() async {
        let mock = MockProcessRunner()
        mock.registerSuccess(
            executable: "/usr/bin/csrutil",
            arguments: ["status"],
            stdout: "System Integrity Protection status: enabled (Custom Configuration)."
        )

        let check = SIPCheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        #expect(findings.count == 1)
        #expect(findings[0].status == .warn)
        #expect(findings[0].severity == .high)
    }

    @Test("SIP check returns inconclusive on timeout")
    func sipTimeout() async {
        let mock = MockProcessRunner()
        mock.registerTimeout(executable: "/usr/bin/csrutil", arguments: ["status"])

        let check = SIPCheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        #expect(findings.count == 1)
        #expect(findings[0].status == .inconclusive)
    }

    @Test("SIP disabled is NOT a false positive (the critical bug)")
    func sipDisabledNotFalsePositive() async {
        // This test verifies the fix for the substring matching bug
        // where "disabled" contains "enabled" as a substring
        let mock = MockProcessRunner()
        mock.registerSuccess(
            executable: "/usr/bin/csrutil",
            arguments: ["status"],
            stdout: "System Integrity Protection status: disabled."
        )

        let check = SIPCheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        // MUST be fail, NEVER pass
        #expect(findings[0].status == .fail)
        #expect(findings[0].status != .pass)
    }

    @Test("FileVault check returns pass when on")
    func fileVaultOn() async {
        let mock = MockProcessRunner()
        mock.registerSuccess(
            executable: "/usr/bin/fdesetup",
            arguments: ["status"],
            stdout: "FileVault is On."
        )

        let check = FileVaultCheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        #expect(findings[0].status == .pass)
    }

    @Test("Gatekeeper check reads stderr too")
    func gatekeeperStderr() async {
        let mock = MockProcessRunner()
        // spctl writes to stderr on some versions
        mock.register(
            executable: "/usr/sbin/spctl",
            arguments: ["--status"],
            result: ProcessResult(exitCode: 0, stdout: "", stderr: "assessments enabled", timedOut: false)
        )

        let check = GatekeeperCheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        #expect(findings[0].status == .pass)
    }

    @Test("Gatekeeper disabled is detected correctly")
    func gatekeeperDisabled() async {
        let mock = MockProcessRunner()
        mock.register(
            executable: "/usr/sbin/spctl",
            arguments: ["--status"],
            result: ProcessResult(exitCode: 0, stdout: "", stderr: "assessments disabled", timedOut: false)
        )

        let check = GatekeeperCheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        #expect(findings[0].status == .fail)
    }

    @Test("AMFI check detects disabled AMFI")
    func amfiDisabled() async {
        let mock = MockProcessRunner()
        mock.registerSuccess(
            executable: "/usr/sbin/nvram",
            arguments: ["-p"],
            stdout: "amfi_get_out_of_my_way\t1\nother-var\tvalue"
        )

        let check = AMFICheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        #expect(findings[0].status == .fail)
        #expect(findings[0].severity == .critical)
    }

    @Test("AMFI check with value=0 is warn, not fail")
    func amfiValueZero() async {
        let mock = MockProcessRunner()
        mock.registerSuccess(
            executable: "/usr/sbin/nvram",
            arguments: ["-p"],
            stdout: "amfi_get_out_of_my_way\t0\nother-var\tvalue"
        )

        let check = AMFICheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        // Key exists but value is 0 — warn, not fail
        #expect(findings[0].status == .warn)
        #expect(findings[0].status != .fail)
    }

    @Test("Firewall disabled is not a false positive")
    func firewallDisabledNotFalsePositive() async {
        let mock = MockProcessRunner()
        mock.registerSuccess(
            executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
            arguments: ["--getglobalstate"],
            stdout: "Firewall is disabled. (State = 0)"
        )

        let check = FirewallEnabledCheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        #expect(findings[0].status == .warn)
        #expect(findings[0].status != .pass)
    }

    @Test("Full audit produces findings and risk score with confidence")
    func fullAudit() async {
        let mock = MockProcessRunner()
        // Register minimum required responses
        mock.registerSuccess(executable: "/usr/bin/csrutil", arguments: ["status"],
                           stdout: "System Integrity Protection status: enabled.")
        mock.registerSuccess(executable: "/usr/bin/fdesetup", arguments: ["status"],
                           stdout: "FileVault is On.")
        mock.registerSuccess(executable: "/usr/sbin/spctl", arguments: ["--status"],
                           stdout: "assessments enabled")
        mock.registerSuccess(executable: "/usr/sbin/nvram", arguments: ["-p"],
                           stdout: "")
        mock.registerSuccess(executable: "/usr/sbin/scutil", arguments: ["--get", "ComputerName"],
                           stdout: "TestMac")

        let engine = AuditEngine(
            runner: mock,
            capabilities: SystemCapabilities(
                hasFullDiskAccess: false, architecture: "arm64",
                osVersion: "14.0", isRosetta: false
            )
        )

        let report = await engine.audit()

        #expect(!report.findings.isEmpty)
        #expect(report.riskScore.composite >= 0)
        #expect(report.riskScore.composite <= 100)
        #expect(report.hostname == "TestMac")
        #expect(report.riskScore.confidence >= 0.0)
        #expect(report.riskScore.confidence <= 1.0)
    }
}
