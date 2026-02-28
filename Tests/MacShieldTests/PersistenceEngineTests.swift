import Testing
@testable import MacShieldLib

@Suite("Persistence Engine Tests")
struct PersistenceEngineTests {

    @Test("Kext check detects non-Apple kexts")
    func nonAppleKexts() async {
        let mock = MockProcessRunner()
        mock.registerSuccess(
            executable: "/usr/sbin/kextstat",
            arguments: [],
            stdout: """
            Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
                1   10 0xffffff8000 0x1000  0x1000     com.apple.kpi.bsd (20.0)
                2    5 0xffffff8001 0x2000  0x2000     com.vmware.kext.vmx86 (16.0)
            """
        )

        let check = KernelExtensionsCheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        #expect(findings.count == 1)
        #expect(findings[0].status == .warn)
        #expect(findings[0].detail.contains("vmware"))
    }

    @Test("Cron check reports no cron jobs")
    func noCronJobs() async {
        let mock = MockProcessRunner()
        mock.registerFailure(
            executable: "/usr/bin/crontab",
            arguments: ["-l"],
            stderr: "no crontab for user"
        )

        let check = CronJobsCheck()
        let caps = SystemCapabilities(
            hasFullDiskAccess: false, architecture: "arm64",
            osVersion: "14.0", isRosetta: false
        )
        let findings = await check.run(runner: mock, capabilities: caps)

        #expect(findings[0].detail == "none")
    }
}
