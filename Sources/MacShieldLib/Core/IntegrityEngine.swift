import Foundation

/// Self-verification engine. Checks code signature of the running binary.
public struct IntegrityEngine: Sendable {

    private let runner: ProcessRunning

    public init(runner: ProcessRunning = SystemProcessRunner()) {
        self.runner = runner
    }

    /// Verify the integrity of the running macshield binary.
    public func verify() async -> [Finding] {
        let binaryPath = ProcessInfo.processInfo.arguments[0]

        // Resolve to absolute path
        let resolvedPath: String
        if binaryPath.hasPrefix("/") {
            resolvedPath = binaryPath
        } else {
            let cwd = FileManager.default.currentDirectoryPath
            resolvedPath = cwd + "/" + binaryPath
        }

        let result = await runner.run(
            executable: "/usr/bin/codesign",
            arguments: ["-v", "--deep", "--strict", resolvedPath],
            timeout: 10.0
        )

        if result.succeeded {
            return [Finding(
                id: "self_integrity",
                check: "Binary Integrity",
                category: .systemProtection,
                status: .pass, severity: .info,
                detail: "Code signature valid"
            )]
        }

        return [Finding(
            id: "self_integrity",
            check: "Binary Integrity",
            category: .systemProtection,
            status: .warn, severity: .high,
            detail: "Binary signature invalid or unsigned: \(Sanitizer.sanitizeOutput(result.stderr, maxLength: 200))",
            remediation: "Reinstall macshield from a trusted source"
        )]
    }
}
