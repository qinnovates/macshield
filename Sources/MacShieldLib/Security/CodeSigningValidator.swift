import Foundation

/// Validates code signing of arbitrary binaries using codesign CLI.
/// Used for checking persistence items and port listeners.
public struct CodeSigningValidator: Sendable {

    private let runner: ProcessRunning

    public init(runner: ProcessRunning = SystemProcessRunner()) {
        self.runner = runner
    }

    public struct SigningInfo: Sendable {
        public let isSigned: Bool
        public let isApple: Bool
        public let identity: String
        public let detail: String
    }

    /// Check if a binary at the given path is properly signed.
    public func validate(path: String) async -> SigningInfo {
        let result = await runner.run(
            executable: "/usr/bin/codesign",
            arguments: ["-dv", "--verbose=2", path],
            timeout: 10.0
        )

        // codesign -dv writes to stderr
        let output = result.stderr

        if output.contains("code object is not signed") || result.exitCode != 0 {
            return SigningInfo(
                isSigned: false,
                isApple: false,
                identity: "unsigned",
                detail: "Binary is not code signed"
            )
        }

        var identity = "unknown"
        var isApple = false

        for line in output.components(separatedBy: "\n") {
            if line.hasPrefix("Authority=") {
                identity = String(line.dropFirst("Authority=".count))
                if identity.contains("Apple") || identity.contains("Software Signing") {
                    isApple = true
                }
                break
            }
        }

        return SigningInfo(
            isSigned: true,
            isApple: isApple,
            identity: identity,
            detail: "Signed by: \(identity)"
        )
    }

    /// Check signing status of a process by PID.
    public func validatePID(_ pid: String) async -> SigningInfo {
        let result = await runner.run(
            executable: "/usr/bin/codesign",
            arguments: ["-v", "--pid", pid],
            timeout: 5.0
        )

        if result.succeeded {
            return SigningInfo(
                isSigned: true,
                isApple: false,  // Can't determine from -v alone
                identity: "valid",
                detail: "Process has valid signature"
            )
        }

        return SigningInfo(
            isSigned: false,
            isApple: false,
            identity: "unsigned/invalid",
            detail: Sanitizer.sanitizeOutput(result.stderr, maxLength: 200)
        )
    }
}
