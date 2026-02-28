import Foundation
@testable import MacShieldLib

/// Mock process runner for testing. Returns predetermined results per executable+args key.
public final class MockProcessRunner: ProcessRunning, @unchecked Sendable {

    /// Map of "executable arg1 arg2..." -> ProcessResult
    private var responses: [String: ProcessResult] = [:]
    private var callLog: [String] = []

    public init() {}

    /// Register a mock response for a given command.
    public func register(
        executable: String,
        arguments: [String] = [],
        result: ProcessResult
    ) {
        let key = ([executable] + arguments).joined(separator: " ")
        responses[key] = result
    }

    /// Convenience: register a successful command with stdout.
    public func registerSuccess(executable: String, arguments: [String] = [], stdout: String) {
        register(executable: executable, arguments: arguments, result: ProcessResult(
            exitCode: 0, stdout: stdout, stderr: "", timedOut: false
        ))
    }

    /// Convenience: register a failed command.
    public func registerFailure(executable: String, arguments: [String] = [], stderr: String = "") {
        register(executable: executable, arguments: arguments, result: ProcessResult(
            exitCode: 1, stdout: "", stderr: stderr, timedOut: false
        ))
    }

    /// Convenience: register a timed-out command.
    public func registerTimeout(executable: String, arguments: [String] = []) {
        register(executable: executable, arguments: arguments, result: ProcessResult(
            exitCode: -1, stdout: "", stderr: "timed out", timedOut: true
        ))
    }

    public func run(
        executable: String,
        arguments: [String],
        timeout: TimeInterval
    ) async -> ProcessResult {
        let key = ([executable] + arguments).joined(separator: " ")
        callLog.append(key)

        if let response = responses[key] {
            return response
        }

        // Default: return empty success
        return ProcessResult(exitCode: 0, stdout: "", stderr: "", timedOut: false)
    }

    /// Get the log of all commands that were called.
    public var calls: [String] { callLog }
}
