import Foundation

/// Result of running an external process.
public struct ProcessResult: Sendable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
    public let timedOut: Bool

    public var succeeded: Bool { exitCode == 0 && !timedOut }
}

/// Protocol for running external processes. Tests inject MockProcessRunner.
public protocol ProcessRunning: Sendable {
    func run(
        executable: String,
        arguments: [String],
        timeout: TimeInterval
    ) async -> ProcessResult
}

/// Concrete implementation using Foundation.Process with real timeout enforcement
/// and non-blocking pipe draining to prevent deadlocks.
public struct SystemProcessRunner: ProcessRunning {

    public init() {}

    public func run(
        executable: String,
        arguments: [String],
        timeout: TimeInterval = 10.0
    ) async -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        // Harden PATH
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        process.environment = env

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
        } catch {
            return ProcessResult(
                exitCode: -1,
                stdout: "",
                stderr: "Failed to launch \(executable): \(error.localizedDescription)",
                timedOut: false
            )
        }

        // Drain pipes asynchronously BEFORE waiting for termination.
        // If we wait for termination first and the process writes >64KB,
        // the pipe buffer fills and the process blocks — deadlock.
        let stdoutHandle = stdoutPipe.fileHandleForReading
        let stderrHandle = stderrPipe.fileHandleForReading

        // Collect pipe data on background threads (non-blocking)
        let outDataTask = Task.detached { () -> Data in
            stdoutHandle.readDataToEndOfFile()
        }
        let errDataTask = Task.detached { () -> Data in
            stderrHandle.readDataToEndOfFile()
        }

        // Race: wait for termination vs timeout
        let timedOut = await withTaskGroup(of: Bool.self) { group in
            // Task 1: wait for process to finish
            group.addTask {
                await withCheckedContinuation { continuation in
                    process.terminationHandler = { _ in
                        continuation.resume(returning: false)
                    }
                }
            }

            // Task 2: timeout watchdog
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                return true
            }

            // First to finish wins
            let result = await group.next() ?? true
            group.cancelAll()

            if result {
                // Timeout fired first — kill the process
                if process.isRunning {
                    process.terminate()
                    // Give it 1s to die gracefully, then force kill
                    try? await Task.sleep(nanoseconds: 500_000_000)
                    if process.isRunning {
                        kill(process.processIdentifier, SIGKILL)
                    }
                }
            }

            return result
        }

        // Collect the pipe data (pipes close when process terminates)
        let outData = await outDataTask.value
        let errData = await errDataTask.value

        let outStr = String(data: outData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let errStr = String(data: errData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        if timedOut {
            return ProcessResult(
                exitCode: -1,
                stdout: outStr,
                stderr: errStr,
                timedOut: true
            )
        }

        return ProcessResult(
            exitCode: process.terminationStatus,
            stdout: outStr,
            stderr: errStr,
            timedOut: false
        )
    }
}
