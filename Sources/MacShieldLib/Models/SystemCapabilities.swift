import Foundation

/// Runtime-detected system capabilities. Probed once at startup.
public struct SystemCapabilities: Codable, Sendable {
    /// Whether Full Disk Access is available (TCC.db readable)
    public let hasFullDiskAccess: Bool
    /// CPU architecture (arm64, x86_64)
    public let architecture: String
    /// macOS version string
    public let osVersion: String
    /// Whether running under Rosetta
    public let isRosetta: Bool

    public static func detect() -> SystemCapabilities {
        let hasFDA = FileManager.default.isReadableFile(
            atPath: NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"
        )

        #if arch(arm64)
        let arch = "arm64"
        #elseif arch(x86_64)
        let arch = "x86_64"
        #else
        let arch = "unknown"
        #endif

        let version = ProcessInfo.processInfo.operatingSystemVersionString

        // Detect Rosetta: sysctl.proc_translated == 1
        var isRosetta = false
        var size = MemoryLayout<Int32>.size
        var translated: Int32 = 0
        if sysctlbyname("sysctl.proc_translated", &translated, &size, nil, 0) == 0 {
            isRosetta = translated == 1
        }

        return SystemCapabilities(
            hasFullDiskAccess: hasFDA,
            architecture: arch,
            osVersion: version,
            isRosetta: isRosetta
        )
    }
}
