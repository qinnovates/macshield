import ArgumentParser
import Foundation

/// Root command for macshield.
@available(macOS 14, *)
public struct MacShieldCommand: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "macshield",
        abstract: "macOS security posture analyzer",
        discussion: """
            Read-only security analysis. No system modifications.
            No background processes. No sudo. Zero attack surface.
            """,
        version: "1.0.0",
        subcommands: [
            AuditCommand.self,
            ScanCommand.self,
            ConnectionsCommand.self,
            PersistenceCommand.self,
            PermissionsCommand.self,
        ],
        defaultSubcommand: AuditCommand.self
    )

    public init() {}
}

// MARK: - Shared Options

public struct FormatOptions: ParsableArguments {
    @Option(name: .long, help: "Output format: json, human")
    public var format: String?

    @Flag(name: .long, help: "Disable colored output")
    public var noColor: Bool = false

    public init() {}
}

// MARK: - Audit

public struct AuditCommand: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "audit",
        abstract: "Full security posture audit with risk scoring"
    )

    @OptionGroup public var formatOptions: FormatOptions

    public init() {}

    public func run() async throws {
        let outputFormat = OutputFormatter.detectFormat(explicit: formatOptions.format)
        let engine = AuditEngine()
        let report = await engine.audit()
        let color = !formatOptions.noColor && isatty(STDOUT_FILENO) != 0
        let output = OutputFormatter.format(report, as: outputFormat, color: color)
        print(output)
    }
}

// MARK: - Scan (Port Scanner)

public struct ScanCommand: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "scan",
        abstract: "Scan open TCP/UDP ports with process identification"
    )

    @OptionGroup public var formatOptions: FormatOptions

    public init() {}

    public func run() async throws {
        let outputFormat = OutputFormatter.detectFormat(explicit: formatOptions.format)
        let engine = ScanEngine()
        let report = await engine.scan()
        let color = !formatOptions.noColor && isatty(STDOUT_FILENO) != 0
        let output = OutputFormatter.format(report, as: outputFormat, color: color)
        print(output)
    }
}

// MARK: - Connections

public struct ConnectionsCommand: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "connections",
        abstract: "Show active TCP connections with process names"
    )

    @OptionGroup public var formatOptions: FormatOptions

    public init() {}

    public func run() async throws {
        let outputFormat = OutputFormatter.detectFormat(explicit: formatOptions.format)
        let engine = ConnectionEngine()
        let report = await engine.scan()
        let color = !formatOptions.noColor && isatty(STDOUT_FILENO) != 0
        let output = OutputFormatter.format(report, as: outputFormat, color: color)
        print(output)
    }
}

// MARK: - Persistence

public struct PersistenceCommand: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "persistence",
        abstract: "List non-Apple persistence mechanisms with signing status"
    )

    @OptionGroup public var formatOptions: FormatOptions

    public init() {}

    public func run() async throws {
        let outputFormat = OutputFormatter.detectFormat(explicit: formatOptions.format)
        let engine = PersistenceEngine()
        let report = await engine.scan()
        let color = !formatOptions.noColor && isatty(STDOUT_FILENO) != 0
        let output = OutputFormatter.format(report, as: outputFormat, color: color)
        print(output)
    }
}

// MARK: - Permissions

public struct PermissionsCommand: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "permissions",
        abstract: "Audit TCC permissions (camera, mic, screen recording, etc.)"
    )

    @OptionGroup public var formatOptions: FormatOptions

    public init() {}

    public func run() async throws {
        let outputFormat = OutputFormatter.detectFormat(explicit: formatOptions.format)
        let engine = PermissionsEngine()
        let report = await engine.scan()
        let color = !formatOptions.noColor && isatty(STDOUT_FILENO) != 0
        let output = OutputFormatter.format(report, as: outputFormat, color: color)
        print(output)
    }
}
