import MacShieldLib
import ArgumentParser

// Struct to serve as async entry point
@available(macOS 14, *)
@main struct MacShieldEntry: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
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
}
