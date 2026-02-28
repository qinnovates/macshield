import Foundation

/// Result status of a security check. INCONCLUSIVE is the key differentiator
/// from the Bash version — it prevents false reassurance when a check cannot
/// determine the actual state.
public enum CheckStatus: String, Codable, Sendable {
    case pass
    case fail
    case warn
    case info
    case inconclusive

    public var symbol: String {
        switch self {
        case .pass:         return "PASS"
        case .fail:         return "FAIL"
        case .warn:         return "WARN"
        case .info:         return "INFO"
        case .inconclusive: return "UNKN"
        }
    }

    public var ansiColor: String {
        switch self {
        case .pass:         return "\u{1B}[32m"  // green
        case .fail:         return "\u{1B}[31m"  // red
        case .warn:         return "\u{1B}[33m"  // yellow
        case .info:         return "\u{1B}[36m"  // cyan
        case .inconclusive: return "\u{1B}[35m"  // magenta
        }
    }
}
