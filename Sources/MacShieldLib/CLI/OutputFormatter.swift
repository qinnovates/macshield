import Foundation

/// Output format for reports.
public enum OutputFormat: String, Sendable {
    case json
    case human
}

/// Formats reports for terminal or machine consumption.
public enum OutputFormatter {

    private static let reset = "\u{1B}[0m"
    private static let bold = "\u{1B}[1m"
    private static let dim = "\u{1B}[2m"

    /// Auto-detect format: JSON when piped, human when TTY.
    public static func detectFormat(explicit: String?) -> OutputFormat {
        if let explicit {
            return OutputFormat(rawValue: explicit) ?? .human
        }
        return isatty(STDOUT_FILENO) != 0 ? .human : .json
    }

    /// Format a complete report.
    public static func format(_ report: Report, as format: OutputFormat, color: Bool = true) -> String {
        switch format {
        case .json:
            return formatJSON(report)
        case .human:
            return formatHuman(report, color: color)
        }
    }

    // MARK: - JSON

    private static func formatJSON(_ report: Report) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(report),
              let json = String(data: data, encoding: .utf8) else {
            return "{\"error\": \"Failed to encode report\"}"
        }
        return json
    }

    // MARK: - Human

    private static func formatHuman(_ report: Report, color: Bool) -> String {
        var lines: [String] = []

        lines.append("")
        lines.append(styled("macshield v\(report.version)", bold: true, color: color))
        lines.append(styled("Security Posture Report", dim: true, color: color))
        lines.append(styled("Generated: \(report.timestamp)", dim: true, color: color))
        lines.append(styled("Host: \(report.hostname)", dim: true, color: color))
        lines.append("")

        // Group findings by category
        let grouped = Dictionary(grouping: report.findings) { $0.category }
        let categoryOrder: [RiskScore.Category] = [
            .systemProtection, .firewallNetwork, .sharingServices,
            .privacyPermissions, .fileHygiene, .persistence
        ]

        for cat in categoryOrder {
            guard let findings = grouped[cat], !findings.isEmpty else { continue }
            lines.append(styled("--- \(cat.displayName) ---", bold: true, color: color))
            lines.append("")

            for finding in findings {
                let statusStr: String
                if color {
                    statusStr = "\(finding.status.ansiColor)\(finding.status.symbol)\(reset)"
                } else {
                    statusStr = finding.status.symbol
                }
                lines.append("  [\(statusStr)] \(finding.check) - \(finding.detail)")
                if let rem = finding.remediation {
                    lines.append(styled("         \(rem)", dim: true, color: color))
                }
            }
            lines.append("")
        }

        // Risk score
        lines.append(styled("--- Risk Score ---", bold: true, color: color))
        lines.append("")
        lines.append("  Composite: \(String(format: "%.0f", report.riskScore.composite))/100 (Grade: \(report.riskScore.grade))")
        lines.append("  Confidence: \(String(format: "%.0f%%", report.riskScore.confidence * 100)) (\(report.riskScore.confidenceLabel))")
        if report.riskScore.confidence < 0.9 {
            lines.append(styled("  Warning: Score confidence is reduced due to inconclusive checks.", dim: true, color: color))
        }
        lines.append("")

        for cat in RiskScore.Category.allCases {
            if let score = report.riskScore.categoryScores[cat] {
                let bar = progressBar(score, width: 20)
                lines.append("  \(cat.displayName.padding(toLength: 25, withPad: " ", startingAt: 0)) \(bar) \(String(format: "%.0f", score))")
            }
        }
        lines.append("")

        // Summary
        lines.append(styled("--- Summary ---", bold: true, color: color))
        lines.append("")
        var summary = "  PASS: \(report.passCount)  |  WARN: \(report.warnCount)  |  FAIL: \(report.failCount)"
        if report.inconclusiveCount > 0 {
            summary += "  |  INCONCLUSIVE: \(report.inconclusiveCount)"
        }
        lines.append(summary)
        lines.append("")

        // Capabilities
        if !report.capabilities.hasFullDiskAccess {
            lines.append(styled("  Note: Running without Full Disk Access. Some checks returned INCONCLUSIVE.", dim: true, color: color))
            lines.append(styled("  Grant FDA in System Settings > Privacy & Security > Full Disk Access.", dim: true, color: color))
            lines.append("")
        }

        return lines.joined(separator: "\n")
    }

    private static func progressBar(_ value: Double, width: Int) -> String {
        let filled = Int((value / 100.0) * Double(width))
        let empty = width - filled
        return "[" + String(repeating: "#", count: filled) + String(repeating: ".", count: empty) + "]"
    }

    private static func styled(_ text: String, bold: Bool = false, dim: Bool = false, color: Bool) -> String {
        guard color else { return text }
        var prefix = ""
        if bold { prefix += self.bold }
        if dim { prefix += self.dim }
        return prefix.isEmpty ? text : "\(prefix)\(text)\(reset)"
    }
}
