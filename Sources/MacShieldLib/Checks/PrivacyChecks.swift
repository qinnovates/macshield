import Foundation

// MARK: - Analytics

public struct AnalyticsCheck: SecurityCheck {
    public let id = "analytics"
    public let category = RiskScore.Category.privacyPermissions

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/bin/defaults",
            arguments: ["read", "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist", "AutoSubmit"],
            timeout: 5.0
        )

        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if value == "0" {
            return [Finding(
                id: id, check: "Share Mac Analytics", category: category,
                status: .pass, severity: .info, detail: "disabled"
            )]
        } else if value == "1" {
            return [Finding(
                id: id, check: "Share Mac Analytics", category: category,
                status: .warn, severity: .low,
                detail: "enabled (sends usage data to Apple)",
                remediation: "Disable in System Settings > Privacy & Security > Analytics & Improvements"
            )]
        }

        return [Finding(
            id: id, check: "Share Mac Analytics", category: category,
            status: .info, severity: .info,
            detail: "could not determine"
        )]
    }
}

// MARK: - Siri

public struct SiriCheck: SecurityCheck {
    public let id = "siri"
    public let category = RiskScore.Category.privacyPermissions

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/bin/defaults",
            arguments: ["read", "com.apple.assistant.support", "Assistant Enabled"],
            timeout: 5.0
        )

        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if value == "0" {
            return [Finding(
                id: id, check: "Siri", category: category,
                status: .pass, severity: .info, detail: "disabled"
            )]
        } else if value == "1" {
            return [Finding(
                id: id, check: "Siri", category: category,
                status: .info, severity: .info,
                detail: "enabled (sends voice data to Apple for processing)"
            )]
        }

        return [Finding(
            id: id, check: "Siri", category: category,
            status: .info, severity: .info,
            detail: "could not determine"
        )]
    }
}

// MARK: - Spotlight Suggestions

public struct SpotlightSuggestionsCheck: SecurityCheck {
    public let id = "spotlight_suggestions"
    public let category = RiskScore.Category.privacyPermissions

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/bin/defaults",
            arguments: ["read", "com.apple.lookup.shared", "LookupSuggestionsDisabled"],
            timeout: 5.0
        )

        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if value == "1" {
            return [Finding(
                id: id, check: "Spotlight Suggestions", category: category,
                status: .pass, severity: .info, detail: "disabled (queries stay local)"
            )]
        }

        return [Finding(
            id: id, check: "Spotlight Suggestions", category: category,
            status: .info, severity: .info,
            detail: "enabled (sends search queries to Apple)"
        )]
    }
}

// MARK: - Personalized Ads

public struct PersonalizedAdsCheck: SecurityCheck {
    public let id = "personalized_ads"
    public let category = RiskScore.Category.privacyPermissions

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/bin/defaults",
            arguments: ["read", "com.apple.AdLib", "allowApplePersonalizedAdvertising"],
            timeout: 5.0
        )

        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if value == "0" {
            return [Finding(
                id: id, check: "Personalized Ads", category: category,
                status: .pass, severity: .info, detail: "disabled"
            )]
        }

        return [Finding(
            id: id, check: "Personalized Ads", category: category,
            status: .info, severity: .info,
            detail: "enabled or could not determine"
        )]
    }
}
