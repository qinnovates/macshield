import Foundation

/// Sanitizes output strings to prevent information leakage and control character injection.
public enum Sanitizer {

    /// Strip control characters except newline and tab.
    public static func stripControlCharacters(_ input: String) -> String {
        input.unicodeScalars.filter { scalar in
            scalar == "\n" || scalar == "\t" || scalar == "\r" ||
            !CharacterSet.controlCharacters.contains(scalar)
        }.map { String($0) }.joined()
    }

    /// Redact IPv4 addresses (replace last two octets).
    public static func redactIPv4(_ input: String) -> String {
        let pattern = #"(\d{1,3}\.\d{1,3}\.)\d{1,3}\.\d{1,3}"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return input
        }
        let range = NSRange(input.startIndex..., in: input)
        return regex.stringByReplacingMatches(
            in: input,
            range: range,
            withTemplate: "$1x.x"
        )
    }

    /// Sanitize process output: strip control chars, limit length.
    public static func sanitizeOutput(_ input: String, maxLength: Int = 4096) -> String {
        let cleaned = stripControlCharacters(input)
        if cleaned.count > maxLength {
            return String(cleaned.prefix(maxLength)) + "...(truncated)"
        }
        return cleaned
    }
}
