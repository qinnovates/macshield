import Testing
@testable import MacShieldLib

@Suite("Sanitizer Tests")
struct SanitizerTests {

    @Test("Strip control characters preserves normal text")
    func preservesNormalText() {
        let input = "Hello, World! 123"
        #expect(Sanitizer.stripControlCharacters(input) == input)
    }

    @Test("Strip control characters preserves newlines and tabs")
    func preservesNewlinesAndTabs() {
        let input = "line1\nline2\ttab"
        #expect(Sanitizer.stripControlCharacters(input) == input)
    }

    @Test("Strip control characters removes bell and escape")
    func removesControlChars() {
        let input = "hello\u{07}world\u{1B}[31m"
        let result = Sanitizer.stripControlCharacters(input)
        #expect(!result.contains("\u{07}"))
        // ESC is \u{1B} which is a control char, but [31m are printable
        #expect(!result.contains("\u{1B}"))
    }

    @Test("Redact IPv4 addresses")
    func redactIPv4() {
        let input = "Connection to 192.168.1.100 on port 443"
        let result = Sanitizer.redactIPv4(input)
        #expect(result.contains("192.168.x.x"))
        #expect(!result.contains("1.100"))
    }

    @Test("Redact multiple IPs")
    func redactMultipleIPs() {
        let input = "10.0.0.1 -> 172.16.0.5"
        let result = Sanitizer.redactIPv4(input)
        #expect(result.contains("10.0.x.x"))
        #expect(result.contains("172.16.x.x"))
    }

    @Test("Sanitize output truncates long strings")
    func truncatesLongStrings() {
        let input = String(repeating: "a", count: 5000)
        let result = Sanitizer.sanitizeOutput(input, maxLength: 100)
        #expect(result.count <= 120)  // 100 + "...(truncated)"
        #expect(result.hasSuffix("...(truncated)"))
    }

    @Test("Sanitize output passes short strings through")
    func passesShortStrings() {
        let input = "short string"
        let result = Sanitizer.sanitizeOutput(input)
        #expect(result == input)
    }
}
