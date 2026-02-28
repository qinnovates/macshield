import Foundation

// MARK: - WiFi Security

public struct WiFiSecurityCheck: SecurityCheck {
    public let id = "wifi_security"
    public let category = RiskScore.Category.firewallNetwork

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        // Get WiFi interface
        let hwResult = await runner.run(
            executable: "/usr/sbin/networksetup",
            arguments: ["-listallhardwareports"],
            timeout: 5.0
        )

        guard let iface = extractWiFiInterface(from: hwResult.stdout) else {
            return [Finding(
                id: id, check: "WiFi Security", category: category,
                status: .info, severity: .info, detail: "No WiFi interface detected"
            )]
        }

        // Try ipconfig first
        let ipResult = await runner.run(
            executable: "/usr/sbin/ipconfig",
            arguments: ["getsummary", iface],
            timeout: 5.0
        )

        var security = ""
        for line in ipResult.stdout.components(separatedBy: "\n") {
            if line.contains("Security") {
                security = line.components(separatedBy: " : ").last?
                    .trimmingCharacters(in: .whitespaces) ?? ""
                break
            }
        }

        // Fallback to system_profiler
        if security.isEmpty {
            let spResult = await runner.run(
                executable: "/usr/sbin/system_profiler",
                arguments: ["SPAirPortDataType"],
                timeout: 10.0
            )
            for line in spResult.stdout.components(separatedBy: "\n") {
                if line.contains("Security") {
                    security = line.components(separatedBy: ":").last?
                        .trimmingCharacters(in: .whitespaces) ?? ""
                    break
                }
            }
        }

        if security.isEmpty {
            return [Finding(
                id: id, check: "WiFi Security", category: category,
                status: .inconclusive, severity: .medium,
                detail: "Could not determine WiFi security type"
            )]
        }

        if security.contains("WPA3") || security.contains("SAE") {
            return [Finding(
                id: id, check: "WiFi Security", category: category,
                status: .pass, severity: .info, detail: security
            )]
        } else if security.contains("WPA2") {
            return [Finding(
                id: id, check: "WiFi Security", category: category,
                status: .pass, severity: .info, detail: security
            )]
        } else if security.contains("WEP") {
            return [Finding(
                id: id, check: "WiFi Security", category: category,
                status: .fail, severity: .critical,
                detail: "\(security) (WEP is broken, do not use)",
                remediation: "Connect to a WPA2/WPA3 network"
            )]
        } else if security.contains("None") || security.contains("Open") {
            return [Finding(
                id: id, check: "WiFi Security", category: category,
                status: .fail, severity: .high,
                detail: "OPEN network (no encryption, traffic visible to all)",
                remediation: "Use a VPN or connect to an encrypted network"
            )]
        }

        return [Finding(
            id: id, check: "WiFi Security", category: category,
            status: .info, severity: .info, detail: security
        )]
    }

    private func extractWiFiInterface(from output: String) -> String? {
        let lines = output.components(separatedBy: "\n")
        for (i, line) in lines.enumerated() {
            if line.contains("Wi-Fi") || line.contains("AirPort") {
                if i + 1 < lines.count {
                    let deviceLine = lines[i + 1]
                    let parts = deviceLine.components(separatedBy: " ")
                    if parts.count >= 2 {
                        return parts.last?.trimmingCharacters(in: .whitespaces)
                    }
                }
            }
        }
        return nil
    }
}

// MARK: - Private WiFi Address

public struct PrivateWiFiAddressCheck: SecurityCheck {
    public let id = "private_wifi_address"
    public let category = RiskScore.Category.firewallNetwork

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let hwResult = await runner.run(
            executable: "/usr/sbin/networksetup",
            arguments: ["-listallhardwareports"],
            timeout: 5.0
        )

        guard let iface = extractWiFiInterface(from: hwResult.stdout) else {
            return []  // No WiFi, skip
        }

        let result = await runner.run(
            executable: "/usr/sbin/ipconfig",
            arguments: ["getsummary", iface],
            timeout: 5.0
        )

        for line in result.stdout.components(separatedBy: "\n") {
            if line.contains("Private MAC") {
                let value = line.components(separatedBy: " : ").last?
                    .trimmingCharacters(in: .whitespaces) ?? ""
                if value.contains("Yes") || value.contains("1") {
                    return [Finding(
                        id: id, check: "Private WiFi Address", category: category,
                        status: .pass, severity: .info, detail: "enabled (MAC randomization)"
                    )]
                } else {
                    return [Finding(
                        id: id, check: "Private WiFi Address", category: category,
                        status: .warn, severity: .low,
                        detail: "disabled (real MAC exposed)",
                        remediation: "Enable in WiFi network settings > Private Wi-Fi Address"
                    )]
                }
            }
        }

        return [Finding(
            id: id, check: "Private WiFi Address", category: category,
            status: .inconclusive, severity: .low,
            detail: "Could not determine private address status"
        )]
    }

    private func extractWiFiInterface(from output: String) -> String? {
        let lines = output.components(separatedBy: "\n")
        for (i, line) in lines.enumerated() {
            if line.contains("Wi-Fi") || line.contains("AirPort") {
                if i + 1 < lines.count {
                    return lines[i + 1].components(separatedBy: " ").last?
                        .trimmingCharacters(in: .whitespaces)
                }
            }
        }
        return nil
    }
}

// MARK: - DNS Check

public struct DNSCheck: SecurityCheck {
    public let id = "dns"
    public let category = RiskScore.Category.firewallNetwork

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/sbin/networksetup",
            arguments: ["-getdnsservers", "Wi-Fi"],
            timeout: 5.0
        )

        let output = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if output.contains("any DNS") || output.isEmpty {
            return [Finding(
                id: id, check: "DNS Servers", category: category,
                status: .info, severity: .low,
                detail: "ISP default (your ISP sees every domain you visit)",
                remediation: "Set custom DNS: networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112"
            )]
        }

        let servers = output.components(separatedBy: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .joined(separator: ", ")

        return [Finding(
            id: id, check: "DNS Servers", category: category,
            status: .info, severity: .info,
            detail: Sanitizer.redactIPv4(servers)
        )]
    }
}

// MARK: - ARP Spoofing Detection

public struct ARPSpoofingCheck: SecurityCheck {
    public let id = "arp_spoofing"
    public let category = RiskScore.Category.firewallNetwork

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let result = await runner.run(
            executable: "/usr/sbin/arp",
            arguments: ["-a"],
            timeout: 5.0
        )

        guard result.succeeded else {
            return [Finding(
                id: id, check: "ARP Table", category: category,
                status: .inconclusive, severity: .medium,
                detail: "Could not read ARP table"
            )]
        }

        // Extract MAC addresses and check for duplicates
        var macCounts: [String: Int] = [:]
        for line in result.stdout.components(separatedBy: "\n") {
            let parts = line.components(separatedBy: " ")
            // arp -a format: hostname (ip) at mac on iface ...
            if parts.count >= 4 {
                let mac = parts[3].lowercased()
                if mac != "(incomplete)" && mac != "ff:ff:ff:ff:ff:ff" && mac.contains(":") {
                    macCounts[mac, default: 0] += 1
                }
            }
        }

        let duplicates = macCounts.filter { $0.value > 1 }
        if duplicates.isEmpty {
            return [Finding(
                id: id, check: "ARP Table", category: category,
                status: .pass, severity: .info,
                detail: "No duplicate MAC addresses (no obvious ARP spoofing)"
            )]
        }

        return [Finding(
            id: id, check: "ARP Table", category: category,
            status: .fail, severity: .high,
            detail: "DUPLICATE MAC addresses detected (possible ARP spoofing/MitM): \(duplicates.count) duplicate(s)",
            remediation: "Investigate network for potential man-in-the-middle attack"
        )]
    }
}
