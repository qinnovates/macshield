import Foundation

// MARK: - SSH Directory Permissions

public struct SSHDirectoryCheck: SecurityCheck {
    public let id = "ssh_directory"
    public let category = RiskScore.Category.fileHygiene

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let sshDir = NSHomeDirectory() + "/.ssh"
        let fm = FileManager.default

        guard fm.fileExists(atPath: sshDir) else {
            return [Finding(
                id: id, check: ".ssh Directory", category: category,
                status: .info, severity: .info, detail: "not found"
            )]
        }

        let result = await runner.run(
            executable: "/usr/bin/stat",
            arguments: ["-f", "%Lp", sshDir],
            timeout: 5.0
        )

        let perms = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if perms == "700" {
            return [Finding(
                id: id, check: ".ssh Directory", category: category,
                status: .pass, severity: .info, detail: "permissions 700"
            )]
        }

        return [Finding(
            id: id, check: ".ssh Directory", category: category,
            status: .warn, severity: .medium,
            detail: "permissions \(perms) (should be 700)",
            remediation: "chmod 700 ~/.ssh"
        )]
    }
}

// MARK: - SSH Key Permissions

public struct SSHKeyPermissionsCheck: SecurityCheck {
    public let id = "ssh_key_permissions"
    public let category = RiskScore.Category.fileHygiene

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let sshDir = NSHomeDirectory() + "/.ssh"
        let fm = FileManager.default

        guard fm.fileExists(atPath: sshDir) else { return [] }

        guard let contents = try? fm.contentsOfDirectory(atPath: sshDir) else { return [] }

        let privateKeys = contents.filter { name in
            name.hasPrefix("id_") && !name.hasSuffix(".pub")
        }

        guard !privateKeys.isEmpty else { return [] }

        var badKeys: [String] = []
        for key in privateKeys {
            let keyPath = sshDir + "/" + key
            let result = await runner.run(
                executable: "/usr/bin/stat",
                arguments: ["-f", "%Lp", keyPath],
                timeout: 5.0
            )
            let perms = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if perms != "600" && perms != "400" {
                badKeys.append("\(key) (\(perms))")
            }
        }

        if badKeys.isEmpty {
            return [Finding(
                id: id, check: "SSH Key Permissions", category: category,
                status: .pass, severity: .info,
                detail: "all \(privateKeys.count) private key(s) have correct permissions"
            )]
        }

        return [Finding(
            id: id, check: "SSH Key Permissions", category: category,
            status: .warn, severity: .medium,
            detail: "insecure permissions: \(badKeys.joined(separator: ", "))",
            remediation: "chmod 600 ~/.ssh/id_*"
        )]
    }
}

// MARK: - .env Files

public struct EnvFilesCheck: SecurityCheck {
    public let id = "env_files"
    public let category = RiskScore.Category.fileHygiene

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let home = NSHomeDirectory()
        let searchDirs = [
            home,
            home + "/Desktop",
            home + "/Documents",
            home + "/Projects",
            home + "/Code",
            home + "/dev",
            home + "/src",
        ]

        var envCount = 0
        let fm = FileManager.default

        for dir in searchDirs {
            guard fm.fileExists(atPath: dir) else { continue }
            // Check for .env directly in the directory
            if fm.fileExists(atPath: dir + "/.env") {
                envCount += 1
            }
            // Check one level deep
            if let contents = try? fm.contentsOfDirectory(atPath: dir) {
                for item in contents {
                    let subPath = dir + "/" + item + "/.env"
                    if fm.fileExists(atPath: subPath) {
                        envCount += 1
                    }
                }
            }
        }

        if envCount > 0 {
            return [Finding(
                id: id, check: ".env Files", category: category,
                status: .warn, severity: .medium,
                detail: "\(envCount) file(s) near home directory (may contain secrets)",
                remediation: "Ensure .env files are in .gitignore and contain no production secrets"
            )]
        }

        return []  // No finding if no .env files — not noteworthy
    }
}

// MARK: - Git Credentials

public struct GitCredentialsCheck: SecurityCheck {
    public let id = "git_credentials"
    public let category = RiskScore.Category.fileHygiene

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let path = NSHomeDirectory() + "/.git-credentials"
        if FileManager.default.fileExists(atPath: path) {
            return [Finding(
                id: id, check: ".git-credentials", category: category,
                status: .warn, severity: .medium,
                detail: "plaintext credentials file exists",
                remediation: "Use git credential-osxkeychain instead"
            )]
        }
        return []
    }
}

// MARK: - .netrc

public struct NetrcCheck: SecurityCheck {
    public let id = "netrc"
    public let category = RiskScore.Category.fileHygiene

    public init() {}

    public func run(runner: ProcessRunning, capabilities: SystemCapabilities) async -> [Finding] {
        let path = NSHomeDirectory() + "/.netrc"
        guard FileManager.default.fileExists(atPath: path) else { return [] }

        let result = await runner.run(
            executable: "/usr/bin/stat",
            arguments: ["-f", "%Lp", path],
            timeout: 5.0
        )

        let perms = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if perms == "600" || perms == "400" {
            return [Finding(
                id: id, check: ".netrc", category: category,
                status: .info, severity: .info,
                detail: "exists (permissions \(perms))"
            )]
        }

        return [Finding(
            id: id, check: ".netrc", category: category,
            status: .warn, severity: .medium,
            detail: "permissions \(perms) (should be 600, contains credentials)",
            remediation: "chmod 600 ~/.netrc"
        )]
    }
}
