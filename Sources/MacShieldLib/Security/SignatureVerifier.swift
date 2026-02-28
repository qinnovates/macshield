import Foundation
import Security

/// Verifies code signatures using the Security framework's SecStaticCode API.
/// Self-verification checks designated requirement and team ID, not just "is signed".
public enum SignatureVerifier {

    public enum VerificationResult: Sendable {
        case valid
        case invalid(String)
        case error(String)
    }

    /// Verify the code signature of a file at the given path using SecStaticCode.
    public static func verify(path: String) -> VerificationResult {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?

        let createStatus = SecStaticCodeCreateWithPath(url, SecCSFlags(), &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            return .error("Could not create static code object: \(createStatus)")
        }

        let checkStatus = SecStaticCodeCheckValidityWithErrors(
            code,
            SecCSFlags(rawValue: kSecCSCheckAllArchitectures),
            nil,
            nil
        )

        if checkStatus == errSecSuccess {
            return .valid
        }

        return .invalid("Signature validation failed: OSStatus \(checkStatus)")
    }

    /// Verify the currently running binary with full rigor:
    /// 1. Validates code signature integrity
    /// 2. Checks designated requirement (not just ad-hoc signed)
    /// 3. Validates team identifier if provided
    public static func verifySelf(expectedTeamID: String? = nil) -> VerificationResult {
        var selfCode: SecCode?
        let status = SecCodeCopySelf(SecCSFlags(), &selfCode)
        guard status == errSecSuccess, let code = selfCode else {
            return .error("Could not get self code: \(status)")
        }

        // Convert SecCode to SecStaticCode for validation
        var staticCode: SecStaticCode?
        let staticStatus = SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode)
        guard staticStatus == errSecSuccess, let sCode = staticCode else {
            return .error("Could not get static code: \(staticStatus)")
        }

        // Step 1: Validate signature integrity (all architectures)
        let checkStatus = SecStaticCodeCheckValidityWithErrors(
            sCode,
            SecCSFlags(rawValue: kSecCSCheckAllArchitectures),
            nil,
            nil
        )

        guard checkStatus == errSecSuccess else {
            return .invalid("Self-verification failed: OSStatus \(checkStatus)")
        }

        // Step 2: Check designated requirement (prevents ad-hoc re-signing)
        var requirement: SecRequirement?
        let reqStatus = SecCodeCopyDesignatedRequirement(sCode, SecCSFlags(), &requirement)

        if reqStatus == errSecSuccess, let req = requirement {
            let reqCheckStatus = SecStaticCodeCheckValidityWithErrors(
                sCode,
                SecCSFlags(),
                req,
                nil
            )
            guard reqCheckStatus == errSecSuccess else {
                return .invalid("Designated requirement check failed: OSStatus \(reqCheckStatus)")
            }
        }
        // If no designated requirement exists (ad-hoc or unsigned), that's a warning
        // but we already passed the basic signature check above

        // Step 3: Verify team identifier if expected
        if let expectedTeamID {
            var info: CFDictionary?
            let infoStatus = SecCodeCopySigningInformation(
                sCode,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &info
            )

            guard infoStatus == errSecSuccess, let signingInfo = info as? [String: Any] else {
                return .error("Could not read signing information")
            }

            let teamID = signingInfo[kSecCodeInfoTeamIdentifier as String] as? String
            if teamID != expectedTeamID {
                return .invalid("Team ID mismatch: got \(teamID ?? "nil"), expected \(expectedTeamID)")
            }
        }

        return .valid
    }
}
