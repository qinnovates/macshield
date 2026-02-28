import Foundation

/// Safe plist reader using PropertyListSerialization. No shell commands.
public enum PlistReader {

    public enum PlistError: Error {
        case fileNotFound(String)
        case invalidData
        case keyNotFound(String)
    }

    /// Read a plist file and return the root dictionary.
    public static func read(at path: String) throws -> [String: Any] {
        let url = URL(fileURLWithPath: path)
        guard FileManager.default.fileExists(atPath: path) else {
            throw PlistError.fileNotFound(path)
        }
        let data = try Data(contentsOf: url)
        guard let plist = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        ) as? [String: Any] else {
            throw PlistError.invalidData
        }
        return plist
    }

    /// Read a specific string value from a plist.
    public static func readString(at path: String, key: String) throws -> String {
        let dict = try read(at: path)
        guard let value = dict[key] as? String else {
            throw PlistError.keyNotFound(key)
        }
        return value
    }

    /// Read a specific boolean/integer value from a plist.
    public static func readBool(at path: String, key: String) throws -> Bool {
        let dict = try read(at: path)
        if let value = dict[key] as? Bool {
            return value
        }
        if let value = dict[key] as? Int {
            return value != 0
        }
        throw PlistError.keyNotFound(key)
    }
}
