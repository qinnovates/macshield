import Foundation
import SQLite3

/// Reads TCC.db using the sqlite3 C API with parameterized queries only.
/// No string interpolation of service names into SQL.
/// Queries both user-level and system-level TCC databases.
public enum TCCReader {

    /// SQLITE_TRANSIENT tells SQLite to make its own copy of the string.
    private static let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    /// Query apps granted a specific TCC permission from the user database.
    /// Returns nil if database is unreadable (no FDA).
    /// Returns empty array if no apps have the permission.
    public static func queryGrantedApps(service: String) -> [String]? {
        let userDB = NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"
        let systemDB = "/Library/Application Support/com.apple.TCC/TCC.db"

        var allApps: [String] = []
        var anySuccess = false

        // Query user-level TCC database
        if let userApps = queryDatabase(path: userDB, service: service) {
            allApps.append(contentsOf: userApps)
            anySuccess = true
        }

        // Query system-level TCC database (may not be readable without root)
        if let systemApps = queryDatabase(path: systemDB, service: service) {
            allApps.append(contentsOf: systemApps)
            anySuccess = true
        }

        return anySuccess ? allApps : nil
    }

    /// Query a specific TCC database file.
    private static func queryDatabase(path: String, service: String) -> [String]? {
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            sqlite3_close(db)
            return nil
        }
        defer { sqlite3_close(db) }

        // auth_value = 2 means "allowed" in macOS 14+
        // On older versions this was auth_value = 1, but we target macOS 14+ only
        let sql = "SELECT client FROM access WHERE service = ?1 AND auth_value = 2;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            sqlite3_finalize(stmt)
            return nil
        }
        defer { sqlite3_finalize(stmt) }

        guard sqlite3_bind_text(stmt, 1, service, -1, SQLITE_TRANSIENT) == SQLITE_OK else {
            return nil
        }

        var apps: [String] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let cStr = sqlite3_column_text(stmt, 0) {
                apps.append(String(cString: cStr))
            }
        }

        return apps
    }
}
