import Foundation

enum AgentStatusPaths {
    static let agentDataDirEnv = "TRACENIUM_AGENT_DATA_DIR"
    static let trayStatusPathEnv = "TRACENIUM_TRAY_STATUS_PATH"
    static let defaultAgentDataDir = "/Library/Application Support/Tracenium/Agent"
    /// Tracenium base dir — parent of Agent/, contains status/ as
    /// sibling so the tray (running as user) can read without needing
    /// traversal perms on the Agent/ dir (which is mode 700 root-only).
    static let defaultTraceniumBaseDir = "/Library/Application Support/Tracenium"
    static let statusDirectoryName = "status"
    static let trayStatusFileName = "tray-status.json"

    static func trayStatusCandidates(environment: [String: String] = ProcessInfo.processInfo.environment) -> [String] {
        var candidates: [String] = []

        // Highest priority: explicit env var set by the LaunchAgent plist.
        if let explicitPath = environment[trayStatusPathEnv], !explicitPath.isEmpty {
            candidates.append(explicitPath)
        }

        // Production layout: status/ as sibling of Agent/, both under
        // /Library/Application Support/Tracenium/. The Agent/ dir is
        // mode 700 (root only); status/ is 755 so the user-session
        // tray can read tray-status.json (mode 644) directly.
        candidates.append("\(defaultTraceniumBaseDir)/\(statusDirectoryName)/\(trayStatusFileName)")

        // Legacy layout (status inside Agent/): supported for transition
        // builds where users may still have an old install. Won't work
        // unless the user happens to be root — but harmless to probe.
        let baseDir = environment[agentDataDirEnv].flatMap { $0.isEmpty ? nil : $0 } ?? defaultAgentDataDir
        candidates.append((baseDir as NSString).appendingPathComponent(statusDirectoryName).appending("/\(trayStatusFileName)"))

        // Dev fallback: $HOME/.tracenium/agent/status/tray-status.json.
        // Production should not rely on this.
        let legacyHome = (NSHomeDirectory() as NSString)
            .appendingPathComponent(".tracenium/agent")
            .appending("/\(statusDirectoryName)/\(trayStatusFileName)")
        candidates.append(legacyHome)

        var seen = Set<String>()
        return candidates.filter { seen.insert($0).inserted }
    }
}
