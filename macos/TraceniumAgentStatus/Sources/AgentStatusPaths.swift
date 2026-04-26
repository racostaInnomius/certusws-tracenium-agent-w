import Foundation

enum AgentStatusPaths {
    static let agentDataDirEnv = "TRACENIUM_AGENT_DATA_DIR"
    static let trayStatusPathEnv = "TRACENIUM_TRAY_STATUS_PATH"
    static let defaultAgentDataDir = "/Library/Application Support/Tracenium/Agent"
    static let statusDirectoryName = "status"
    static let trayStatusFileName = "tray-status.json"

    static func trayStatusCandidates(environment: [String: String] = ProcessInfo.processInfo.environment) -> [String] {
        var candidates: [String] = []

        if let explicitPath = environment[trayStatusPathEnv], !explicitPath.isEmpty {
            candidates.append(explicitPath)
        }

        let baseDir = environment[agentDataDirEnv].flatMap { $0.isEmpty ? nil : $0 } ?? defaultAgentDataDir
        candidates.append((baseDir as NSString).appendingPathComponent(statusDirectoryName).appending("/\(trayStatusFileName)"))

        // Legacy fallback for older dev layouts; production should not rely on this.
        let legacyHome = (NSHomeDirectory() as NSString)
            .appendingPathComponent(".tracenium/agent")
            .appending("/\(statusDirectoryName)/\(trayStatusFileName)")
        candidates.append(legacyHome)

        var seen = Set<String>()
        return candidates.filter { seen.insert($0).inserted }
    }
}
