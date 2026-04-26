import Foundation

final class StatusSnapshotReader {
    private let decoder: JSONDecoder
    let snapshotPath: String
    let candidatePaths: [String]
    private var lastIssueKey: String?
    private var lastSuccessPath: String?

    init(snapshotPath: String? = nil) {
        let candidates = AgentStatusPaths.trayStatusCandidates()
        self.candidatePaths = snapshotPath.map { [$0] } ?? candidates
        self.snapshotPath = self.candidatePaths.first ?? AgentStatusPaths.trayStatusCandidates().first ?? ""
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
    }

    func read() -> TrayStatus? {
        for path in candidatePaths {
            let url = URL(fileURLWithPath: path)
            guard FileManager.default.fileExists(atPath: url.path) else {
                continue
            }

            do {
                let data = try Data(contentsOf: url)
                let decoded = try decoder.decode(TrayStatus.self, from: data)
                if lastSuccessPath != path {
                    Logger.shared.info("Loaded tray status snapshot from \(path)")
                    lastSuccessPath = path
                }
                lastIssueKey = nil
                return decoded
            } catch {
                let issueKey = "decode:\(path):\(error.localizedDescription)"
                if lastIssueKey != issueKey {
                    Logger.shared.warn("Failed to decode tray status snapshot at \(path): \(error.localizedDescription)")
                    lastIssueKey = issueKey
                }
                continue
            }
        }

        let missingKey = "missing:\(candidatePaths.joined(separator: "|"))"
        if lastIssueKey != missingKey {
            Logger.shared.warn("No tray status snapshot found. Checked: \(candidatePaths.joined(separator: ", "))")
            lastIssueKey = missingKey
        }
        return nil
    }
}
