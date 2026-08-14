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
                // localizedDescription collapses every DecodingError into
                // "isn't in the correct format", which names nothing. The
                // coding path is the only thing that identifies the offending
                // field, and without it a broken snapshot is undiagnosable
                // from a log.
                let detail = StatusSnapshotReader.describe(error)
                let issueKey = "decode:\(path):\(detail)"
                if lastIssueKey != issueKey {
                    Logger.shared.warn("Failed to decode tray status snapshot at \(path): \(detail)")
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

    /// Turn a DecodingError into something that names the field.
    ///
    /// localizedDescription collapses every DecodingError into "isn't in the
    /// correct format", which identifies nothing. The coding path is the only
    /// thing that says WHICH field broke, and without it a snapshot the daemon
    /// changed shape on is undiagnosable from a log — which is exactly how this
    /// went unnoticed while the app retried every 5 seconds for days.
    private static func describe(_ error: Error) -> String {
        guard let decoding = error as? DecodingError else { return error.localizedDescription }
        func path(_ context: DecodingError.Context) -> String {
            let keys = context.codingPath.map { $0.stringValue }
            return keys.isEmpty ? "<root>" : keys.joined(separator: ".")
        }
        switch decoding {
        case .keyNotFound(let key, let context):
            return "missing key '\(key.stringValue)' at \(path(context))"
        case .typeMismatch(let type, let context):
            return "type mismatch, expected \(type) at \(path(context))"
        case .valueNotFound(let type, let context):
            return "null where \(type) required at \(path(context))"
        case .dataCorrupted(let context):
            return "corrupted at \(path(context)): \(context.debugDescription)"
        @unknown default:
            return error.localizedDescription
        }
    }
}
