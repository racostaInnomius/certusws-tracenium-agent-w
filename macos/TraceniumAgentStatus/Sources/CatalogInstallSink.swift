import Foundation

/// Tray -> core channel for the self-service Software Catalog tab.
///
/// This app has no control-plane credentials and no network access of
/// its own — every real capability (auth, the gRPC stream, PrivSvc)
/// lives in the root daemon. So "please install this" travels the same
/// file-mediated path LocationSink uses for the opposite direction
/// (this session -> the daemon): write a small JSON document into our
/// own Application Support directory; the daemon (running as
/// root/SYSTEM, outside this user's session) polls for it — see
/// catalog-install-request-watcher.ts on the agent side.
enum CatalogInstallSink {
    static var fileURL: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Tracenium", isDirectory: true)
        return base.appendingPathComponent("catalog-install-request.json")
    }

    /// Writes a fresh request. Overwrites any request already waiting —
    /// there is only ever one "next" self-install the daemon should act
    /// on, and the UI already disables the Install button for the
    /// duration of a pending/running job, so a genuine double-write
    /// shouldn't happen in practice.
    static func write(packageId: String) {
        let payload: [String: Any] = [
            "packageId": packageId,
            "requestedAtUtc": ISO8601DateFormatter().string(from: Date()),
        ]

        do {
            let dir = fileURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let data = try JSONSerialization.data(withJSONObject: payload)
            try data.write(to: fileURL, options: .atomic)
            // Readable by root (which is all that needs it) and the owner —
            // not world-readable, same posture as LocationSink.
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        } catch {
            Logger.shared.info("Failed to publish self-install request: \(error.localizedDescription)")
        }
    }
}
