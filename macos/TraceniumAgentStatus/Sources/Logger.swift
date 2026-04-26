import Foundation

final class Logger {
    static let shared = Logger()

    private let logURL: URL
    private let queue = DispatchQueue(label: "com.certusws.tracenium.agentstatus.logger")
    private let isoFormatter: ISO8601DateFormatter

    private init() {
        let logsDir = (NSHomeDirectory() as NSString).appendingPathComponent("Library/Logs")
        let traceniumDir = (logsDir as NSString).appendingPathComponent("Tracenium")
        let filePath = (traceniumDir as NSString).appendingPathComponent("TraceniumAgentStatus.log")
        self.logURL = URL(fileURLWithPath: filePath)
        self.isoFormatter = ISO8601DateFormatter()
        self.isoFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        queue.async {
            try? FileManager.default.createDirectory(
                at: self.logURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
        }
    }

    func info(_ message: String) {
        write(level: "INFO", message: message)
    }

    func warn(_ message: String) {
        write(level: "WARN", message: message)
    }

    func error(_ message: String) {
        write(level: "ERROR", message: message)
    }

    private func write(level: String, message: String) {
        let line = "[\(isoFormatter.string(from: Date()))] [\(level)] \(message)\n"
        queue.async {
            do {
                try FileManager.default.createDirectory(
                    at: self.logURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )

                if FileManager.default.fileExists(atPath: self.logURL.path) {
                    let handle = try FileHandle(forWritingTo: self.logURL)
                    defer { try? handle.close() }
                    try handle.seekToEnd()
                    if let data = line.data(using: .utf8) {
                        try handle.write(contentsOf: data)
                    }
                } else {
                    try line.write(to: self.logURL, atomically: true, encoding: .utf8)
                }
            } catch {
                // Keep logger isolated. Status app must not crash on log IO failure.
            }
        }
    }
}
