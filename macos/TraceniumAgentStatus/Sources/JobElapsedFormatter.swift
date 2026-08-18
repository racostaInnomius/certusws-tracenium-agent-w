import Foundation

/// Formats the time since a job started as a short, human string
/// ("just started", "12s", "2m 14s", "1h 03m"). Pure and side-effect
/// free — no AppKit dependency — so it's unit-testable in isolation.
/// This is the honest substitute for a completion percentage: the
/// agent has no step/progress signal to report for a running job (see
/// TrayCurrentJob), so elapsed time is the only real number the tray
/// apps can show.
enum JobElapsedFormatter {
    static func format(startedAtUtc: Date?, now: Date = Date()) -> String {
        guard let startedAtUtc else { return "—" }
        let seconds = max(0, Int(now.timeIntervalSince(startedAtUtc)))

        if seconds < 1 {
            return "just started"
        }
        if seconds < 60 {
            return "\(seconds)s"
        }

        let minutes = seconds / 60
        let remainingSeconds = seconds % 60
        if minutes < 60 {
            return remainingSeconds > 0 ? "\(minutes)m \(remainingSeconds)s" : "\(minutes)m"
        }

        let hours = minutes / 60
        let remainingMinutes = minutes % 60
        return String(format: "%dh %02dm", hours, remainingMinutes)
    }
}
