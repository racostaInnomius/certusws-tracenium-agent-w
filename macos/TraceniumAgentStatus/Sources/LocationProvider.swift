import Foundation
import CoreLocation

/// Publishes the Mac's position for the agent daemon to pick up.
///
/// Why this lives in the menubar app and not in the daemon
/// ----------------------------------------------------------------------------
/// CoreLocation is gated by TCC, and TCC grants are made to a signed .app
/// bundle acting in a logged-in user's session. The Node daemon is a root
/// LaunchDaemon in session 0: it has no bundle identity to grant, and no user
/// session to prompt in, so it can never obtain a location no matter how it
/// asks. This app is the only component of the agent that satisfies both
/// conditions — it is a signed bundle and it already runs as a LaunchAgent in
/// the console user's session.
///
/// So the split is: the daemon decides WHETHER to collect (it owns the policy)
/// and this app performs the collection, handing the result back through a file
/// the daemon reads on its next inventory tick.
///
/// The user still sees the standard macOS prompt the first time, and can revoke
/// it at any point in System Settings → Privacy & Security → Location Services.
/// Revoking is a supported outcome: the file simply stops being refreshed and
/// the daemon starts ignoring it once it goes stale.
final class LocationProvider: NSObject, CLLocationManagerDelegate {

    /// How often a fresh fix is requested.
    ///
    /// Not continuous updates: those keep the Wi-Fi scanning machinery warm and
    /// cost battery on laptops, for a datum that changes when someone carries
    /// the machine to another building — not second to second. The daemon's
    /// own staleness window is wider than this, so a missed cycle is harmless.
    private static let refreshInterval: TimeInterval = 15 * 60

    private let manager = CLLocationManager()
    private var timer: Timer?
    private var enabled = false

    override init() {
        super.init()
        manager.delegate = self
        // Roughly "which building", which is all an inventory system needs and
        // markedly cheaper than the best-accuracy modes.
        manager.desiredAccuracy = kCLLocationAccuracyHundredMeters
    }

    /// Called on every snapshot refresh with the daemon's current policy.
    ///
    /// Idempotent: repeated calls with an unchanged value do nothing, so it is
    /// safe to drive straight from the 5-second status poll.
    func apply(enabled newValue: Bool) {
        guard newValue != enabled else { return }
        enabled = newValue

        if newValue {
            Logger.shared.info("Location collection enabled by policy")
            requestAuthorizationIfNeeded()
            startTimer()
            requestFix()
        } else {
            Logger.shared.info("Location collection disabled by policy")
            stopTimer()
            // Remove rather than leave behind: a policy that was switched off
            // must not keep a readable coordinate sitting on disk.
            LocationSink.clear()
        }
    }

    func stop() {
        stopTimer()
    }

    // MARK: - Internals

    private func startTimer() {
        stopTimer()
        timer = Timer.scheduledTimer(withTimeInterval: Self.refreshInterval, repeats: true) { [weak self] _ in
            self?.requestFix()
        }
    }

    private func stopTimer() {
        timer?.invalidate()
        timer = nil
    }

    private func requestAuthorizationIfNeeded() {
        if manager.authorizationStatus == .notDetermined {
            manager.requestWhenInUseAuthorization()
        }
    }

    private func requestFix() {
        guard enabled else { return }
        switch manager.authorizationStatus {
        case .authorized, .authorizedAlways:
            // requestLocation delivers exactly one fix and powers the radio
            // back down, which is the whole point of not using startUpdating.
            manager.requestLocation()
        case .notDetermined:
            requestAuthorizationIfNeeded()
        default:
            // Denied or restricted. Nothing to do and nothing to log every
            // cycle — the daemon will see the file go stale and stop using it.
            break
        }
    }

    // MARK: - CLLocationManagerDelegate

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard enabled, let location = locations.last else { return }
        LocationSink.write(location)
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        // Transient failures are normal indoors and on wake. Deliberately not
        // clearing the last fix here: one failed attempt does not mean the
        // machine moved, and the daemon's staleness window already bounds how
        // long an old fix stays usable.
        Logger.shared.info("Location request failed: \(error.localizedDescription)")
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        switch manager.authorizationStatus {
        case .authorized, .authorizedAlways:
            Logger.shared.info("Location authorization granted")
            requestFix()
        case .denied, .restricted:
            Logger.shared.info("Location authorization denied by the user")
            // The user said no. Drop anything we published earlier rather than
            // letting the daemon keep reading a fix they have since revoked.
            LocationSink.clear()
        default:
            break
        }
    }
}

/// The handoff file: written here in the user session, read by the root daemon.
///
/// It lives in the console user's own Application Support directory rather than
/// a shared world-writable location. Root can read any home directory, so the
/// daemon has no trouble — but another unprivileged user on the machine cannot
/// plant a fake position, because they would have to write into someone else's
/// home to do it.
enum LocationSink {
    static var fileURL: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Tracenium", isDirectory: true)
        return base.appendingPathComponent("location.json")
    }

    static func write(_ location: CLLocation) {
        let accuracy = location.horizontalAccuracy
        let payload: [String: Any] = [
            "lat": location.coordinate.latitude,
            "lon": location.coordinate.longitude,
            // CoreLocation signals "invalid" with a negative accuracy; passing
            // that through would render as a nonsense radius on the map.
            "accuracyM": accuracy >= 0 ? accuracy : NSNull(),
            "collectedAtUtc": ISO8601DateFormatter().string(from: location.timestamp),
        ]

        do {
            let dir = fileURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let data = try JSONSerialization.data(withJSONObject: payload)
            try data.write(to: fileURL, options: .atomic)
            // Readable by root (which is all we need) and by the owner. Not
            // world-readable: it is the user's own whereabouts.
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        } catch {
            Logger.shared.info("Failed to publish location: \(error.localizedDescription)")
        }
    }

    static func clear() {
        try? FileManager.default.removeItem(at: fileURL)
    }
}
