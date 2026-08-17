import Foundation
import CoreLocation
import AppKit

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

    /// Whether we already presented the permission alert in THIS launch.
    ///
    /// Asking puts the app in the foreground, and the status stays
    /// `.notDetermined` until somebody answers — so re-asking on every refresh
    /// cycle meant stealing focus from whoever was using the Mac four times an
    /// hour, indefinitely. Once per launch is the whole budget: if they ignore
    /// it, the next login asks again, and the dashboard reports
    /// `consent_required` in the meantime so an admin can see it and grant it
    /// from System Settings instead.
    private var hasPresentedPromptThisLaunch = false

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

    /// True while a click on "Allow location…" would accomplish something.
    var needsUserConsent: Bool {
        enabled && manager.authorizationStatus == .notDetermined
    }

    /// Triggered by the person clicking the button in the popover.
    ///
    /// Bypasses the once-per-launch budget on purpose: that budget exists to
    /// stop US from stealing focus unbidden. A click is the opposite situation
    /// — they asked, the app is already frontmost, and this is the one moment
    /// macOS reliably presents the alert.
    func requestConsentFromUser() {
        guard enabled else { return }
        Logger.shared.info("Location permission requested by the user from the popover")
        hasPresentedPromptThisLaunch = false
        requestAuthorizationIfNeeded()
        requestFix()
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

    /// Every authorization state that lets us actually ask for a fix.
    ///
    /// ⚠️ `requestWhenInUseAuthorization()` (the call we make below) grants
    /// `.authorizedWhenInUse` on macOS — a case that was missing from all three
    /// switches that consumed the status. The result was that granting the
    /// permission accomplished nothing: `statusName` reported "unavailable",
    /// `requestFix()` fell through to the "denied or restricted" branch and
    /// never called `requestLocation()`, and the delegate ignored the grant
    /// entirely. The published document then aged past the daemon's one-hour
    /// staleness window and the dashboard settled on `agent_not_publishing`
    /// — "the menubar app is not reporting" — for a Mac whose menubar app was
    /// running fine and whose user had said yes.
    ///
    /// Deriving all three from ONE predicate is the point: three parallel
    /// switches over the same enum is how a case goes missing from some of
    /// them but not others.
    private var isAuthorized: Bool {
        switch manager.authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse: return true
        default: return false
        }
    }

    /// The OS status, as a string the daemon and the dashboard can act on.
    ///
    /// Mirrors GeoStatus on the agent side. `notDetermined` is its own answer
    /// and NOT "unavailable": nobody has been asked yet, so waiting will never
    /// help — somebody has to grant it.
    private var statusName: String {
        if isAuthorized { return "ok" }
        switch manager.authorizationStatus {
        case .denied, .restricted: return "denied"
        case .notDetermined: return "consent_required"
        // Unreachable — `isAuthorized` returned above for both. Listed anyway
        // so the switch stays exhaustive: that is what makes the compiler,
        // rather than a field report, catch the next case we forget.
        case .authorizedAlways, .authorizedWhenInUse: return "ok"
        @unknown default: return "unavailable"
        }
    }

    private func requestAuthorizationIfNeeded() {
        guard manager.authorizationStatus == .notDetermined else { return }
        guard !hasPresentedPromptThisLaunch else { return }
        hasPresentedPromptThisLaunch = true

        // ⚠️ This app is LSUIElement — a menubar agent with no windows. macOS
        // will register it as a location client (it shows up in locationd's
        // clients.plist) but will NOT reliably present the permission alert to
        // a process that is not foreground. That is exactly what happened in
        // the field: every launch logged "enabled by policy", the client was
        // Registered, no Authorized key was ever written, and the status sat
        // at notDetermined forever while we silently re-asked every 15 minutes.
        //
        // Becoming a regular app for the duration of the ask puts us in the
        // foreground so the alert can appear, then we drop straight back to
        // accessory. The user sees a Dock icon for a moment — a fair price for
        // a consent prompt that otherwise never shows.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        manager.requestWhenInUseAuthorization()

        DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
            NSApp.setActivationPolicy(.accessory)
        }
    }

    private func requestFix() {
        guard enabled else { return }

        // Publish the reason on EVERY cycle, not only on success. The previous
        // version wrote nothing at all unless a fix arrived, so the daemon saw
        // an absent file and reported "no fix yet" — telling the operator to
        // wait for something that was never going to happen.
        LocationSink.writeStatus(statusName)

        if isAuthorized {
            // Heartbeat. Granted-but-no-fix-yet used to leave NO file at all,
            // which the daemon could not tell apart from "this app is dead" —
            // both looked like an absent file. Writing a reason here makes the
            // difference visible, and it never clobbers a fix we already have.
            LocationSink.writeStatusIfNoFix("unavailable")
            // requestLocation delivers exactly one fix and powers the radio
            // back down, which is the whole point of not using startUpdating.
            manager.requestLocation()
            return
        }

        switch manager.authorizationStatus {
        case .notDetermined:
            if hasPresentedPromptThisLaunch {
                // Already asked this launch and nobody answered. Say so once
                // per cycle in the log, but do NOT drag the app back to the
                // foreground — the dashboard already carries the reason.
                Logger.shared.info("Location permission still unanswered; not re-prompting until next launch")
            } else {
                Logger.shared.info("Location permission not yet answered; presenting the prompt")
                requestAuthorizationIfNeeded()
            }
        default:
            Logger.shared.info("Location permission is denied or restricted; not asking again")
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
        if isAuthorized {
            Logger.shared.info("Location authorization granted")
            requestFix()
            return
        }

        switch manager.authorizationStatus {
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
            "status": "ok",
        ]

        write(payload: payload)
    }

    private static func write(payload: [String: Any]) {
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

    /// Publish WHY there is no position.
    ///
    /// Same file as a real fix, minus the coordinates: the daemon parses one
    /// document either way, and a reason with no lat/lon can never be mistaken
    /// for a position. Stamped so the daemon's staleness window applies to a
    /// reason just as it does to a fix — a status from a process that died
    /// hours ago is not current either.
    static func writeStatus(_ status: String) {
        guard status != "ok" else { return }
        write(payload: [
            "status": status,
            "collectedAtUtc": ISO8601DateFormatter().string(from: Date()),
        ])
    }

    /// Publish a reason ONLY when there is no usable fix on disk already.
    ///
    /// A device that got a fix and then stops producing new ones keeps showing
    /// the last known position until the daemon's staleness window retires it.
    /// Overwriting it with a status would blank the map 45 minutes early for a
    /// laptop that is simply indoors.
    static func writeStatusIfNoFix(_ status: String) {
        if let data = try? Data(contentsOf: fileURL),
           let doc = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           doc["lat"] != nil, doc["lon"] != nil {
            return
        }
        writeStatus(status)
    }

    static func clear() {
        try? FileManager.default.removeItem(at: fileURL)
    }
}
