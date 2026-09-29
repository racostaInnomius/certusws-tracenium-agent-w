import XCTest
@testable import TraceniumAgentStatus

/// Recordatorio de instalar una actualización de macOS: el presentador de la
/// acción para el usuario `os.update` (ADR-0036 D1; nació como job
/// os_update_nudge, 29-sep). En Apple silicon el agente no puede instalarla:
/// pide la contraseña de un propietario (job e4689371). Lo que se fija aquí:
/// que el bloque se lea tal como lo escribe el agente, el ritmo común, la
/// agrupación, la telemetría y que no se enseñe de más.
final class OsUpdateReminderTests: XCTestCase {
    private func decode(_ block: String) throws -> TrayStatus {
        let decoder = TrayJSON.makeDecoder()
        let json = """
        { "agentVersion": "1.1.86", "hostname": "JPR-MacBookPro", "userActions": \(block) }
        """
        return try decoder.decode(TrayStatus.self, from: Data(json.utf8))
    }

    private let deadline = ISO8601DateFormatter().date(from: "2026-10-06T23:00:00Z")!
    private let expires = ISO8601DateFormatter().date(from: "2026-11-05T23:00:00Z")!

    private func update(_ id: String, label: String, deadline: Date? = nil) -> TrayUserAction {
        TrayUserAction(actionId: id, kind: "os.update", title: label.components(separatedBy: "-").first ?? label,
                       deadlineUtc: deadline ?? self.deadline, expiresUtc: expires, params: ["label": label])
    }

    // MARK: Decodificación

    func testDecodesTheBlockAsTheAgentWritesIt_withMilliseconds() throws {
        // `toISOString()` → milisegundos, que `.iso8601` rechaza. Con el `try?`
        // del resto del modelo sería una acción perdida en silencio.
        let s = try decode(#"[{ "actionId": "act-00000001", "kind": "os.update", "title": "macOS 27.0.1", "deadlineUtc": "2026-10-06T23:00:00.000Z", "expiresUtc": "2026-11-05T23:00:00.000Z", "params": { "label": "macOS 27.0.1-26A434", "title": "macOS 27.0.1" } }]"#)
        let a = try XCTUnwrap(s.userActions.first)
        XCTAssertEqual(a.actionId, "act-00000001")
        XCTAssertEqual(a.title, "macOS 27.0.1")
        XCTAssertEqual(a.params["label"], "macOS 27.0.1-26A434")
        XCTAssertEqual(a.deadlineUtc, deadline)
        XCTAssertEqual(a.expiresUtc, expires)
    }

    func testTitleFallsBackToParams() throws {
        let s = try decode(#"[{ "actionId": "act-00000001", "kind": "os.update", "expiresUtc": "2026-11-05T23:00:00Z", "deadlineUtc": "2026-10-06T23:00:00Z", "params": { "label": "macOS 27.0.1-26A434" } }]"#)
        XCTAssertEqual(s.userActions.first?.title, "macOS 27.0.1-26A434")
    }

    func testABrokenOrUnknownActionCostsOnlyThatAction() throws {
        let s = try decode(#"""
        [
          { "actionId": "act-bad00001", "kind": "os.update", "expiresUtc": "mañana" },
          { "actionId": "act-unk00001", "kind": "profile.install", "expiresUtc": "2026-11-05T23:00:00Z" },
          { "actionId": "act-ok000001", "kind": "os.update", "expiresUtc": "2026-11-05T23:00:00Z", "deadlineUtc": "2026-10-06T23:00:00Z", "params": { "label": "macOS 27.0.1-26A434" } }
        ]
        """#)
        XCTAssertEqual(s.userActions.map { $0.actionId }, ["act-ok000001"])
        XCTAssertEqual(s.hostname, "JPR-MacBookPro")
    }

    func testABrokenBlockCostsOnlyTheBlock() throws {
        let s = try decode(#"{ "no": "es un array" }"#)
        XCTAssertEqual(s.userActions, [])
        XCTAssertEqual(s.hostname, "JPR-MacBookPro")
    }

    // MARK: Agrupación

    func testAllOsUpdatesInOneWindow_mostUrgentFirst_expiredLeftOut() {
        let now = deadline.addingTimeInterval(-7 * UserActionCadence.day)
        let later = update("act-later001", label: "macOS 27.0.1-26A434")
        let sooner = update("act-sooner01", label: "macOS Tahoe 26.7.1-25G241", deadline: deadline.addingTimeInterval(-4 * UserActionCadence.day))
        var gone = update("act-gone0001", label: "macOS 26.0-25A1")
        gone.expiresUtc = now.addingTimeInterval(-60)
        let r = TrayOsUpdateRequest.from([later, gone, sooner], now: now)
        XCTAssertEqual(r?.label, "macOS Tahoe 26.7.1-25G241")
        XCTAssertEqual(r?.pendingCount, 2)
        XCTAssertEqual(r?.actionIds, ["act-sooner01", "act-later001"])
        XCTAssertNil(TrayOsUpdateRequest.from([gone], now: now))
    }

    // MARK: Ritmo

    func testCadence() {
        let day = UserActionCadence.day
        XCTAssertEqual(UserActionCadence.interval(deadline: deadline, now: deadline.addingTimeInterval(-7 * day)), day)
        XCTAssertEqual(UserActionCadence.interval(deadline: deadline, now: deadline.addingTimeInterval(-2 * day)), 4 * 3600)
        XCTAssertEqual(UserActionCadence.interval(deadline: deadline, now: deadline.addingTimeInterval(60)), 3600)
        // Sin fecha: una vez al día.
        XCTAssertEqual(UserActionCadence.interval(deadline: nil, now: deadline), day)
    }

    func testIsDue() {
        let now = deadline.addingTimeInterval(-7 * UserActionCadence.day)
        XCTAssertTrue(UserActionCadence.isDue(lastShown: nil, deadline: deadline, now: now))
        XCTAssertFalse(UserActionCadence.isDue(lastShown: now.addingTimeInterval(-3600), deadline: deadline, now: now))
        XCTAssertTrue(UserActionCadence.isDue(lastShown: now.addingTimeInterval(-25 * 3600), deadline: deadline, now: now))
        // Vencida: cada hora.
        let late = deadline.addingTimeInterval(7200)
        XCTAssertTrue(UserActionCadence.isDue(lastShown: late.addingTimeInterval(-3601), deadline: deadline, now: late))
    }

    // MARK: Cuándo se enseña

    private func freshDefaults() -> UserDefaults {
        let name = "OsUpdateReminderTests.\(UUID().uuidString)"
        let d = UserDefaults(suiteName: name)!
        d.removePersistentDomain(forName: name)
        return d
    }

    func testRecordsWhenShownAndDoesNotRepeatWithinTheInterval() {
        let defaults = freshDefaults()
        let key = "userAction.lastShown.act-00000001"
        let now = deadline.addingTimeInterval(-7 * UserActionCadence.day)
        defaults.set(now.addingTimeInterval(-3600), forKey: key)
        var events: [(ids: [String], event: UserActionEventSink.Event)] = []

        let reminder = OsUpdateReminder(defaults: defaults) { ids, event in events.append((ids, event)) }
        reminder.handle([update("act-00000001", label: "macOS 27.0.1-26A434")], now: now)
        // No tocaba: la marca sigue siendo la de hace una hora y no hay evento.
        XCTAssertEqual(defaults.object(forKey: key) as? Date, now.addingTimeInterval(-3600))
        XCTAssertTrue(events.isEmpty)
    }

    func testNoActionsNothingShown() {
        var events: [UserActionEventSink.Event] = []
        let reminder = OsUpdateReminder(defaults: freshDefaults()) { _, event in events.append(event) }
        reminder.handle([], now: deadline)
        XCTAssertTrue(events.isEmpty)
    }

    // MARK: Telemetría

    func testSinkAppendsEventsAndCapsThem() throws {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("ua-events-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let at = ISO8601DateFormatter().date(from: "2026-09-29T15:00:00Z")!
        UserActionEventSink.record(actionIds: ["a1", "a2"], event: .shown, at: at, to: url)
        UserActionEventSink.record(actionIds: ["a1"], event: .opened, at: at, to: url)
        let events = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [[String: String]])
        XCTAssertEqual(events.map { $0["event"] }, ["shown", "shown", "opened"])
        XCTAssertEqual(events.first?["atUtc"], "2026-09-29T15:00:00Z")
        let perms = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)

        for _ in 0..<(UserActionEventSink.maxEvents + 10) {
            UserActionEventSink.record(actionIds: ["a1"], event: .snoozed, at: at, to: url)
        }
        let capped = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [[String: String]])
        XCTAssertEqual(capped.count, UserActionEventSink.maxEvents)
    }

    // MARK: Texto

    func testTextSaysWhyOnlyTheUserCanDoIt() {
        let request = TrayOsUpdateRequest(label: "macOS 27.0.1-26A434", title: "macOS 27.0.1", deadlineUtc: deadline)
        let before = deadline.addingTimeInterval(-86400)
        XCTAssertTrue(OsUpdateReminderText.title(request, now: before).hasPrefix("Please install macOS 27.0.1 by "))
        XCTAssertTrue(OsUpdateReminderText.body(request, now: before).contains("only you can install it"))
        XCTAssertFalse(OsUpdateReminderText.body(request, now: before).contains("deadline has passed"))

        let after = deadline.addingTimeInterval(60)
        XCTAssertTrue(OsUpdateReminderText.title(request, now: after).hasPrefix("macOS 27.0.1 was due on "))
        XCTAssertTrue(OsUpdateReminderText.body(request, now: after).hasPrefix("The deadline has passed."))
    }

    func testContentRendersBothButtons() {
        let request = TrayOsUpdateRequest(label: "macOS 27.0.1-26A434", title: "macOS 27.0.1", deadlineUtc: deadline)
        let view = OsUpdateReminder.content(request, now: deadline.addingTimeInterval(-86400), target: nil)
        func buttons(_ v: NSView) -> [String] {
            (v as? NSButton).map { [$0.title] } ?? v.subviews.flatMap(buttons)
        }
        XCTAssertEqual(Set(buttons(view)), ["Open Software Update", "Remind me later"])
        XCTAssertNotNil(OsUpdateReminder.softwareUpdateURL)
    }

    private func findLabel(_ text: String, in v: NSView) -> NSTextField? {
        if let t = v as? NSTextField, t.stringValue == text { return t }
        for sub in v.subviews { if let f = findLabel(text, in: sub) { return f } }
        return nil
    }

    // MARK: Captura

    /// Renderiza la ventana a PNG (antes y después de la fecha) para mirarla:
    /// una restricción rota da un contenido de alto cero sin ningún error.
    func testSnapshot() throws {
        let request = TrayOsUpdateRequest(label: "macOS 27.0.1-26A434", title: "macOS 27.0.1", deadlineUtc: deadline, pendingCount: 1)
        for (name, now) in [("before", deadline.addingTimeInterval(-5 * 86400)), ("overdue", deadline.addingTimeInterval(3600))] {
            let view = OsUpdateReminder.content(request, now: now, target: nil)
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 100), styleMask: [.borderless], backing: .buffered, defer: false)
            window.appearance = NSAppearance(named: .aqua)
            window.contentView = view
            view.layoutSubtreeIfNeeded()
            window.setContentSize(view.fittingSize)
            view.layoutSubtreeIfNeeded()
            XCTAssertGreaterThan(view.fittingSize.height, 150, name)
            // 29-sep: el botón de cerrar (la ventana dibuja bajo la barra de
            // título) tapaba «Tracenium». La marca tiene que empezar por
            // debajo de los 28 pt de la barra.
            if let brand = findLabel("Tracenium", in: view) {
                let frame = brand.convert(brand.bounds, to: view)
                let fromTop = view.isFlipped ? frame.minY : view.bounds.height - frame.maxY
                XCTAssertGreaterThanOrEqual(fromTop, 28, "\(name): brand under the title bar")
            } else {
                XCTFail("no brand label")
            }
            guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { throw XCTSkip("no bitmap") }
            view.cacheDisplay(in: view.bounds, to: rep)
            let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("tracenium-os-update-\(name).png")
            try rep.representation(using: .png, properties: [:])?.write(to: url)
            print("SNAPSHOT os-update-\(name) -> \(url.path)")
        }
    }
}
