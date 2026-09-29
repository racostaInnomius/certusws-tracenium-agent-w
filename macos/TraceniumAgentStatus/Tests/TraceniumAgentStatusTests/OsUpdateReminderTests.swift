import XCTest
@testable import TraceniumAgentStatus

/// Recordatorio de instalar una actualización de macOS (job os_update_nudge,
/// 29-sep). En Apple silicon el agente no puede instalarla: pide la contraseña
/// de un propietario (job e4689371). Lo que se fija aquí: que el bloque se lea
/// tal como lo escribe el agente, el ritmo, y que no se enseñe de más.
final class OsUpdateReminderTests: XCTestCase {
    private func decode(_ block: String) throws -> TrayStatus {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let json = """
        { "agentVersion": "1.1.86", "hostname": "JPR-MacBookPro", "osUpdateRequest": \(block) }
        """
        return try decoder.decode(TrayStatus.self, from: Data(json.utf8))
    }

    // MARK: Decodificación

    func testDecodesTheBlockAsTheAgentWritesIt_withMilliseconds() throws {
        // `toISOString()` → milisegundos, que `.iso8601` rechaza. Con el `try?`
        // del resto del modelo sería una petición perdida en silencio.
        let s = try decode(#"{ "label": "macOS 27.0.1-26A434", "title": "macOS 27.0.1", "deadlineUtc": "2026-10-06T23:00:00.000Z", "pendingCount": 2 }"#)
        let r = try XCTUnwrap(s.osUpdateRequest)
        XCTAssertEqual(r.label, "macOS 27.0.1-26A434")
        XCTAssertEqual(r.title, "macOS 27.0.1")
        XCTAssertEqual(r.pendingCount, 2)
        XCTAssertEqual(r.deadlineUtc, ISO8601DateFormatter().date(from: "2026-10-06T23:00:00Z"))
    }

    func testTitleFallsBackToLabel() throws {
        let s = try decode(#"{ "label": "macOS 27.0.1-26A434", "deadlineUtc": "2026-10-06T23:00:00Z" }"#)
        XCTAssertEqual(s.osUpdateRequest?.title, "macOS 27.0.1-26A434")
        XCTAssertEqual(s.osUpdateRequest?.pendingCount, 1)
    }

    func testABrokenBlockCostsOnlyTheBlock() throws {
        let s = try decode(#"{ "label": "", "deadlineUtc": "mañana" }"#)
        XCTAssertNil(s.osUpdateRequest)
        XCTAssertEqual(s.hostname, "JPR-MacBookPro")
    }

    // MARK: Ritmo

    private let deadline = ISO8601DateFormatter().date(from: "2026-10-06T23:00:00Z")!

    func testCadence() {
        let day = OsUpdateReminderCadence.day
        XCTAssertEqual(OsUpdateReminderCadence.interval(deadline: deadline, now: deadline.addingTimeInterval(-7 * day)), day)
        XCTAssertEqual(OsUpdateReminderCadence.interval(deadline: deadline, now: deadline.addingTimeInterval(-2 * day)), 4 * 3600)
        XCTAssertEqual(OsUpdateReminderCadence.interval(deadline: deadline, now: deadline.addingTimeInterval(60)), 3600)
    }

    func testIsDue() {
        let now = deadline.addingTimeInterval(-7 * OsUpdateReminderCadence.day)
        XCTAssertTrue(OsUpdateReminderCadence.isDue(lastShown: nil, deadline: deadline, now: now))
        XCTAssertFalse(OsUpdateReminderCadence.isDue(lastShown: now.addingTimeInterval(-3600), deadline: deadline, now: now))
        XCTAssertTrue(OsUpdateReminderCadence.isDue(lastShown: now.addingTimeInterval(-25 * 3600), deadline: deadline, now: now))
        // Vencida: cada hora.
        let late = deadline.addingTimeInterval(7200)
        XCTAssertTrue(OsUpdateReminderCadence.isDue(lastShown: late.addingTimeInterval(-3601), deadline: deadline, now: late))
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
        let key = "osUpdateReminder.lastShown.macOS 27.0.1-26A434"
        let request = TrayOsUpdateRequest(label: "macOS 27.0.1-26A434", title: "macOS 27.0.1", deadlineUtc: deadline)
        let now = deadline.addingTimeInterval(-7 * OsUpdateReminderCadence.day)
        defaults.set(now.addingTimeInterval(-3600), forKey: key)

        let reminder = OsUpdateReminder(defaults: defaults)
        reminder.handle(request, now: now)
        // No tocaba: la marca sigue siendo la de hace una hora.
        XCTAssertEqual(defaults.object(forKey: key) as? Date, now.addingTimeInterval(-3600))
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
            guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { throw XCTSkip("no bitmap") }
            view.cacheDisplay(in: view.bounds, to: rep)
            let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("tracenium-os-update-\(name).png")
            try rep.representation(using: .png, properties: [:])?.write(to: url)
            print("SNAPSHOT os-update-\(name) -> \(url.path)")
        }
    }
}
