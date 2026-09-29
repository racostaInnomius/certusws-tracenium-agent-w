import XCTest
@testable import TraceniumAgentStatus

/// Las fechas tal como las escribe el agente: `new Date().toISOString()`, o sea
/// CON milisegundos ("2026-10-06T23:00:00.000Z").
///
/// Con `.iso8601`, el Foundation antiguo (macOS 12, el iMac de T1) rechaza la
/// fracción de segundo, y el modelo decodifica cada fecha con `try?`: el fallo
/// no rompía nada, dejaba el campo en `nil` en silencio —y `jobs.current`, que
/// no es tolerante campo a campo, desaparecía entero. Los fixtures del resto de
/// tests usaban "…Z" sin milisegundos, que es justo la forma que el agente no
/// escribe nunca.
///
/// ⚠️ En un macOS reciente estos tests pasan también con `.iso8601` —su
/// JSONDecoder sí acepta milisegundos—, así que en el Mac de desarrollo no
/// detectan una vuelta atrás; en uno con macOS 12 sí. Lo que fijan aquí es la
/// forma: que los lectores de verdad (`StatusSnapshotReader`,
/// `ConsentRequestReader.decode`) lean lo que escribe el agente.
final class AgentTimestampDecodingTests: XCTestCase {
    private let ms = "2026-10-06T23:00:00.123Z"
    private var expected: Date {
        Date(timeIntervalSince1970: 1_791_327_600.123)
    }
    private var tmpDir: URL!

    override func setUpWithError() throws {
        tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tray-ts-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tmpDir)
    }

    private func readSnapshot(_ json: String) throws -> TrayStatus {
        let path = tmpDir.appendingPathComponent("tray-status.json")
        try Data(json.utf8).write(to: path)
        return try XCTUnwrap(StatusSnapshotReader(snapshotPath: path.path).read())
    }

    private func assertDate(_ d: Date?, _ field: String, file: StaticString = #filePath, line: UInt = #line) {
        guard let d else {
            XCTFail("\(field) quedó en nil", file: file, line: line)
            return
        }
        XCTAssertEqual(d.timeIntervalSince1970, expected.timeIntervalSince1970, accuracy: 0.0005,
                       "\(field)", file: file, line: line)
    }

    func testSnapshotDatesWithMillisecondsDecode() throws {
        let s = try readSnapshot("""
        {
          "updatedAtUtc": "\(ms)",
          "agentVersion": "1.1.86",
          "grpc": {
            "connected": true,
            "lastConnectedAtUtc": "\(ms)",
            "lastDisconnectedAtUtc": "\(ms)",
            "lastHeartbeatAtUtc": "\(ms)"
          },
          "jobs": {
            "lastJobType": "patch_install",
            "lastJobStatus": "in_progress",
            "lastJobAtUtc": "\(ms)",
            "current": { "jobId": "j1", "jobType": "patch_install", "startedAtUtc": "\(ms)" }
          },
          "update": { "status": "idle", "lastCheckedAtUtc": "\(ms)", "lastCompletedAtUtc": "\(ms)" },
          "patch": { "status": "idle", "lastScanAtUtc": "\(ms)" },
          "catalog": { "updatedAtUtc": "\(ms)", "catalogVersion": "v1", "items": [] },
          "remoteSession": {
            "active": true, "sessionId": "s1", "capability": "rcp.screen",
            "startedAtUtc": "\(ms)", "controlling": false, "recording": false
          }
        }
        """)
        assertDate(s.updatedAtUtc, "updatedAtUtc")
        assertDate(s.grpc.lastConnectedAtUtc, "grpc.lastConnectedAtUtc")
        assertDate(s.grpc.lastDisconnectedAtUtc, "grpc.lastDisconnectedAtUtc")
        assertDate(s.grpc.lastHeartbeatAtUtc, "grpc.lastHeartbeatAtUtc")
        assertDate(s.jobs.lastJobAtUtc, "jobs.lastJobAtUtc")
        // `current` no es tolerante campo a campo: una fecha ilegible tiraba el
        // bloque entero, y con él la pestaña Active Job y la insignia.
        let current = try XCTUnwrap(s.jobs.current, "jobs.current se perdió entero")
        assertDate(current.startedAtUtc, "jobs.current.startedAtUtc")
        assertDate(s.update.lastCheckedAtUtc, "update.lastCheckedAtUtc")
        assertDate(s.update.lastCompletedAtUtc, "update.lastCompletedAtUtc")
        assertDate(s.patch.lastScanAtUtc, "patch.lastScanAtUtc")
        assertDate(s.catalog?.updatedAtUtc, "catalog.updatedAtUtc")
        assertDate(s.remoteSession?.startedAtUtc, "remoteSession.startedAtUtc")
    }

    func testSnapshotDatesWithoutFractionStillDecode() throws {
        let s = try readSnapshot(#"{ "updatedAtUtc": "2026-10-06T23:00:00Z", "patch": { "lastScanAtUtc": "2026-10-06T23:00:00Z" } }"#)
        XCTAssertEqual(s.updatedAtUtc, Date(timeIntervalSince1970: 1_791_327_600))
        XCTAssertEqual(s.patch.lastScanAtUtc, Date(timeIntervalSince1970: 1_791_327_600))
    }

    func testAGarbageDateStillDegradesToNilWithoutLosingTheRest() throws {
        let s = try readSnapshot(#"{ "updatedAtUtc": "yesterday", "agentVersion": "1.1.86" }"#)
        XCTAssertNil(s.updatedAtUtc)
        XCTAssertEqual(s.agentVersion, "1.1.86")
    }

    func testParseIsoDateAcceptsBothFormsAndRejectsGarbage() {
        XCTAssertEqual(TrayJSON.parseIsoDate(ms)?.timeIntervalSince1970 ?? 0,
                       expected.timeIntervalSince1970, accuracy: 0.0005)
        XCTAssertEqual(TrayJSON.parseIsoDate("2026-10-06T23:00:00Z"), Date(timeIntervalSince1970: 1_791_327_600))
        XCTAssertEqual(TrayJSON.parseIsoDate("2026-10-07T01:00:00.000+02:00"), Date(timeIntervalSince1970: 1_791_327_600))
        XCTAssertNil(TrayJSON.parseIsoDate("yesterday"))
        XCTAssertNil(TrayJSON.parseIsoDate(""))
    }

    // MARK: Consentimiento

    private func consent(expiresAtUtc: String) -> ConsentRequest? {
        ConsentRequestReader.decode(Data("""
        {
          "requestId": "sess-1.view.1", "sessionId": "sess-1", "kind": "view",
          "lines": ["Javier wants to VIEW this screen."],
          "expiresAtUtc": "\(expiresAtUtc)"
        }
        """.utf8))
    }

    func testConsentExpiryWithMillisecondsDecodes() throws {
        let r = try XCTUnwrap(consent(expiresAtUtc: ms))
        assertDate(r.expiresAtUtc, "expiresAtUtc")
    }

    func testAStaleConsentRequestAsTheAgentWritesItIsExpired() throws {
        // Un consent-request.json que quedó sin consumir (el agente reinició
        // con el diálogo abierto). Con la fecha ilegible, `isExpired` decía
        // `false` y la bandeja lo habría enseñado horas después.
        let r = try XCTUnwrap(consent(expiresAtUtc: "2026-01-01T00:00:00.000Z"))
        XCTAssertTrue(r.isExpired(now: Date(timeIntervalSince1970: 1_791_327_600)))
    }
}
