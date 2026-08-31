import XCTest
@testable import TraceniumAgentStatus

/// El bloque `remoteSession` alimenta el indicador que le dice a una persona
/// que le están viendo la pantalla (ADR-0012). Sus fallos son silenciosos por
/// naturaleza: si no decodifica, no hay error visible en ningún sitio —
/// simplemente alguien mira sin que se note, que es el estado del que nadie se
/// quejó nunca porque nadie podía saberlo.
///
/// Por eso lo que se fija aquí es la asimetría: qué enciende la banda y, sobre
/// todo, qué NO debe encenderla.
final class RemoteSessionDecodingTests: XCTestCase {
    private func decode(_ json: String) throws -> TrayStatus {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(TrayStatus.self, from: Data(json.utf8))
    }

    private func snapshot(remoteBlock: String?) -> String {
        let remote = remoteBlock.map { ",\n  \"remoteSession\": \($0)" } ?? ""
        return """
        {
          "updatedAtUtc": "2026-08-30T12:00:00Z",
          "agentVersion": "1.1.53",
          "coreVersion": "1.1.53",
          "deviceId": "7149a30a-1181-41ed-86a7-08c7a62f20b4",
          "tenantId": "1",
          "hostname": "MacBook-Air-de-Rodrigo.local",
          "grpc": { "connected": true },
          "policy": { "version": "1", "plugins": [], "modules": [] },
          "jobs": {},
          "update": {},
          "patch": {}\(remote)
        }
        """
    }

    func testDecodesALiveSession() throws {
        let status = try decode(snapshot(remoteBlock: """
        {
          "active": true,
          "sessionId": "sess-abc",
          "capability": "rcp.screen",
          "operator": "Javier Pacheco",
          "controlling": true,
          "recording": false,
          "startedAtUtc": "2026-08-30T11:59:00Z"
        }
        """))

        let session = try XCTUnwrap(status.remoteSession)
        XCTAssertTrue(session.active)
        XCTAssertEqual(session.sessionId, "sess-abc")
        XCTAssertEqual(session.operator, "Javier Pacheco")
        XCTAssertTrue(session.controlling)
        XCTAssertFalse(session.recording)
        XCTAssertNotNil(session.startedAtUtc)
    }

    func testAbsentBlockMeansNoSession() throws {
        // El caso normal, con diferencia: nadie está mirando. Un agente
        // anterior al ADR tampoco escribe el bloque.
        let status = try decode(snapshot(remoteBlock: nil))
        XCTAssertNil(status.remoteSession)
    }

    func testControllingAndRecordingDefaultToFalse() throws {
        // Los campos son opcionales en el contrato TS. Ausentes tienen que
        // significar "no", no romper el bloque entero.
        let status = try decode(snapshot(remoteBlock: """
        { "active": true, "sessionId": "sess-abc", "capability": "rcp.screen" }
        """))

        let session = try XCTUnwrap(status.remoteSession)
        XCTAssertTrue(session.active)
        XCTAssertFalse(session.controlling)
        XCTAssertFalse(session.recording)
    }

    func testUnknownFieldDoesNotKillTheBlock() throws {
        // El agente puede empezar a escribir campos que esta versión no
        // conoce. Perder el indicador entero por eso sería el peor cambio
        // posible: dejaría de avisar justo al desplegar la versión nueva.
        let status = try decode(snapshot(remoteBlock: """
        {
          "active": true,
          "sessionId": "sess-abc",
          "capability": "rcp.screen",
          "somethingNewFromTheFuture": { "nested": [1, 2, 3] }
        }
        """))

        XCTAssertEqual(try XCTUnwrap(status.remoteSession).sessionId, "sess-abc")
    }

    func testMalformedFieldDegradesInsteadOfThrowing() throws {
        // Un tipo equivocado en un campo no puede tirar el snapshot COMPLETO,
        // que es el fallo que ya nos costó días de una Mac sin ubicación.
        let status = try decode(snapshot(remoteBlock: """
        { "active": true, "sessionId": "sess-abc", "controlling": "sí" }
        """))

        let session = try XCTUnwrap(status.remoteSession)
        XCTAssertTrue(session.active)
        XCTAssertFalse(session.controlling)
    }

    func testAnIllegibleActiveDoesNotLightTheBanner() throws {
        // La única asimetría deliberada del modelo: cuando no se entiende,
        // se apaga. Encender la banda por un campo ilegible enseñaría un aviso
        // falso cada vez que el JSON cambie de forma, y una alarma falsa
        // entrena a la gente a ignorar la de verdad.
        let status = try decode(snapshot(remoteBlock: """
        { "active": "puede", "sessionId": "sess-abc" }
        """))

        XCTAssertFalse(try XCTUnwrap(status.remoteSession).active)
    }

    func testBrokenRemoteBlockDoesNotCostTheRestOfTheSnapshot() throws {
        // El bloque degrada solo, como todos los demás: una sesión remota
        // ilegible no puede dejar a la app sin versión ni sin estado de gRPC.
        let status = try decode(snapshot(remoteBlock: "\"esto no es un objeto\""))

        XCTAssertNil(status.remoteSession)
        XCTAssertEqual(status.agentVersion, "1.1.53")
        XCTAssertTrue(status.grpc.connected)
    }
}
