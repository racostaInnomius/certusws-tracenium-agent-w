import XCTest
@testable import TraceniumAgentStatus

/// La petición de consentimiento es lo que decide si alguien puede ver —o
/// usar— el equipo de otra persona. Sus casos degenerados tienen que caer
/// todos del mismo lado: no enseñar nada es seguro; enseñar un aviso que no
/// dice para qué es pedir un "sí" que no significa nada.
final class ConsentRequestTests: XCTestCase {
    private func decode(_ json: String) throws -> ConsentRequest {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return try d.decode(ConsentRequest.self, from: Data(json.utf8))
    }

    func testDecodesAControlRequest() throws {
        let r = try decode("""
        {
          "requestId": "sess-1.control.123",
          "sessionId": "sess-1",
          "kind": "control",
          "title": "Remote control request",
          "lines": ["Javier wants to CONTROL this computer.", "They can already see your screen."],
          "allowLabel": "Allow control",
          "denyLabel": "Don't allow",
          "expiresAtUtc": "2099-01-01T00:00:00Z"
        }
        """)
        XCTAssertEqual(r.kind, "control")
        XCTAssertEqual(r.lines.count, 2)
        XCTAssertTrue(r.isShowable)
        XCTAssertFalse(r.isExpired())
    }

    func testARequestWithNoTextIsNotShowable() throws {
        // Un diálogo que pide permiso sin decir para qué obtiene un "sí" vacío
        // y deja en auditoría que la persona aceptó.
        let r = try decode("""
        { "requestId": "x", "sessionId": "s", "kind": "view", "lines": [] }
        """)
        XCTAssertFalse(r.isShowable)
    }

    func testARequestWithNoIdIsNotShowable() throws {
        // Sin id no hay a qué responder: la respuesta no se podría emparejar y
        // el agente agotaría el plazo igualmente.
        let r = try decode("""
        { "sessionId": "s", "kind": "view", "lines": ["algo"] }
        """)
        XCTAssertFalse(r.isShowable)
    }

    func testAnExpiredRequestIsNotShown() throws {
        // El caso que evita el peor fallo de este canal: un aviso que aparece
        // horas tarde pidiendo permiso para una sesión que ya terminó.
        let r = try decode("""
        {
          "requestId": "x", "sessionId": "s", "kind": "view",
          "lines": ["algo"], "expiresAtUtc": "2020-01-01T00:00:00Z"
        }
        """)
        XCTAssertTrue(r.isExpired())
    }

    func testNoExpiryMeansNotExpired() throws {
        // Un agente anterior al campo no lo escribe. Tratarlo como vencido
        // haría que el aviso no saliera nunca.
        let r = try decode("""
        { "requestId": "x", "sessionId": "s", "kind": "view", "lines": ["algo"] }
        """)
        XCTAssertFalse(r.isExpired())
    }

    func testUnknownFieldsDoNotKillTheRequest() throws {
        // Un agente más nuevo puede añadir campos. Perder el aviso por eso
        // dejaría de pedir consentimiento justo al desplegar la versión nueva.
        let r = try decode("""
        {
          "requestId": "x", "sessionId": "s", "kind": "view",
          "lines": ["algo"], "somethingNew": {"a": [1,2]}
        }
        """)
        XCTAssertTrue(r.isShowable)
    }
}
