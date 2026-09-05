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

/// ⚠️ Quién respondió, no solo qué respondió.
///
/// AgentCore corre como root y busca la respuesta en TODOS los perfiles del
/// equipo, porque no sabe de antemano quién está en consola. Sin
/// `respondedBy`, una respuesta escrita desde otra sesión valía igual que la
/// de quien está sentado delante — y el consentimiento de ADR-0012 es el de
/// esa persona: es SU pantalla.
///
/// La bandeja de Windows ya mandaba el campo; esta no, así que en macOS la
/// comprobación del agente se saldaba SIEMPRE con "no se sabe" y la ventana
/// de observación no observaba nada.
final class ConsentResponsePayloadTests: XCTestCase {
    func testCarriesWhoAnswered() {
        let p = ConsentPrompt.responsePayload(requestId: "sess-1.view.9",
                                              approved: true,
                                              respondedBy: "javier")
        XCTAssertEqual(p["requestId"] as? String, "sess-1.view.9")
        XCTAssertEqual(p["decision"] as? String, "approved")
        XCTAssertEqual(p["respondedBy"] as? String, "javier")
    }

    func testDenialAlsoCarriesIt() {
        // Un "no" también hay que poder atribuirlo: si no, una negativa
        // ajena es indistinguible de la de la persona del equipo.
        let p = ConsentPrompt.responsePayload(requestId: "x",
                                              approved: false,
                                              respondedBy: "javier")
        XCTAssertEqual(p["decision"] as? String, "denied")
        XCTAssertEqual(p["respondedBy"] as? String, "javier")
    }

    func testAnEmptyNameIsOmittedRatherThanSentBlank() {
        // El agente distingue tres cosas: la bandeja no lo dice (bandeja
        // vieja: se acepta y se anota), no se pudo resolver quién está en
        // consola (avería de lectura), y no coincide (otro usuario). Una
        // cadena vacía se leería como la tercera, que es la única que señala
        // a alguien.
        let p = ConsentPrompt.responsePayload(requestId: "x",
                                              approved: true,
                                              respondedBy: "   ")
        XCTAssertNil(p["respondedBy"])
    }

    func testTheNameIsTrimmed() {
        let p = ConsentPrompt.responsePayload(requestId: "x",
                                              approved: true,
                                              respondedBy: " javier\n")
        XCTAssertEqual(p["respondedBy"] as? String, "javier")
    }

    func testItSerializesAsTheAgentReadsIt() throws {
        // El agente hace `JSON.parse` y lee `respondedBy` como string. Si el
        // diccionario llevara algo no serializable, `write` fallaría en
        // silencio y el consentimiento venceria por plazo.
        let p = ConsentPrompt.responsePayload(requestId: "x",
                                              approved: true,
                                              respondedBy: "javier")
        let data = try JSONSerialization.data(withJSONObject: p)
        let back = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(back["respondedBy"] as? String, "javier")
    }
}
