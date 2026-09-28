// test/plugins/rcp-candidate-kind.test.ts
//
// 🔴 Un `ice_failed` no dejaba NINGUNA pista de qué candidatos se reunieron.
//
// MSIG-VEEAM-SRV (T111, 28-sep-2026) costó una tarde de diagnóstico: el
// segmento estaba bien —MSIG-WSUS, en la misma /24 y con la misma pasarela,
// conectó en segundos—, el perfil de cortafuegos era el mismo en los dos, y el
// agente contestaba el offer en 1,2 s. Se descartaron a mano el relay, el
// enrutado del VPN, el NAT y la pasarela, uno por uno, porque el agente no
// anotaba una sola línea sobre sus propios candidatos.
//
// El recuento por tipo distingue las tres causas de un lado:
//   sin `host`  → el agente no pudo ni mirar sus interfaces;
//   sólo `host` → no hay salida UDP y no se ofreció relay;
//   con `relay` → el relay estaba, así que el problema es del otro extremo.

import { describe, expect, it } from "vitest";
import { candidateKind } from "../../src/plugins/rcp/peer-session";

describe("candidateKind", () => {
  it("lee los cuatro tipos de su sitio", () => {
    expect(candidateKind(
      "candidate:1 1 udp 2130706431 10.130.130.6 54321 typ host"
    )).toBe("host");
    expect(candidateKind(
      "candidate:2 1 udp 1694498815 189.203.193.0 54321 typ srflx raddr 10.130.130.6 rport 54321"
    )).toBe("srflx");
    expect(candidateKind(
      "candidate:3 1 udp 16777215 141.101.90.1 50000 typ relay raddr 0.0.0.0 rport 0"
    )).toBe("relay");
    expect(candidateKind(
      "candidate:4 1 udp 1 1.2.3.4 1 typ prflx"
    )).toBe("prflx");
  });

  it("⚠️ lee el token que sigue a `typ`, no la palabra suelta", () => {
    // `raddr` puede traer una direccion de un equipo llamado host, y contar
    // apariciones sueltas inflaria el unico numero que vamos a mirar cuando
    // algo falle. Aqui el tipo REAL es srflx aunque `host` aparezca antes.
    expect(candidateKind(
      "candidate:9 1 udp 100 1.2.3.4 9 typ srflx raddr 10.0.0.1 rport 9 ufrag host"
    )).toBe("srflx");
  });

  it("nada raro rompe el recuento", () => {
    expect(candidateKind("")).toBe("otro");
    expect(candidateKind("basura sin typ")).toBe("otro");
    expect(candidateKind("candidate:1 1 udp 1 1.2.3.4 1 typ")).toBe("otro");
    expect(candidateKind(undefined as any)).toBe("otro");
  });
});
