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
import { iceServerUrls } from "../../src/plugins/rcp/session-manager";

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

/**
 * La otra mitad de la misma tarde perdida: «¿qué extremos abro en el
 * cortafuegos del cliente?» no se podía contestar desde el equipo. El backend
 * sella la lista en `rcp_session_routing.ice_servers_json` con
 * `RCP_SECRETS_KEY`, y el agente sólo anotaba `iceServersCount`. Hubo que
 * abrir las herramientas de desarrollo del navegador del operador para leer
 * `turnConfig.iceServers`.
 */
describe("iceServerUrls", () => {
  it("aplana urls de cadena y de array, sin repetir", () => {
    expect(iceServerUrls([
      { urls: "stun:stun.l.google.com:19302" },
      { urls: ["turn:turn.cloudflare.com:3478?transport=udp",
               "turns:turn.cloudflare.com:5349?transport=tcp"] },
      { urls: "stun:stun.l.google.com:19302" },
    ])).toEqual([
      "stun:stun.l.google.com:19302",
      "turn:turn.cloudflare.com:3478?transport=udp",
      "turns:turn.cloudflare.com:5349?transport=tcp",
    ]);
  });

  it("⚠️ NO copia username ni credential: son credenciales TURN vivas", () => {
    const logged = iceServerUrls([{
      urls: "turn:turn.cloudflare.com:3478",
      username: "1759000000:tracenium",
      credential: "K6vQ2mJ8pR4sT9wX1yZ3aB5cD7eF0gH2iJ4kL6mN8oP",
    }]);
    // La aserción es sobre lo que sale, no sobre lo que el objeto traía: si
    // alguien pasa a registrar el RTCIceServer entero, esto se pone rojo.
    const flat = JSON.stringify(logged);
    expect(flat).not.toContain("credential");
    expect(flat).not.toContain("K6vQ2mJ8pR4sT9wX1yZ3aB5cD7eF0gH2iJ4kL6mN8oP");
    expect(flat).not.toContain("1759000000:tracenium");
    expect(logged).toEqual(["turn:turn.cloudflare.com:3478"]);
  });

  it("descarta una url que traiga credencial embebida", () => {
    expect(iceServerUrls([{ urls: "turn:user:secreto@turn.cloudflare.com:3478" }]))
      .toEqual([]);
  });

  it("nada raro rompe el log", () => {
    expect(iceServerUrls([])).toEqual([]);
    expect(iceServerUrls(undefined as any)).toEqual([]);
    expect(iceServerUrls([null, {}, { urls: "" }, { urls: [null, "  "] }] as any))
      .toEqual([]);
  });
});
