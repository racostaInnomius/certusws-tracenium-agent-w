// test/plugins/cdp-tls-kem.test.ts
//
// Fase 2 del analisis de madurez: lo que el handshake NEGOCIA, y el
// veredicto de KEM hibrido.
//
// ⚠️ Esto se prueba contra un servidor TLS REAL en 127.0.0.1, no con un
// mock del socket. Dos razones: la primera version del probe leia solo
// getPeerCertificate y nadie noto durante meses que protocolo, suite y
// grupo no viajaban — un mock habria pasado igual. Y el veredicto de KEM
// depende de como responde OpenSSL a un cliente restringido, que es
// justo lo que un mock inventaria.
//
// Hallazgo medido al escribirlo (2026-09-04), mas matizado que lo que
// decia ADR-0004: getEphemeralKeyInfo() SI devuelve el grupo en TLS 1.3
// en Node 22.21… pero solo para ECDH clasico (X25519, prime256v1). Para
// el grupo hibrido devuelve `{}`. Consecuencia: la observacion pasiva
// sirve para decir «negocio clasico», no para confirmar «negocio
// hibrido» — para eso sigue haciendo falta la segunda conexion.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import tls from "tls";
import type { AddressInfo } from "net";
import {
  probeTlsWithKem,
  probeTlsEndpoint,
  kemProbeSupported,
  HYBRID_KEM_GROUP
} from "../../src/plugins/cdp/providers/tls-listeners";
import { FIXTURE_CERT, FIXTURE_KEY } from "./tls-fixture";

function listen(server: tls.Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
  });
}

describe("lo negociado viaja", () => {
  let server: tls.Server;
  let port: number;
  beforeAll(async () => {
    server = tls.createServer({ key: FIXTURE_KEY, cert: FIXTURE_CERT });
    port = await listen(server);
  });
  afterAll(() => server.close());

  it("⭐ protocolo, suite y grupo de intercambio salen del handshake", async () => {
    const r = await probeTlsEndpoint("127.0.0.1", port, "localhost");
    expect(r).not.toBeNull();
    expect(r!.protocol).toMatch(/^TLSv1\.[23]$/);
    expect(r!.cipher).toMatch(/^TLS_|^ECDHE/);
    // El grupo solo tiene nombre si fue ECDH clasico. Un servidor Node
    // por defecto contra un cliente Node por defecto NEGOCIA hibrido
    // (ambos lo ofrecen), y entonces Node no lo nombra. Se comprueba el
    // contrato real: o hay nombre, o es TLS 1.3 sin nombre.
    if (r!.kexGroup !== undefined) expect(r!.kexGroup.length).toBeGreaterThan(0);
    else expect(r!.protocol).toBe("TLSv1.3");
  });

  it("un servidor clasico SI nombra su grupo", async () => {
    const srv = tls.createServer({ key: FIXTURE_KEY, cert: FIXTURE_CERT, ecdhCurve: "X25519" });
    const p = await listen(srv);
    try {
      const r = await probeTlsEndpoint("127.0.0.1", p, "localhost");
      expect(r!.kexGroup).toBe("X25519");
    } finally {
      srv.close();
    }
  });
});

describe("veredicto de KEM hibrido", () => {
  it("⭐ un servidor restringido a P-256 NO soporta hibrido → false, no null", async () => {
    // Es el caso que importa distinguir: el servidor contesta con un
    // alert de handshake al grupo hibrido. Eso es un «no» del servidor,
    // no un silencio.
    const server = tls.createServer({ key: FIXTURE_KEY, cert: FIXTURE_CERT, ecdhCurve: "prime256v1" });
    const port = await listen(server);
    try {
      const r = await probeTlsWithKem("127.0.0.1", port, "localhost");
      expect(r).not.toBeNull();
      expect(r!.kexGroup).toBe("prime256v1");
      if (kemProbeSupported()) {
        expect(r!.kemHybrid).toBe(false);
        expect(r!.kemProbeError).toBeUndefined();
      } else {
        expect(r!.kemHybrid).toBeNull();
        expect(r!.kemProbeError).toBe("client_openssl_lacks_group");
      }
    } finally {
      server.close();
    }
  });

  it("un servidor que acepta el grupo hibrido → true", async () => {
    if (!kemProbeSupported()) return; // este OpenSSL no puede ni preguntarlo
    const server = tls.createServer({ key: FIXTURE_KEY, cert: FIXTURE_CERT, ecdhCurve: `${HYBRID_KEM_GROUP}:X25519` });
    const port = await listen(server);
    try {
      const r = await probeTlsWithKem("127.0.0.1", port, "localhost");
      expect(r).not.toBeNull();
      expect(r!.kemHybrid).toBe(true);
    } finally {
      server.close();
    }
  });

  it("⭐ un servidor que SOLO acepta hibrido → true, aunque Node no nombre el grupo", async () => {
    // Medido: para X25519MLKEM768 getEphemeralKeyInfo() es `{}`. Si el
    // veredicto dependiera del nombre, el caso mas post-cuantico de
    // todos saldria «desconocido». La segunda conexion es la que decide.
    if (!kemProbeSupported()) return;
    const server = tls.createServer({ key: FIXTURE_KEY, cert: FIXTURE_CERT, ecdhCurve: HYBRID_KEM_GROUP });
    const port = await listen(server);
    let connections = 0;
    server.on("secureConnection", () => {
      connections += 1;
    });
    try {
      const r = await probeTlsWithKem("127.0.0.1", port, "localhost");
      expect(r!.kexGroup).toBeUndefined();
      expect(r!.kemHybrid).toBe(true);
      expect(connections).toBeLessThanOrEqual(2);
    } finally {
      server.close();
    }
  });

  it("un puerto que no contesta → null, y NO se afirma nada del KEM", async () => {
    // Puerto cerrado: ECONNREFUSED. El resultado entero es null porque no
    // hay certificado; el veredicto de KEM no llega a existir.
    const server = tls.createServer({ key: FIXTURE_KEY, cert: FIXTURE_CERT });
    const port = await listen(server);
    await new Promise<void>((res) => server.close(() => res()));
    const r = await probeTlsWithKem("127.0.0.1", port, "localhost");
    expect(r).toBeNull();
  });
});
