// test/plugins/cdp-starttls.test.ts
//
// StartTLS (§5.2): la sonda habla el preambulo en claro de SMTP, IMAP,
// POP3, LDAP, PostgreSQL y MySQL y luego hace el mismo handshake. Se
// prueba contra servidores REALES en loopback que implementan cada
// preambulo y suben a TLS con el certificado de prueba — no contra
// dobles del protocolo. Y lo que un servidor sin StartTLS contesta se
// convierte en `not_offered`, no en un timeout mudo.

import { describe, it, expect, afterEach } from "vitest";
import net from "net";
import tls from "tls";
import crypto from "crypto";
import type { AddressInfo } from "net";
import { FIXTURE_KEY, FIXTURE_CERT } from "./tls-fixture";
import { probeTlsEndpointDetailed, probeTlsWithKem, SKIPPED_PORTS } from "../../src/plugins/cdp/providers/tls-listeners";
import { STARTTLS_PORTS, LDAP_STARTTLS_REQUEST, PG_SSL_REQUEST, mysqlServerOffersSsl, mysqlSslRequestPacket, connectWithStartTls } from "../../src/plugins/cdp/starttls";

const FP = crypto.createHash("sha256").update(new crypto.X509Certificate(FIXTURE_CERT).raw).digest("hex");
const servers: net.Server[] = [];
afterEach(() => {
  for (const s of servers.splice(0)) s.close();
});

/** Servidor en claro que ejecuta `preamble` y, si devuelve true, sube a TLS. */
function serve(preamble: (sock: net.Socket, send: (s: string | Buffer) => void, onLine: (cb: (line: string) => boolean | void) => void) => void) {
  const server = net.createServer((sock) => {
    let buf = "";
    let handler: ((line: string) => boolean | void) | null = null;
    const upgrade = () => {
      sock.removeAllListeners("data");
      const secure = new tls.TLSSocket(sock, { isServer: true, key: FIXTURE_KEY, cert: FIXTURE_CERT });
      secure.on("error", () => undefined);
    };
    sock.on("data", (d) => {
      buf += d.toString("latin1");
      let i: number;
      while ((i = buf.indexOf("\n")) >= 0 && handler) {
        const line = buf.slice(0, i).replace(/\r$/, "");
        buf = buf.slice(i + 1);
        if (handler(line) === true) return upgrade();
      }
    });
    preamble(sock, (s) => sock.write(s), (cb) => (handler = cb));
    (sock as any)._upgrade = upgrade;
  });
  servers.push(server);
  return new Promise<number>((r) => server.listen(0, "127.0.0.1", () => r((server.address() as AddressInfo).port)));
}

/** Como `serve`, pero el preambulo es binario y decide el mismo cuando subir. */
function serveBinary(onData: (sock: net.Socket, chunk: Buffer, upgrade: (rest?: Buffer) => void) => void, greeting?: Buffer) {
  const server = net.createServer((sock) => {
    // `rest`: bytes que llegaron pegados al ultimo paquete en claro (el
    // ClientHello del cliente MySQL, que no espera respuesta al SSLRequest).
    // Se devuelven al stream para que los lea el lado TLS.
    //
    // ⚠️ EL `pause()` NO ES DECORATIVO: sin el, este doble fallaba una de
    // cada dos veces (run 34066976193 y ~50 % en local).
    //
    // Quitar los oyentes de `data` no saca al socket del modo FLUIDO, y
    // un stream fluido SIN oyentes tira lo que llega. Asi que el
    // `unshift` devolvia el ClientHello a un stream que lo descartaba
    // acto seguido: el TLSSocket no veia handshake y la sonda expiraba.
    // Se notaba solo cuando el cliente mandaba el SSLRequest y el
    // ClientHello en el MISMO segmento —lo que hace de verdad, porque no
    // espera respuesta—, y eso depende del reloj: con `rest` vacio no
    // habia nada que perder y el test pasaba.
    const upgrade = (rest?: Buffer) => {
      sock.removeAllListeners("data");
      sock.pause();
      if (rest && rest.length > 0) sock.unshift(rest);
      const secure = new tls.TLSSocket(sock, { isServer: true, key: FIXTURE_KEY, cert: FIXTURE_CERT });
      secure.on("error", () => undefined);
    };
    if (greeting) sock.write(greeting);
    sock.on("data", (d) => onData(sock, d, upgrade));
  });
  servers.push(server);
  return new Promise<number>((r) => server.listen(0, "127.0.0.1", () => r((server.address() as AddressInfo).port)));
}

// Los puertos reales estan reservados; se sondea el puerto efimero pero
// se fuerza el protocolo con un mapa temporal.
function withProtocol<T>(port: number, proto: keyof typeof STARTTLS_PORTS extends never ? never : any, fn: () => Promise<T>): Promise<T> {
  (STARTTLS_PORTS as any)[port] = proto;
  return fn().finally(() => {
    delete (STARTTLS_PORTS as any)[port];
  });
}

describe("lista de saltados", () => {
  it("⭐ SMTP, POP3, IMAP, MySQL y PostgreSQL ya se sondean; SSH, telnet y las bases sin StartTLS estandar siguen fuera", () => {
    for (const p of [25, 587, 110, 143, 389, 5432, 3306]) expect(SKIPPED_PORTS.has(p)).toBe(false);
    for (const p of [22, 23, 53, 1433, 6379, 27017]) expect(SKIPPED_PORTS.has(p)).toBe(true);
    expect(STARTTLS_PORTS[25]).toBe("smtp");
    expect(STARTTLS_PORTS[3306]).toBe("mysql");
  });
});

describe("preambulos contra servidores reales", () => {
  it("⭐ SMTP: EHLO → STARTTLS → 220 → handshake; el certificado servido es el del servidor", async () => {
    const port = await serve((sock, send, onLine) => {
      send("220 mail.corp ESMTP\r\n");
      onLine((line) => {
        if (/^EHLO/i.test(line)) send("250-mail.corp\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n");
        else if (/^STARTTLS/i.test(line)) {
          send("220 Ready to start TLS\r\n");
          return true;
        }
      });
    });
    const r = await withProtocol(port, "smtp", () => probeTlsEndpointDetailed("127.0.0.1", port, "localhost"));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(crypto.createHash("sha256").update(r.probe.der).digest("hex")).toBe(FP);
      expect(r.probe.startTls).toBe("smtp");
      expect(r.probe.protocol).toMatch(/^TLSv1\.[23]$/);
    }
  });

  it("⭐ SMTP sin STARTTLS en el EHLO → `starttls:not_offered`, sin timeout", async () => {
    const port = await serve((sock, send, onLine) => {
      send("220 old.mail\r\n");
      onLine((line) => {
        if (/^EHLO/i.test(line)) send("250-old.mail\r\n250 SIZE 1000\r\n");
      });
    });
    const started = Date.now();
    const r = await withProtocol(port, "smtp", () => probeTlsEndpointDetailed("127.0.0.1", port, "localhost"));
    expect(r).toEqual({ ok: false, code: "starttls:not_offered" });
    expect(Date.now() - started).toBeLessThan(2500);
  });

  it("IMAP: `a1 STARTTLS` → `a1 OK`", async () => {
    const port = await serve((sock, send, onLine) => {
      send("* OK IMAP4rev1 ready\r\n");
      onLine((line) => {
        if (/^a1 STARTTLS/i.test(line)) {
          send("a1 OK Begin TLS\r\n");
          return true;
        }
      });
    });
    const r = await withProtocol(port, "imap", () => probeTlsEndpointDetailed("127.0.0.1", port, "localhost"));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.probe.startTls).toBe("imap");
  });

  it("POP3: STLS → +OK; -ERR es not_offered", async () => {
    const ok = await serve((sock, send, onLine) => {
      send("+OK POP3 ready\r\n");
      onLine((line) => {
        if (/^STLS/i.test(line)) {
          send("+OK Begin TLS\r\n");
          return true;
        }
      });
    });
    expect((await withProtocol(ok, "pop3", () => probeTlsEndpointDetailed("127.0.0.1", ok, "localhost"))).ok).toBe(true);
    const no = await serve((sock, send, onLine) => {
      send("+OK POP3 ready\r\n");
      onLine((line) => {
        if (/^STLS/i.test(line)) send("-ERR TLS not available\r\n");
      });
    });
    expect(await withProtocol(no, "pop3", () => probeTlsEndpointDetailed("127.0.0.1", no, "localhost"))).toEqual({ ok: false, code: "starttls:not_offered" });
  });

  it("PostgreSQL: SSLRequest → 'S' sube; 'N' es not_offered", async () => {
    const yes = await serveBinary((sock, chunk, upgrade) => {
      if (chunk.equals(PG_SSL_REQUEST)) {
        sock.write("S");
        upgrade();
      }
    });
    const r = await withProtocol(yes, "postgres", () => probeTlsEndpointDetailed("127.0.0.1", yes, "localhost"));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.probe.startTls).toBe("postgres");
    const no = await serveBinary((sock, chunk) => {
      if (chunk.equals(PG_SSL_REQUEST)) sock.write("N");
    });
    expect(await withProtocol(no, "postgres", () => probeTlsEndpointDetailed("127.0.0.1", no, "localhost"))).toEqual({ ok: false, code: "starttls:not_offered" });
  });

  it("LDAP: ExtendedRequest StartTLS → ExtendedResponse success sube; unavailable es not_offered", async () => {
    const success = Buffer.from([0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]);
    const yes = await serveBinary((sock, chunk, upgrade) => {
      if (chunk.equals(LDAP_STARTTLS_REQUEST)) {
        sock.write(success);
        upgrade();
      }
    });
    const r = await withProtocol(yes, "ldap", () => probeTlsEndpointDetailed("127.0.0.1", yes, "localhost"));
    expect(r.ok).toBe(true);
    const unavailable = Buffer.from([0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x35, 0x04, 0x00, 0x04, 0x00]);
    const no = await serveBinary((sock, chunk) => {
      if (chunk.equals(LDAP_STARTTLS_REQUEST)) sock.write(unavailable);
    });
    expect(await withProtocol(no, "ldap", () => probeTlsEndpointDetailed("127.0.0.1", no, "localhost"))).toEqual({ ok: false, code: "starttls:not_offered" });
  });

  it("MySQL: handshake v10 con CLIENT_SSL → paquete SSLRequest → sube; sin la capacidad es not_offered", async () => {
    const handshake = (caps: number) => {
      const version = Buffer.from("8.0.36\0", "latin1");
      const p = Buffer.concat([Buffer.from([10]), version, Buffer.alloc(4, 1), Buffer.alloc(8, 2), Buffer.from([0]), Buffer.from([caps & 0xff, (caps >> 8) & 0xff]), Buffer.alloc(16, 0)]);
      return Buffer.concat([Buffer.from([p.length & 0xff, (p.length >> 8) & 0xff, (p.length >> 16) & 0xff, 0]), p]);
    };
    expect(mysqlServerOffersSsl(handshake(0x0800 | 0x0200))).toBe(true);
    expect(mysqlServerOffersSsl(handshake(0x0200))).toBe(false);
    expect(mysqlSslRequestPacket().length).toBe(36);

    // Se ACUMULA en vez de mirar el chunk suelto: el SSLRequest son 36
    // bytes y nada garantiza que lleguen en una sola lectura. Con la
    // condicion sobre el chunk, un corte a mitad del paquete dejaba esos
    // bytes tirados y el test caia con un timeout que no dice nada. Es
    // la misma suposicion de stream que el `pause()` de arriba, por el
    // otro lado.
    let visto = Buffer.alloc(0);
    const yes = await serveBinary((sock, chunk, upgrade) => {
      visto = Buffer.concat([visto, chunk]);
      if (visto.length >= 36 && visto[3] === 1) upgrade(visto.subarray(36));
    }, handshake(0x0800 | 0x0200 | 0x8000));
    const r = await withProtocol(yes, "mysql", () => probeTlsEndpointDetailed("127.0.0.1", yes, "localhost"));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.probe.startTls).toBe("mysql");

    const no = await serveBinary(() => undefined, handshake(0x0200));
    expect(await withProtocol(no, "mysql", () => probeTlsEndpointDetailed("127.0.0.1", no, "localhost"))).toEqual({ ok: false, code: "starttls:not_offered" });
  });

  it("un servidor mudo en un puerto StartTLS termina en preamble_timeout, no colgado", async () => {
    const port = await serveBinary(() => undefined);
    await expect(connectWithStartTls("127.0.0.1", port, "smtp", 300)).rejects.toThrow("starttls:preamble_timeout");
  });

  it("el veredicto KEM tambien pasa por StartTLS (dos conexiones, ambas con preambulo)", async () => {
    let ehlos = 0;
    const port = await serve((sock, send, onLine) => {
      send("220 mail\r\n");
      onLine((line) => {
        if (/^EHLO/i.test(line)) {
          ehlos += 1;
          send("250-mail\r\n250 STARTTLS\r\n");
        } else if (/^STARTTLS/i.test(line)) {
          send("220 go\r\n");
          return true;
        }
      });
    });
    const r = await withProtocol(port, "smtp", () => probeTlsWithKem("127.0.0.1", port, "localhost"));
    expect(r).not.toBeNull();
    expect(r!.startTls).toBe("smtp");
    // Node contra Node negocia hibrido a la primera, o se hizo la segunda
    // conexion forzada: en ambos casos hubo al menos un EHLO.
    expect(ehlos).toBeGreaterThanOrEqual(1);
  });
});
