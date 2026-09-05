// src/plugins/cdp/starttls.ts
//
// StartTLS (analisis de madurez de CDP 2026-09, §5.2).
//
// Hasta ahora la sonda solo hablaba TLS implicito: un ClientHello nada
// mas abrir el socket. Los protocolos que empiezan en claro y SUBEN a
// TLS (SMTP, IMAP, POP3, LDAP, PostgreSQL, MySQL) estaban en la lista de
// puertos saltados, porque un ClientHello a ciegas los confunde y llena
// sus logs. El resultado: el certificado del servidor de correo, del
// directorio y de las bases de datos no existia para el inventario, y
// esos son justo los que un balanceador no tapa.
//
// Aqui vive el preambulo en claro de cada protocolo: lo minimo para que
// el servidor diga «adelante» y devolver el socket listo para
// `tls.connect({ socket })`. Ni un byte de aplicacion despues: en cuanto
// hay handshake, la sonda cierra.
//
// Cada preambulo es de LECTURA: EHLO/STARTTLS, `a1 STARTTLS`, STLS, la
// operacion extendida 1.3.6.1.4.1.1466.20037, SSLRequest, el paquete SSL
// de MySQL. Ninguno autentica ni consulta nada.

import net from "net";

export type StartTlsProtocol = "smtp" | "imap" | "pop3" | "ldap" | "postgres" | "mysql";

/** Puerto → protocolo con StartTLS. Fuera de aqui, TLS implicito. */
export const STARTTLS_PORTS: Record<number, StartTlsProtocol> = {
  25: "smtp",
  587: "smtp",
  110: "pop3",
  143: "imap",
  389: "ldap",
  5432: "postgres",
  3306: "mysql"
};

export class StartTlsError extends Error {
  constructor(public readonly reason: string) {
    super(`starttls:${reason}`);
  }
}

/** Lee hasta que `done(buffer)` diga que hay respuesta completa. */
function readUntil(socket: net.Socket, done: (buf: Buffer) => boolean, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    let settled = false;
    const finish = (err?: Error, out?: Buffer) => {
      if (settled) return;
      settled = true;
      clearTimeout(t);
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
      if (err) reject(err);
      else resolve(out!);
    };
    const onData = (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length > 65536) return finish(new StartTlsError("response_too_large"));
      if (done(buf)) finish(undefined, buf);
    };
    const onError = (e: any) => finish(new StartTlsError(String(e?.code || e?.message || "socket_error")));
    const onClose = () => finish(new StartTlsError("closed_during_preamble"));
    const t = setTimeout(() => finish(new StartTlsError("preamble_timeout")), timeoutMs);
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

/** Respuesta de linea(s) terminada en CRLF; para SMTP, la ultima linea es `NNN ` (espacio). */
const lineDone = (buf: Buffer) => buf.includes("\n");
const smtpDone = (buf: Buffer) => {
  const s = buf.toString("latin1");
  if (!s.endsWith("\r\n") && !s.endsWith("\n")) return false;
  const lines = s.trim().split(/\r?\n/);
  const last = lines[lines.length - 1];
  return /^\d{3}(\s|$)/.test(last);
};

async function smtp(socket: net.Socket, t: number): Promise<void> {
  const greet = (await readUntil(socket, smtpDone, t)).toString("latin1");
  if (!greet.startsWith("220")) throw new StartTlsError(`smtp_greeting_${greet.slice(0, 3)}`);
  socket.write("EHLO tracenium.probe\r\n");
  const ehlo = (await readUntil(socket, smtpDone, t)).toString("latin1");
  if (!ehlo.startsWith("250")) throw new StartTlsError(`smtp_ehlo_${ehlo.slice(0, 3)}`);
  if (!/^250[- ]STARTTLS/im.test(ehlo)) throw new StartTlsError("not_offered");
  socket.write("STARTTLS\r\n");
  const go = (await readUntil(socket, smtpDone, t)).toString("latin1");
  if (!go.startsWith("220")) throw new StartTlsError(`smtp_starttls_${go.slice(0, 3)}`);
}

async function imap(socket: net.Socket, t: number): Promise<void> {
  const greet = (await readUntil(socket, lineDone, t)).toString("latin1");
  if (!/^\* (OK|PREAUTH)/i.test(greet)) throw new StartTlsError("imap_greeting");
  socket.write("a1 STARTTLS\r\n");
  const resp = (await readUntil(socket, (b) => /^a1 /m.test(b.toString("latin1")) && b.includes("\n"), t)).toString("latin1");
  if (!/^a1 OK/im.test(resp)) throw new StartTlsError(/^a1 (NO|BAD)/im.test(resp) ? "not_offered" : "imap_starttls");
}

async function pop3(socket: net.Socket, t: number): Promise<void> {
  const greet = (await readUntil(socket, lineDone, t)).toString("latin1");
  if (!greet.startsWith("+OK")) throw new StartTlsError("pop3_greeting");
  socket.write("STLS\r\n");
  const resp = (await readUntil(socket, lineDone, t)).toString("latin1");
  if (!resp.startsWith("+OK")) throw new StartTlsError(resp.startsWith("-ERR") ? "not_offered" : "pop3_stls");
}

/** ExtendedRequest StartTLS (RFC 4511 §4.14), messageID 1, ya codificado. */
export const LDAP_STARTTLS_REQUEST = Buffer.from([
  0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16,
  ...Buffer.from("1.3.6.1.4.1.1466.20037", "ascii")
]);

async function ldap(socket: net.Socket, t: number): Promise<void> {
  socket.write(LDAP_STARTTLS_REQUEST);
  // ExtendedResponse: 30 len 02 01 01 78 len 0a 01 <resultCode> ...
  const resp = await readUntil(socket, (b) => b.length >= 2 && b.length >= 2 + (b[1] < 0x80 ? b[1] : 0), t);
  const i = resp.indexOf(0x78);
  if (i < 0 || resp[i + 2] !== 0x0a) throw new StartTlsError("ldap_response");
  const code = resp[i + 4];
  if (code !== 0) throw new StartTlsError(code === 2 || code === 53 ? "not_offered" : `ldap_result_${code}`);
}

/** SSLRequest: longitud 8, codigo 80877103. Respuesta un byte: S o N. */
export const PG_SSL_REQUEST = Buffer.from([0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f]);

async function postgres(socket: net.Socket, t: number): Promise<void> {
  socket.write(PG_SSL_REQUEST);
  const resp = await readUntil(socket, (b) => b.length >= 1, t);
  const c = String.fromCharCode(resp[0]);
  if (c === "S") return;
  if (c === "N") throw new StartTlsError("not_offered");
  throw new StartTlsError(`postgres_${resp[0]}`);
}

const MYSQL_CLIENT_SSL = 0x0800;
const MYSQL_CLIENT_PROTOCOL_41 = 0x0200;
const MYSQL_CLIENT_SECURE_CONNECTION = 0x8000;

/** Paquete SSLRequest de MySQL (32 bytes de carga, secuencia 1). */
export function mysqlSslRequestPacket(): Buffer {
  const payload = Buffer.alloc(32, 0);
  payload.writeUInt32LE(MYSQL_CLIENT_SSL | MYSQL_CLIENT_PROTOCOL_41 | MYSQL_CLIENT_SECURE_CONNECTION, 0);
  payload.writeUInt32LE(0x01000000, 4); // max packet
  payload[8] = 0x21; // utf8_general_ci
  const header = Buffer.from([32, 0, 0, 1]);
  return Buffer.concat([header, payload]);
}

/** Lee el handshake inicial del servidor y comprueba que anuncia SSL. */
export function mysqlServerOffersSsl(packet: Buffer): boolean | null {
  if (packet.length < 5) return null;
  const len = packet[0] | (packet[1] << 8) | (packet[2] << 16);
  const p = packet.subarray(4, 4 + len);
  if (p.length < len) return null;
  if (p[0] !== 10) return null; // protocolo v10
  const nul = p.indexOf(0, 1);
  if (nul < 0) return null;
  // version\0 (nul) + connection id (4) + auth-plugin-data-part-1 (8) + filler (1) → capability lower 2 bytes
  const off = nul + 1 + 4 + 8 + 1;
  if (p.length < off + 2) return null;
  const capLow = p.readUInt16LE(off);
  return (capLow & MYSQL_CLIENT_SSL) !== 0;
}

async function mysql(socket: net.Socket, t: number): Promise<void> {
  const hs = await readUntil(socket, (b) => {
    if (b.length < 4) return false;
    const len = b[0] | (b[1] << 8) | (b[2] << 16);
    return b.length >= 4 + len;
  }, t);
  const offers = mysqlServerOffersSsl(hs);
  if (offers === null) throw new StartTlsError("mysql_handshake");
  if (!offers) throw new StartTlsError("not_offered");
  socket.write(mysqlSslRequestPacket());
}

const PREAMBLE: Record<StartTlsProtocol, (s: net.Socket, t: number) => Promise<void>> = { smtp, imap, pop3, ldap, postgres, mysql };

/**
 * Abre el socket, ejecuta el preambulo del protocolo y devuelve el
 * socket listo para envolver en TLS. Rechaza con StartTlsError (razon
 * estable: `not_offered`, `preamble_timeout`, `smtp_ehlo_502`…).
 */
export function connectWithStartTls(host: string, port: number, protocol: StartTlsProtocol, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    let settled = false;
    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* ya cerrado */
      }
      reject(err);
    };
    const timer = setTimeout(() => fail(new StartTlsError("connect_timeout")), timeoutMs);
    socket.once("error", (e: any) => fail(new StartTlsError(String(e?.code || e?.message || "connect_error"))));
    socket.once("connect", () => {
      clearTimeout(timer);
      PREAMBLE[protocol](socket, timeoutMs)
        .then(() => {
          if (settled) return;
          settled = true;
          socket.removeAllListeners("error");
          resolve(socket);
        })
        .catch((e) => fail(e instanceof StartTlsError ? e : new StartTlsError(String(e?.message || e))));
    });
  });
}
