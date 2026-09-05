// test/plugins/rcp-file-protocol.test.ts
//
// Sprint 2 (aditivo) — RCP M2: protocolo JSON del DataChannel para file
// ops. Se ejercita la clase real `FileSession` con un DataChannel FAKE
// (no node-datachannel real) y fs REAL sobre tmpdir. Verificamos:
//
//   - list      → responde { op: "listing", entries: [...] } ordenado
//                 (directorios primero, luego alfabético)
//   - download  → parte en chunks base64, marca `done` en el último,
//                 emite audit started + completed
//   - upload    → { op:"ready" }, escribe chunks, uploadDone materializa
//                 el archivo en destino, audit started + completed
//   - cancel    → download en curso termina como "cancelled"
//   - mensajes malformados → JSON inválido / op desconocida / campos
//                 faltantes NO revientan la sesión
//
// El DataChannel real de node-datachannel expone onMessage/onClosed/
// sendMessage; el fake replica exactamente esa superficie mínima que
// FileSession consume, así no cargamos el binding nativo.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";

import { FileSession } from "../../src/plugins/rcp/file-session";
import type { FileTransferAuditPayload } from "../../src/plugins/rcp/file-session";
import type { PolicyRuntime } from "../../src/core/policy-runtime";

// ── Fake DataChannel ───────────────────────────────────────────────────
class FakeDataChannel {
  private msgCb: ((raw: any) => void) | null = null;
  private closedCb: (() => void) | null = null;
  sent: string[] = [];

  onMessage(cb: (raw: any) => void) {
    this.msgCb = cb;
  }
  onClosed(cb: () => void) {
    this.closedCb = cb;
  }
  sendMessage(text: string) {
    this.sent.push(text);
  }
  // helpers de test
  emit(obj: any) {
    this.msgCb?.(typeof obj === "string" ? obj : JSON.stringify(obj));
  }
  emitRaw(raw: any) {
    this.msgCb?.(raw);
  }
  triggerClosed() {
    this.closedCb?.();
  }
  // devuelve los mensajes salientes ya parseados
  parsedSent(): any[] {
    return this.sent.map((s) => JSON.parse(s));
  }
  sentOfOp(op: string): any[] {
    return this.parsedSent().filter((m) => m.op === op);
  }
}

function makeSession() {
  const dc = new FakeDataChannel();
  const audits: FileTransferAuditPayload[] = [];
  const teardowns: string[] = [];
  const ctx: any = {
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} }
  };
  const session = new FileSession(dc as any, {
    sessionId: "sess-file-abcdef",
    ctx,
    sendFileTransferAudit: (a) => audits.push(a),
    onTeardown: (r) => teardowns.push(r)
  });
  return { dc, audits, teardowns, session };
}

/**
 * Sesión cuyo tenant BAJA el tope de subida.
 *
 * ⚠️ El doble se tipa contra la clase REAL. La versión anterior inventaba un
 * `getFeatureValue` que `PolicyRuntime` no ha tenido nunca: el test pasaba, el
 * llamador recibía `undefined` dentro de un `try`, y el tope por política era
 * código muerto en producción mientras aquí salía verde.
 *
 * Con este `Pick`, renombrar o borrar el método rompe la COMPILACIÓN del test
 * en vez de dejarlo pasando contra un mundo que no existe.
 */
function makeSessionWithLimit(maxBytes: number) {
  const dc = new FakeDataChannel();
  const audits: FileTransferAuditPayload[] = [];
  const policyRuntime: Pick<PolicyRuntime, "remoteFileMaxUploadBytes"> = {
    remoteFileMaxUploadBytes: () => maxBytes
  };
  const ctx: any = {
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    policyRuntime
  };
  const session = new FileSession(dc as any, {
    sessionId: "sess-file-limit",
    ctx,
    sendFileTransferAudit: (a) => audits.push(a),
    onTeardown: () => {}
  });
  return { dc, audits, session };
}

let tmpDir: string;
beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rcp-file-test-"));
  vi.clearAllMocks();
});
afterEach(() => {
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {}
});

// Los handlers de FileSession son async y usan fs real (readdir/stat/open/
// read/rename): completarlos requiere ciclos reales de IO, no sólo
// setImmediate. `waitFor` sondea hasta que la condición se cumple o vence
// el plazo, evitando carreras sin acoplar a un nº fijo de ticks.
async function waitFor(cond: () => boolean, timeoutMs = 2000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) return; // deja que el assert falle con detalle
    await new Promise((r) => setTimeout(r, 5));
  }
}

// Para asserts de AUSENCIA de salida: da un margen fijo para que cualquier
// handler (síncrono o async) hubiera tenido oportunidad de responder.
async function settle(): Promise<void> {
  await new Promise((r) => setTimeout(r, 30));
}

describe("RCP file protocol — list", () => {
  it("responde 'listing' con directorios primero y luego alfabético", async () => {
    fs.mkdirSync(path.join(tmpDir, "zeta-dir"));
    fs.mkdirSync(path.join(tmpDir, "alpha-dir"));
    fs.writeFileSync(path.join(tmpDir, "b-file.txt"), "hello");
    fs.writeFileSync(path.join(tmpDir, "a-file.txt"), "hi");

    const { dc } = makeSession();
    dc.emit({ op: "list", path: tmpDir });
    await waitFor(() => dc.sentOfOp("listing").length > 0);

    const listing = dc.sentOfOp("listing")[0];
    expect(listing).toBeDefined();
    const names = listing.entries.map((e: any) => e.name);
    expect(names).toEqual(["alpha-dir", "zeta-dir", "a-file.txt", "b-file.txt"]);
    // metadatos por entrada
    const dir = listing.entries.find((e: any) => e.name === "alpha-dir");
    const file = listing.entries.find((e: any) => e.name === "b-file.txt");
    expect(dir.isDir).toBe(true);
    expect(dir.size).toBeNull();
    expect(file.isDir).toBe(false);
    expect(file.size).toBe(5); // "hello"
    expect(typeof file.modifiedAt).toBe("string");
  });

  it("list de un directorio inexistente emite { op:'error', code:'LIST_FAILED' }", async () => {
    const { dc } = makeSession();
    dc.emit({ op: "list", path: path.join(tmpDir, "does-not-exist") });
    await waitFor(() => dc.sentOfOp("error").length > 0);

    const err = dc.sentOfOp("error")[0];
    expect(err).toBeDefined();
    expect(err.code).toBe("LIST_FAILED");
  });
});

describe("RCP file protocol — download", () => {
  it("descarga un archivo pequeño en un chunk base64 con done=true + audit started/completed", async () => {
    const filePath = path.join(tmpDir, "small.bin");
    const content = Buffer.from("the quick brown fox");
    fs.writeFileSync(filePath, content);

    const { dc, audits } = makeSession();
    dc.emit({ op: "download", transferId: "t1", path: filePath });
    await waitFor(() => audits.some((a) => a.status === "completed"));

    const chunks = dc.sentOfOp("chunk");
    expect(chunks.length).toBe(1);
    expect(chunks[0].transferId).toBe("t1");
    expect(chunks[0].done).toBe(true);
    expect(Buffer.from(chunks[0].data, "base64").toString()).toBe(
      content.toString()
    );

    const started = audits.find((a) => a.status === "started");
    const completed = audits.find((a) => a.status === "completed");
    expect(started).toBeDefined();
    expect(completed).toBeDefined();
    expect(completed!.direction).toBe("download");
    expect(completed!.transferredBytes).toBe(content.length);
  });

  it("archivo mayor que CHUNK_SIZE (32KiB) se parte en varios chunks; sólo el último done", async () => {
    const filePath = path.join(tmpDir, "big.bin");
    const content = Buffer.alloc(32 * 1024 + 100, 7); // > 1 chunk
    fs.writeFileSync(filePath, content);

    const { dc, audits } = makeSession();
    dc.emit({ op: "download", transferId: "t2", path: filePath });
    await waitFor(() => audits.some((a) => a.status === "completed"));

    const chunks = dc.sentOfOp("chunk");
    expect(chunks.length).toBe(2);
    expect(chunks[0].done).toBe(false);
    expect(chunks[1].done).toBe(true);
    // seq incremental
    expect(chunks.map((c) => c.seq)).toEqual([0, 1]);
    // round-trip total
    const total = Buffer.concat(
      chunks.map((c) => Buffer.from(c.data, "base64"))
    );
    expect(total.length).toBe(content.length);
  });

  it("download de path inexistente ⇒ audit failed + { op:'error', code:'DOWNLOAD_FAILED' }", async () => {
    const { dc, audits } = makeSession();
    dc.emit({ op: "download", transferId: "t3", path: path.join(tmpDir, "ghost") });
    await waitFor(() => dc.sentOfOp("error").length > 0);

    expect(audits.some((a) => a.status === "failed")).toBe(true);
    const err = dc.sentOfOp("error")[0];
    expect(err.code).toBe("DOWNLOAD_FAILED");
    expect(err.transferId).toBe("t3");
  });
});

describe("RCP file protocol — upload", () => {
  it("upload → ready, chunks, uploadDone materializa el archivo y audita completed", async () => {
    const dest = path.join(tmpDir, "nested", "out.txt");
    const payload = Buffer.from("uploaded content here");

    const { dc, audits } = makeSession();
    dc.emit({
      op: "upload",
      transferId: "u1",
      path: dest,
      name: "out.txt",
      size: payload.length
    });
    await waitFor(() => dc.sentOfOp("ready").length > 0);

    // el agente confirma readiness
    expect(dc.sentOfOp("ready")[0]).toBeDefined();
    expect(audits.some((a) => a.direction === "upload" && a.status === "started")).toBe(
      true
    );

    dc.emit({
      op: "chunk",
      transferId: "u1",
      seq: 0,
      data: payload.toString("base64")
    });
    dc.emit({ op: "uploadDone", transferId: "u1" });
    await waitFor(() =>
      audits.some((a) => a.direction === "upload" && a.status === "completed")
    );

    // archivo materializado en destino (mkdir recursivo del dir padre)
    expect(fs.existsSync(dest)).toBe(true);
    expect(fs.readFileSync(dest).toString()).toBe(payload.toString());

    const completed = audits.find(
      (a) => a.direction === "upload" && a.status === "completed"
    );
    expect(completed).toBeDefined();
    expect(completed!.transferredBytes).toBe(payload.length);
  });

  it("⚠️ confirma el final al navegador, con bytes y digest", async () => {
    // Antes NADIE decía que el fichero estuviera en su sitio: el navegador
    // se marcaba "Completado" al mandar su último trozo, que solo prueba que
    // los bytes salieron del navegador. Con el canal cerrado los descartaba
    // en silencio, así que un fichero truncado se auditaba como completado.
    const dest = path.join(tmpDir, "confirmed.txt");
    const payload = Buffer.from("hola mundo");
    const sha = crypto.createHash("sha256").update(payload).digest("hex");

    const { dc } = makeSession();
    dc.emit({ op: "upload", transferId: "ok1", path: dest, name: "confirmed.txt", size: payload.length });
    await waitFor(() => dc.sentOfOp("ready").length > 0);
    dc.emit({ op: "chunk", transferId: "ok1", seq: 0, data: payload.toString("base64") });
    dc.emit({ op: "uploadDone", transferId: "ok1" });
    await waitFor(() => dc.sentOfOp("uploadComplete").length > 0);

    const done = dc.sentOfOp("uploadComplete")[0];
    expect(done.bytes).toBe(payload.length);
    // El digest es de lo que se ESCRIBIÓ, no de lo que hay en disco después:
    // releer el fichero mediría lo que otro haya podido dejar ahí.
    expect(done.sha256).toBe(sha);
  });

  it("⚠️ un upload corto se rechaza en vez de auditarse como completado", async () => {
    // El fallo real que esto cierra: al navegador se le caían trozos y el
    // fichero se renombraba a su destino igualmente. Quien restaurase una
    // configuración desde ese expediente restauraría una versión truncada.
    const dest = path.join(tmpDir, "short.txt");
    const { dc, audits } = makeSession();
    dc.emit({ op: "upload", transferId: "s1", path: dest, name: "short.txt", size: 100 });
    await waitFor(() => dc.sentOfOp("ready").length > 0);
    dc.emit({ op: "chunk", transferId: "s1", seq: 0, data: Buffer.from("solo 6").toString("base64") });
    dc.emit({ op: "uploadDone", transferId: "s1" });
    await waitFor(() => audits.some((a) => a.status === "failed"));

    expect(fs.existsSync(dest)).toBe(false);
    const failed = audits.find((a) => a.direction === "upload" && a.status === "failed");
    expect(failed!.errorMessage).toMatch(/incomplete/i);
    expect(dc.sentOfOp("uploadComplete")).toHaveLength(0);
    expect(dc.sentOfOp("error").some((e) => e.code === "UPLOAD_INCOMPLETE")).toBe(true);
  });

  it("⚠️ el tope viaja con las raíces, para que el navegador pueda parar antes", async () => {
    // Sin esto, la única forma de saber que un fichero es demasiado grande
    // era mandarlo entero y que el agente lo rechazara: minutos de subida
    // para un "no".
    const { dc } = makeSessionWithLimit(1024);
    dc.emit({ op: "roots" });
    await waitFor(() => dc.sentOfOp("roots").length > 0);
    expect(dc.sentOfOp("roots")[0].maxUploadBytes).toBe(1024);
  });

  it("⚠️ el tope de la política SOLO puede bajar el techo del agente", async () => {
    // Un límite que existe para acotar daño deja de serlo en cuanto lo puede
    // ensanchar aquello que acota.
    const { dc } = makeSessionWithLimit(999 * 1024 * 1024 * 1024);
    dc.emit({ op: "roots" });
    await waitFor(() => dc.sentOfOp("roots").length > 0);
    expect(dc.sentOfOp("roots")[0].maxUploadBytes).toBe(2 * 1024 * 1024 * 1024);
  });

  it("⚠️ rechaza un fichero mayor que el tope antes de abrir nada en disco", async () => {
    const dest = path.join(tmpDir, "huge.bin");
    const { dc, audits } = makeSession();
    dc.emit({
      op: "upload",
      transferId: "big1",
      path: dest,
      name: "huge.bin",
      size: 4 * 1024 * 1024 * 1024
    });
    await waitFor(() => dc.sentOfOp("error").length > 0);

    expect(dc.sentOfOp("error")[0].code).toBe("UPLOAD_TOO_LARGE");
    expect(dc.sentOfOp("ready")).toHaveLength(0);
    expect(audits.some((a) => a.status === "failed")).toBe(true);
  });

  it("⚠️ un tamaño declarado en falso no sirve para llenar el disco", async () => {
    // El tope del arranque confía en un número del navegador. Este NO: se
    // vuelve a comprobar contra lo que de verdad va llegando.
    const dest = path.join(tmpDir, "liar.bin");
    // Tope bajado por política a 1 KB; el navegador declara 10 bytes y manda 2 KB.
    const { dc, audits } = makeSessionWithLimit(1024);
    dc.emit({ op: "upload", transferId: "l1", path: dest, name: "liar.bin", size: 10 });
    await waitFor(() => dc.sentOfOp("ready").length > 0);
    dc.emit({
      op: "chunk",
      transferId: "l1",
      seq: 0,
      data: Buffer.alloc(2048, 0x41).toString("base64")
    });
    await waitFor(() => dc.sentOfOp("error").length > 0);

    expect(dc.sentOfOp("error")[0].code).toBe("UPLOAD_TOO_LARGE");
    expect(fs.existsSync(dest)).toBe(false);
    expect(audits.some((a) => a.status === "failed")).toBe(true);
  });

  it("chunk de un transferId de upload desconocido es ignorado (no revienta)", async () => {
    const { dc } = makeSession();
    expect(() =>
      dc.emit({ op: "chunk", transferId: "unknown", seq: 0, data: "AAAA" })
    ).not.toThrow();
  });
});

describe("RCP file protocol — cancel", () => {
  it("cancel de un upload en curso ⇒ uploadDone lo audita como 'cancelled' y NO materializa", async () => {
    const dest = path.join(tmpDir, "cancelled.txt");

    const { dc, audits } = makeSession();
    dc.emit({ op: "upload", transferId: "c1", path: dest, name: "x", size: 10 });
    await waitFor(() => dc.sentOfOp("ready").length > 0);
    dc.emit({ op: "chunk", transferId: "c1", seq: 0, data: Buffer.from("half").toString("base64") });
    dc.emit({ op: "cancel", transferId: "c1" });
    dc.emit({ op: "uploadDone", transferId: "c1" });
    await waitFor(() =>
      audits.some((a) => a.direction === "upload" && a.status === "cancelled")
    );

    expect(fs.existsSync(dest)).toBe(false);
    const cancelled = audits.find(
      (a) => a.direction === "upload" && a.status === "cancelled"
    );
    expect(cancelled).toBeDefined();
  });
});

describe("RCP file protocol — mensajes malformados", () => {
  it("JSON inválido no revienta la sesión ni produce salida", async () => {
    const { dc } = makeSession();
    expect(() => dc.emitRaw("{ not json at all")).not.toThrow();
    expect(dc.sent.length).toBe(0);
  });

  it("op desconocida se ignora silenciosamente (debug), sin respuesta", async () => {
    const { dc } = makeSession();
    dc.emit({ op: "teleport", target: "mars" });
    await settle();
    expect(dc.sent.length).toBe(0);
  });

  // Antes era un no-op silencioso. Desde que transferId se valida en la
  // frontera del protocolo (es parte del nombre del fichero de staging),
  // un id ausente o malformado se rechaza explícitamente: al cliente le
  // sirve más saber que su mensaje era inválido que ver silencio.
  it("download sin transferId se rechaza y no toca el disco", async () => {
    const { dc, audits } = makeSession();
    dc.emit({ op: "download", path: "/whatever" });
    await settle();
    expect(audits.length).toBe(0);
    expect(dc.sentOfOp("chunk")).toHaveLength(0);
    expect(dc.sentOfOp("error")[0]?.code).toBe("INVALID_TRANSFER_ID");
  });

  it("mensaje sin 'op' se trata como op vacía y cae al default (no-op)", async () => {
    const { dc } = makeSession();
    dc.emit({ transferId: "x", data: "y" });
    await settle();
    expect(dc.sent.length).toBe(0);
  });

  it("onClosed del canal dispara teardown y limpia uploads en curso", async () => {
    const dest = path.join(tmpDir, "wip.txt");
    const { dc, teardowns } = makeSession();
    dc.emit({ op: "upload", transferId: "w1", path: dest, name: "x", size: 100 });
    await waitFor(() => dc.sentOfOp("ready").length > 0);

    dc.triggerClosed();
    await waitFor(() => teardowns.length > 0);

    expect(teardowns).toContain("data_channel_closed");
  });
});

// ── Confinement wiring ─────────────────────────────────────────────────
//
// path-jail.ts is unit-tested exhaustively in rcp-path-jail.test.ts. What
// these cover is the thing that test cannot: that FileSession actually
// CALLS the jail at every filesystem call site, and keeps calling it as the
// protocol grows. A new op that forgets the gate is the regression this
// guards against.
describe("RCP file protocol — path confinement", () => {
  // A jail rooted at tmpDir only. Nothing else on the host is reachable,
  // which lets us use a real absolute path (/etc) as the escape target.
  function makeConfinedSession(roots: string[]) {
    const dc = new FakeDataChannel();
    const audits: FileTransferAuditPayload[] = [];
    const ctx: any = {
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      policyRuntime: { getRcpFileJailConfig: () => ({ roots }) }
    };
    const session = new FileSession(dc as any, {
      sessionId: "sess-jail-abcdef",
      ctx,
      sendFileTransferAudit: (a) => audits.push(a),
      onTeardown: () => {}
    });
    return { dc, audits, session };
  }

  it("announces its roots so the browser knows where it may start", async () => {
    const { dc } = makeConfinedSession([tmpDir]);
    dc.emit({ op: "roots" });
    await settle();
    const reply = dc.sentOfOp("roots")[0];
    expect(reply).toBeDefined();
    expect(reply.roots.length).toBe(1);
    // Real path — on macOS tmpDir resolves through /private.
    expect(reply.roots[0].endsWith(path.basename(tmpDir))).toBe(true);
  });

  it("refuses to list outside the roots", async () => {
    const { dc } = makeConfinedSession([tmpDir]);
    dc.emit({ op: "list", path: "/etc" });
    await settle();
    const err = dc.sentOfOp("error")[0];
    expect(err).toBeDefined();
    expect(err.code).toBe("PATH_OUTSIDE_ROOTS");
    expect(dc.sentOfOp("listing")).toHaveLength(0);
  });

  it("refuses a traversal that climbs out of a root", async () => {
    const { dc } = makeConfinedSession([tmpDir]);
    dc.emit({ op: "list", path: path.join(tmpDir, "..", "..", "..", "etc") });
    await settle();
    expect(dc.sentOfOp("error")[0]?.code).toBe("PATH_OUTSIDE_ROOTS");
  });

  it("refuses a download outside the roots AND records it as a failed transfer", async () => {
    const { dc, audits } = makeConfinedSession([tmpDir]);
    dc.emit({ op: "download", transferId: "t-esc", path: "/etc/hosts" });
    await waitFor(() => audits.length > 0);
    expect(dc.sentOfOp("error")[0]?.code).toBe("PATH_OUTSIDE_ROOTS");
    expect(dc.sentOfOp("chunk")).toHaveLength(0);
    // The attempt has to leave an audit trail, not just a log line.
    expect(audits).toHaveLength(1);
    expect(audits[0].status).toBe("failed");
    expect(audits[0].direction).toBe("download");
    expect(audits[0].remotePath).toBe("/etc/hosts");
  });

  it("refuses an upload outside the roots without creating a temp file", async () => {
    const { dc, audits } = makeConfinedSession([tmpDir]);
    const before = fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith("rcp-upload-"));
    dc.emit({ op: "upload", transferId: "t-up", path: "/etc/cron.d/pwn", name: "pwn", size: 4 });
    await waitFor(() => audits.length > 0);
    expect(dc.sentOfOp("error")[0]?.code).toBe("PATH_OUTSIDE_ROOTS");
    expect(dc.sentOfOp("ready")).toHaveLength(0);
    expect(audits[0].status).toBe("failed");
    const after = fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith("rcp-upload-"));
    expect(after).toEqual(before);
  });

  it("still allows normal work inside the roots", async () => {
    fs.writeFileSync(path.join(tmpDir, "ok.txt"), "hello");
    const { dc } = makeConfinedSession([tmpDir]);
    dc.emit({ op: "list", path: tmpDir });
    await waitFor(() => dc.sentOfOp("listing").length > 0);
    const listing = dc.sentOfOp("listing")[0];
    expect(listing.entries.map((e: any) => e.name)).toContain("ok.txt");
    expect(dc.sentOfOp("error")).toHaveLength(0);
  });

  it("lets a deny path seal a subtree that sits inside an allowed root", async () => {
    // The shape that matters in production: ProgramData is a useful root,
    // but the agent's own credential directory lives underneath it and must
    // stay unreachable. Deny has to beat roots.
    const agentDir = path.join(tmpDir, "Tracenium", "Agent");
    fs.mkdirSync(agentDir, { recursive: true });
    fs.writeFileSync(path.join(agentDir, "client.key"), "PRIVATE KEY");

    const dc = new FakeDataChannel();
    const ctx: any = {
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      policyRuntime: {
        getRcpFileJailConfig: () => ({
          roots: [tmpDir],
          denyPaths: [path.join(tmpDir, "Tracenium")]
        })
      }
    };
    new FileSession(dc as any, {
      sessionId: "sess-deny-abcdef",
      ctx,
      sendFileTransferAudit: () => {},
      onTeardown: () => {}
    });

    dc.emit({
      op: "download",
      transferId: "t-cred",
      path: path.join(agentDir, "client.key")
    });
    await settle();
    expect(dc.sentOfOp("error")[0]?.code).toBe("PATH_DENIED");
    expect(dc.sentOfOp("chunk")).toHaveLength(0);

    // …while a sibling inside the same root stays reachable.
    fs.writeFileSync(path.join(tmpDir, "reachable.txt"), "ok");
    dc.emit({ op: "list", path: tmpDir });
    await waitFor(() => dc.sentOfOp("listing").length > 0);
    expect(dc.sentOfOp("listing")[0].entries.map((e: any) => e.name)).toContain(
      "reachable.txt"
    );
  });
});

// ── Upload staging safety ──────────────────────────────────────────────
//
// The destination jail (path-jail.ts) guards `path`. The staging file is a
// SECOND filesystem write with a SECOND attacker-influenced input — the
// transfer id — and it is not covered by that jail. These cover it.
describe("RCP file protocol — upload staging", () => {
  function makeConfinedSession(roots: string[]) {
    const dc = new FakeDataChannel();
    const audits: FileTransferAuditPayload[] = [];
    const ctx: any = {
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      policyRuntime: { getRcpFileJailConfig: () => ({ roots }) }
    };
    const session = new FileSession(dc as any, {
      sessionId: "sess-stage-abcdef",
      ctx,
      sendFileTransferAudit: (a) => audits.push(a),
      onTeardown: () => {}
    });
    return { dc, audits, session };
  }

  it("refuses a traversal in transferId instead of writing outside staging", async () => {
    // The escape: `path` is perfectly legal so the destination jail passes,
    // and the traversal rides on the id, which used to be interpolated
    // straight into the staging filename.
    const victim = path.join(tmpDir, "victim.txt");
    fs.writeFileSync(victim, "ORIGINAL");

    // The id had "rcp-upload-" glued to its front, so a bare leading "../"
    // stayed a literal segment. The shape that actually escaped is
    // "<anything>/../<path>": the first segment absorbs the prefix and the
    // ".." then cancels it, leaving a path relative to the temp root.
    // Verified against the pre-fix code: the victim's contents went to "".
    const { dc } = makeConfinedSession([tmpDir]);
    dc.emit({
      op: "upload",
      transferId: `x/../${path.relative(os.tmpdir(), victim)}`,
      path: path.join(tmpDir, "innocent.txt"),
      name: "innocent.txt",
      size: 4
    });
    await settle();

    expect(dc.sentOfOp("error")[0]?.code).toBe("INVALID_TRANSFER_ID");
    expect(dc.sentOfOp("ready")).toHaveLength(0);
    // The whole point: the pre-existing file is untouched.
    expect(fs.readFileSync(victim, "utf8")).toBe("ORIGINAL");
  });

  it("rejects ids with separators or NUL regardless of op", async () => {
    const { dc } = makeConfinedSession([tmpDir]);
    for (const bad of ["a/b", "a\\b", "..", "a\0b", "", "x".repeat(65)]) {
      dc.sent.length = 0;
      dc.emit({ op: "chunk", transferId: bad, seq: 0, data: "AAAA" });
      await settle();
      expect(dc.sentOfOp("error")[0]?.code).toBe("INVALID_TRANSFER_ID");
    }
  });

  it("accepts the UUID form the UI actually mints", async () => {
    const { dc } = makeConfinedSession([tmpDir]);
    dc.emit({
      op: "upload",
      transferId: "6f1c2e2a-7b3d-4c1e-9a0f-1b2c3d4e5f60",
      path: path.join(tmpDir, "ok.bin"),
      name: "ok.bin",
      size: 3
    });
    await waitFor(() => dc.sentOfOp("ready").length > 0);
    expect(dc.sentOfOp("ready")[0].transferId).toBe(
      "6f1c2e2a-7b3d-4c1e-9a0f-1b2c3d4e5f60"
    );
    expect(dc.sentOfOp("error")).toHaveLength(0);
  });

  it("stages into a private per-session directory, not the shared temp root", async () => {
    const { dc } = makeConfinedSession([tmpDir]);
    dc.emit({
      op: "upload",
      transferId: "stage-check-1",
      path: path.join(tmpDir, "staged.bin"),
      name: "staged.bin",
      size: 3
    });
    await waitFor(() => dc.sentOfOp("ready").length > 0);

    const staging = fs
      .readdirSync(os.tmpdir())
      .filter((f) => f.startsWith("tracenium-rcp-"));
    expect(staging.length).toBeGreaterThan(0);
    // The old scheme dropped `rcp-upload-<id>` directly in the temp root.
    expect(
      fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith("rcp-upload-"))
    ).toHaveLength(0);

    if (process.platform !== "win32") {
      const mode = fs.statSync(path.join(os.tmpdir(), staging[0])).mode & 0o777;
      expect(mode).toBe(0o700);
    }
  });

  it("removes the staging directory when the channel closes", async () => {
    const { dc } = makeConfinedSession([tmpDir]);
    dc.emit({
      op: "upload",
      transferId: "stage-check-2",
      path: path.join(tmpDir, "gone.bin"),
      name: "gone.bin",
      size: 3
    });
    await waitFor(() => dc.sentOfOp("ready").length > 0);
    const before = fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith("tracenium-rcp-"));
    expect(before.length).toBeGreaterThan(0);

    dc.triggerClosed();
    await settle();
    const after = fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith("tracenium-rcp-"));
    expect(after.length).toBeLessThan(before.length);
  });

  it("still completes a normal upload end to end", async () => {
    const dest = path.join(tmpDir, "sub", "final.txt");
    const { dc, audits } = makeConfinedSession([tmpDir]);
    dc.emit({ op: "upload", transferId: "happy-1", path: dest, name: "final.txt", size: 5 });
    await waitFor(() => dc.sentOfOp("ready").length > 0);
    dc.emit({
      op: "chunk",
      transferId: "happy-1",
      seq: 0,
      data: Buffer.from("hello").toString("base64")
    });
    dc.emit({ op: "uploadDone", transferId: "happy-1" });
    await waitFor(() => audits.some((a) => a.status === "completed"));
    expect(fs.readFileSync(dest, "utf8")).toBe("hello");
  });
});
