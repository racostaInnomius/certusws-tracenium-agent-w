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

import { FileSession } from "../../src/plugins/rcp/file-session";
import type { FileTransferAuditPayload } from "../../src/plugins/rcp/file-session";

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

  it("download sin transferId es no-op (guard temprano)", async () => {
    const { dc, audits } = makeSession();
    dc.emit({ op: "download", path: "/whatever" });
    await settle();
    expect(audits.length).toBe(0);
    expect(dc.sent.length).toBe(0);
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
