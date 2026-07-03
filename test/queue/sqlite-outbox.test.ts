// test/queue/sqlite-outbox.test.ts
//
// P0 — supervivencia de la cola persistente del agente.
// better-sqlite3 REAL sobre archivos en tmpdir (sin mocks de SQLite).
//
// Fronteras mockeadas:
//   - "os": SOLO homedir(). Motivo: sqlite-outbox.ts exporta un singleton
//     `outbox = new SqliteOutbox()` que se construye AL IMPORTAR el módulo
//     usando defaultDbPath() → os.homedir()/.tracenium/agent/outbox.db.
//     Sin este mock, importar el módulo en tests tocaría la DB real del
//     agente en la máquina del desarrollador.
//   - logger: silenciado (ruido de consola).
import { describe, it, expect, beforeEach, afterAll, vi } from "vitest";
import fs from "fs";
import path from "path";
import Database from "better-sqlite3";

vi.mock("../../src/bootstrap/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() }
}));

vi.mock("os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("os")>();
  const fsMod = await vi.importActual<typeof import("fs")>("fs");
  const pathMod = await vi.importActual<typeof import("path")>("path");
  const fakeHome = fsMod.mkdtempSync(
    pathMod.join(actual.tmpdir(), "tracenium-outbox-home-")
  );
  const patched = { ...actual, homedir: () => fakeHome };
  return { ...patched, default: patched };
});

import os from "os";
import { SqliteOutbox } from "../../src/queue/sqlite-outbox";
import type { OutboxEventType } from "../../src/queue/sqlite-outbox";

const MAX_ATTEMPTS = 20; // espejo de la constante privada del módulo

let workDir: string;
let dbPath: string;
const dirsToClean: string[] = [];

function newDbPath(): string {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), "tracenium-outbox-test-"));
  dirsToClean.push(workDir);
  return path.join(workDir, "outbox.db");
}

/** Conexión independiente para setup/inspección (WAL permite multi-conexión). */
function rawDb(p: string = dbPath) {
  return new Database(p);
}

function isoSecondsAgo(secs: number): string {
  return new Date(Date.now() - secs * 1000).toISOString();
}

function enqueueN(outbox: SqliteOutbox, n: number, type: OutboxEventType = "FACTS_SNAPSHOT"): number[] {
  const ids: number[] = [];
  for (let i = 0; i < n; i++) {
    ids.push(outbox.enqueue({ type, payload: { seq: i, marker: `evt-${i}` } }));
  }
  return ids;
}

beforeEach(() => {
  dbPath = newDbPath();
});

afterAll(() => {
  for (const dir of dirsToClean) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  }
});

describe("SqliteOutbox — enqueue / drain FIFO", () => {
  it("leaseReady devuelve los eventos en orden FIFO (id ascendente = orden de inserción)", () => {
    const outbox = new SqliteOutbox(dbPath);
    const ids = enqueueN(outbox, 5);

    const batch = outbox.leaseReady(25);

    expect(batch.map((r) => Number(r.id))).toEqual(ids);
    expect(batch.map((r) => r.payload_json.seq)).toEqual([0, 1, 2, 3, 4]);
    // ids crecientes → inserción FIFO
    expect([...ids].sort((a, b) => a - b)).toEqual(ids);
  });

  it("los eventos leased pasan a IN_FLIGHT con lock_owner y no se vuelven a entregar", () => {
    const outbox = new SqliteOutbox(dbPath);
    enqueueN(outbox, 2);

    const first = outbox.leaseReady(25);
    expect(first).toHaveLength(2);

    const rows = rawDb()
      .prepare("SELECT status, lock_owner FROM outbox_events ORDER BY id")
      .all() as Array<{ status: string; lock_owner: string | null }>;
    expect(rows.every((r) => r.status === "IN_FLIGHT")).toBe(true);
    expect(rows.every((r) => !!r.lock_owner)).toBe(true);

    // Segunda pasada: nada PENDING → vacío
    expect(outbox.leaseReady(25)).toEqual([]);
  });

  it("markSent completa el ciclo: SENT, lock liberado, sent_at_utc estampado", () => {
    const outbox = new SqliteOutbox(dbPath);
    const [id] = enqueueN(outbox, 1);
    outbox.leaseReady(25);

    outbox.markSent(id);

    const row = rawDb()
      .prepare("SELECT status, lock_owner, sent_at_utc FROM outbox_events WHERE id=?")
      .get(id) as any;
    expect(row.status).toBe("SENT");
    expect(row.lock_owner).toBeNull();
    expect(row.sent_at_utc).toBeTruthy();
  });

  it("enqueue deduplica payloads idénticos del mismo tipo mientras están PENDING/IN_FLIGHT", () => {
    const outbox = new SqliteOutbox(dbPath);
    const id1 = outbox.enqueue({ type: "FACTS_SNAPSHOT", payload: { a: 1 } });
    const id2 = outbox.enqueue({ type: "FACTS_SNAPSHOT", payload: { a: 1 } });
    expect(id2).toBe(id1);

    // Distinto tipo con mismo payload NO deduplica
    const id3 = outbox.enqueue({ type: "JOB_RESULT", payload: { a: 1 } });
    expect(id3).not.toBe(id1);
  });

  it("payloads > 50KB se comprimen en disco (gz:) y el drain los devuelve intactos", () => {
    const outbox = new SqliteOutbox(dbPath);
    const big = { blob: "x".repeat(120 * 1024), tag: "compress-me" };
    const id = outbox.enqueue({ type: "FACTS_SNAPSHOT", payload: big });

    const stored = rawDb()
      .prepare("SELECT payload_json FROM outbox_events WHERE id=?")
      .get(id) as { payload_json: string };
    expect(stored.payload_json.startsWith("gz:")).toBe(true);

    const [row] = outbox.leaseReady(25);
    expect(row.payload_json).toEqual(big);
  });
});

describe("SqliteOutbox — respeto del límite de lease (MAX_IN_FLIGHT = 3)", () => {
  it("leaseReady(3) entrega exactamente 3 y deja el resto PENDING", () => {
    const outbox = new SqliteOutbox(dbPath);
    const ids = enqueueN(outbox, 5);

    const batch = outbox.leaseReady(3); // MAX_IN_FLIGHT en grpc-stream.ts
    expect(batch.map((r) => Number(r.id))).toEqual(ids.slice(0, 3));

    const statuses = rawDb()
      .prepare("SELECT id, status FROM outbox_events ORDER BY id")
      .all() as Array<{ id: number; status: string }>;
    expect(statuses.map((s) => s.status)).toEqual([
      "IN_FLIGHT", "IN_FLIGHT", "IN_FLIGHT", "PENDING", "PENDING"
    ]);
  });

  it("el siguiente lease entrega los restantes en orden, sin repetir los IN_FLIGHT", () => {
    const outbox = new SqliteOutbox(dbPath);
    const ids = enqueueN(outbox, 5);

    outbox.leaseReady(3);
    const second = outbox.leaseReady(3);
    expect(second.map((r) => Number(r.id))).toEqual(ids.slice(3));
  });
});

describe("SqliteOutbox — recoverStaleInflight", () => {
  it("in-flight más viejos que el TTL vuelven a PENDING con attempts+1 y backoff futuro", () => {
    const outbox = new SqliteOutbox(dbPath);
    const ids = enqueueN(outbox, 2);
    outbox.leaseReady(25);

    // Simular que el lock quedó de una corrida anterior (>600s)
    rawDb()
      .prepare("UPDATE outbox_events SET locked_at_utc=? WHERE id=?")
      .run(isoSecondsAgo(700), ids[0]);

    outbox.recoverStaleInflight(600);

    const stale = rawDb()
      .prepare("SELECT status, attempts, lock_owner, next_attempt_at_utc FROM outbox_events WHERE id=?")
      .get(ids[0]) as any;
    expect(stale.status).toBe("PENDING");
    expect(stale.attempts).toBe(1);
    expect(stale.lock_owner).toBeNull();
    // next_attempt con backoff: attempt=1 → 30s + jitter[0,10) desde ahora
    const deltaSecs = (new Date(stale.next_attempt_at_utc).getTime() - Date.now()) / 1000;
    expect(deltaSecs).toBeGreaterThan(25);
    expect(deltaSecs).toBeLessThan(45);

    // El in-flight FRESCO no se toca
    const fresh = rawDb()
      .prepare("SELECT status FROM outbox_events WHERE id=?")
      .get(ids[1]) as any;
    expect(fresh.status).toBe("IN_FLIGHT");
  });

  it("al arrancar (constructor) recupera automáticamente los in-flight viejos", () => {
    const outbox = new SqliteOutbox(dbPath);
    const [id] = enqueueN(outbox, 1);
    outbox.leaseReady(25);
    rawDb()
      .prepare("UPDATE outbox_events SET locked_at_utc=? WHERE id=?")
      .run(isoSecondsAgo(3600), id);

    // Nuevo proceso: abrir la misma DB → initialize() → recoverStaleInflight(600)
    new SqliteOutbox(dbPath);

    const row = rawDb()
      .prepare("SELECT status, attempts, lock_owner FROM outbox_events WHERE id=?")
      .get(id) as any;
    expect(row.status).toBe("PENDING");
    expect(row.attempts).toBe(1);
    expect(row.lock_owner).toBeNull();
  });

  it("un stale que ya agotó los intentos pasa a FAILED, no a PENDING", () => {
    const outbox = new SqliteOutbox(dbPath);
    const [id] = enqueueN(outbox, 1);
    outbox.leaseReady(25);
    rawDb()
      .prepare("UPDATE outbox_events SET locked_at_utc=?, attempts=? WHERE id=?")
      .run(isoSecondsAgo(700), MAX_ATTEMPTS - 1, id);

    outbox.recoverStaleInflight(600);

    const row = rawDb()
      .prepare("SELECT status, attempts, last_error FROM outbox_events WHERE id=?")
      .get(id) as any;
    expect(row.status).toBe("FAILED");
    expect(row.attempts).toBe(MAX_ATTEMPTS);
    expect(row.last_error).toBe("stale inflight exceeded max attempts");
  });
});

describe("SqliteOutbox — markFailed (reintentos con backoff)", () => {
  it("reintento: PENDING con attempts+1 y next_attempt dentro del rango de backoff", () => {
    const outbox = new SqliteOutbox(dbPath);
    const [id] = enqueueN(outbox, 1);
    outbox.leaseReady(25);

    outbox.markFailed(id, "network boom");

    const row = rawDb()
      .prepare("SELECT status, attempts, next_attempt_at_utc, last_error FROM outbox_events WHERE id=?")
      .get(id) as any;
    expect(row.status).toBe("PENDING");
    expect(row.attempts).toBe(1);
    expect(row.last_error).toBe("network boom");
    // attempt=1 → base 30 * 2^0 = 30s + jitter [0,10)
    const deltaSecs = (new Date(row.next_attempt_at_utc).getTime() - Date.now()) / 1000;
    expect(deltaSecs).toBeGreaterThanOrEqual(28); // margen por redondeo de reloj
    expect(deltaSecs).toBeLessThan(41);
  });

  it("al llegar a MAX_ATTEMPTS el evento pasa a FAILED terminal", () => {
    const outbox = new SqliteOutbox(dbPath);
    const [id] = enqueueN(outbox, 1);
    outbox.leaseReady(25);
    rawDb()
      .prepare("UPDATE outbox_events SET attempts=? WHERE id=?")
      .run(MAX_ATTEMPTS - 1, id);

    outbox.markFailed(id, "last straw");

    const row = rawDb()
      .prepare("SELECT status, attempts FROM outbox_events WHERE id=?")
      .get(id) as any;
    expect(row.status).toBe("FAILED");
    expect(row.attempts).toBe(MAX_ATTEMPTS);
  });

  it("los PENDING con next_attempt en el futuro no se entregan hasta que venza el backoff", () => {
    const outbox = new SqliteOutbox(dbPath);
    const [id] = enqueueN(outbox, 1);
    outbox.leaseReady(25);
    outbox.markFailed(id, "retry later");

    // Todavía en backoff → no ready
    expect(outbox.leaseReady(25)).toEqual([]);

    // Vencer el backoff manualmente → vuelve a salir
    rawDb()
      .prepare("UPDATE outbox_events SET next_attempt_at_utc=? WHERE id=?")
      .run(isoSecondsAgo(1), id);
    expect(outbox.leaseReady(25).map((r) => Number(r.id))).toEqual([id]);
  });
});

describe("SqliteOutbox — cleanup periódico", () => {
  it("borra SENT viejos y FAILED viejos; conserva SENT recientes y PENDING", () => {
    const outbox = new SqliteOutbox(dbPath);
    const ids = enqueueN(outbox, 4);
    const [oldSent, recentSent, oldFailed, pending] = ids;
    const db = rawDb();

    const fifteenDaysAgo = isoSecondsAgo(15 * 86400);
    db.prepare("UPDATE outbox_events SET status='SENT', sent_at_utc=? WHERE id=?")
      .run(fifteenDaysAgo, oldSent);
    db.prepare("UPDATE outbox_events SET status='SENT', sent_at_utc=? WHERE id=?")
      .run(isoSecondsAgo(3600), recentSent);
    db.prepare("UPDATE outbox_events SET status='FAILED', created_at_utc=? WHERE id=?")
      .run(fifteenDaysAgo, oldFailed);
    // `pending` queda PENDING con created_at reciente

    outbox.cleanup(14);

    const remaining = db
      .prepare("SELECT id FROM outbox_events ORDER BY id")
      .all() as Array<{ id: number }>;
    expect(remaining.map((r) => r.id)).toEqual([recentSent, pending]);
  });

  it("un PENDING viejísimo NO se borra (cleanup sólo toca SENT/FAILED)", () => {
    const outbox = new SqliteOutbox(dbPath);
    const [id] = enqueueN(outbox, 1);
    rawDb()
      .prepare("UPDATE outbox_events SET created_at_utc=? WHERE id=?")
      .run(isoSecondsAgo(365 * 86400), id);

    outbox.cleanup(14);

    const row = rawDb().prepare("SELECT status FROM outbox_events WHERE id=?").get(id) as any;
    expect(row.status).toBe("PENDING");
  });
});

describe("SqliteOutbox — DB corrupta (auto-healing, BUG A2)", () => {
  // FIX A2 — self-healing ante corrupción del archivo.
  //
  // Antes: better-sqlite3 abre perezosamente y el primer PRAGMA lanzaba
  // SQLITE_NOTADB → como el singleton `outbox` se construye AL IMPORTAR el
  // módulo, un outbox.db corrupto (corte de energía + WAL roto) crasheaba el
  // agente en boot → boot-loop infinito (service manager reinicia y vuelve a
  // crashear).
  //
  // Ahora: al abrir se corre `PRAGMA integrity_check`; si la apertura/verif.
  // detecta corrupción, el archivo (y sus sidecars -wal/-shm) se ponen en
  // CUARENTENA (renombrados, NO borrados) y se recrea una DB vacía → el
  // constructor NO lanza y el outbox queda operativo.

  function writeGarbage(p: string) {
    fs.writeFileSync(
      p,
      Buffer.concat([
        Buffer.from("NOT A SQLITE FILE - garbage header"),
        Buffer.alloc(4096, 0xff)
      ])
    );
  }

  it("un archivo corrupto NO lanza: se pone en cuarentena y se recrea una DB fresca operativa", () => {
    const corruptPath = path.join(workDir, "corrupt.db");
    writeGarbage(corruptPath);

    let outbox: SqliteOutbox | null = null;
    let thrown: any = null;
    try {
      outbox = new SqliteOutbox(corruptPath); // NO debe lanzar
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeNull();
    expect(outbox).toBeTruthy();

    // Cuarentena: el archivo corrupto fue renombrado a corrupt-<timestamp>,
    // preservado para forensics (no borrado).
    const quarantined = fs
      .readdirSync(workDir)
      .filter((f) => f.startsWith("corrupt.db.corrupt-"));
    expect(quarantined).toHaveLength(1);
    // El contenido basura original se preservó intacto.
    const preserved = fs.readFileSync(path.join(workDir, quarantined[0]));
    expect(preserved.subarray(0, 5).toString()).toBe("NOT A");

    // DB fresca en la ruta original: es una SQLite válida y vacía.
    expect(fs.existsSync(corruptPath)).toBe(true);
    const count = rawDb(corruptPath)
      .prepare("SELECT COUNT(*) AS n FROM outbox_events")
      .get() as { n: number };
    expect(count.n).toBe(0);

    // Y el outbox quedó funcional: enqueue + drain operan.
    const id = outbox!.enqueue({ type: "FACTS_SNAPSHOT", payload: { after: "heal" } });
    const batch = outbox!.leaseReady(25);
    expect(batch.map((r) => Number(r.id))).toEqual([id]);
    expect(batch[0].payload_json).toEqual({ after: "heal" });
  });

  it("no arrastra estado inconsistente de los sidecars -wal/-shm viejos a la DB recreada", () => {
    // Nota: al abrir un archivo con header basura, la propia SQLite descarta
    // los sidecars preexistentes (los trata como huérfanos de una DB nueva),
    // así que puede que no lleguen al paso de cuarentena. Lo que importa —y lo
    // que este test garantiza— es que el contenido viejo del -wal/-shm NO
    // sobreviva en la ruta activa hacia la DB recreada.
    const corruptPath = path.join(workDir, "sidecars.db");
    writeGarbage(corruptPath);
    fs.writeFileSync(`${corruptPath}-wal`, Buffer.from("stale wal contents"));
    fs.writeFileSync(`${corruptPath}-shm`, Buffer.from("stale shm contents"));

    let outbox: SqliteOutbox | null = null;
    expect(() => {
      outbox = new SqliteOutbox(corruptPath);
    }).not.toThrow();

    // El contenido viejo del WAL/SHM no debe quedar en la ruta activa.
    const walNow = fs.existsSync(`${corruptPath}-wal`)
      ? fs.readFileSync(`${corruptPath}-wal`).toString()
      : "";
    const shmNow = fs.existsSync(`${corruptPath}-shm`)
      ? fs.readFileSync(`${corruptPath}-shm`).toString()
      : "";
    expect(walNow).not.toContain("stale wal contents");
    expect(shmNow).not.toContain("stale shm contents");

    // El archivo principal corrupto sí queda en cuarentena para forensics.
    const quarantinedMain = fs
      .readdirSync(workDir)
      .filter((f) => /^sidecars\.db\.corrupt-/.test(f));
    expect(quarantinedMain).toHaveLength(1);

    // Y la DB recreada es funcional.
    const id = outbox!.enqueue({ type: "FACTS_SNAPSHOT", payload: { fresh: true } });
    expect(outbox!.leaseReady(25).map((r) => Number(r.id))).toEqual([id]);
  });

  it("una DB sana existente con datos NO se pone en cuarentena (no hay falsos positivos)", () => {
    // Primera vida: crear DB válida con un evento encolado.
    const healthyPath = path.join(workDir, "healthy.db");
    const first = new SqliteOutbox(healthyPath);
    const id = first.enqueue({ type: "FACTS_SNAPSHOT", payload: { keep: "me" } });

    // Segunda apertura (nuevo proceso simulado) sobre la MISMA DB sana.
    const second = new SqliteOutbox(healthyPath);

    // No se generó ningún archivo de cuarentena.
    const quarantined = fs
      .readdirSync(workDir)
      .filter((f) => f.startsWith("healthy.db.corrupt-"));
    expect(quarantined).toHaveLength(0);

    // Los datos previos siguen ahí y son legibles.
    const batch = second.leaseReady(25);
    expect(batch.map((r) => Number(r.id))).toEqual([id]);
    expect(batch[0].payload_json).toEqual({ keep: "me" });
  });
});

describe("SqliteOutbox — estado auxiliar", () => {
  it("getState/setState hacen upsert y round-trip", () => {
    const outbox = new SqliteOutbox(dbPath);
    expect(outbox.getState("k")).toBeNull();
    outbox.setState("k", "v1");
    expect(outbox.getState("k")).toBe("v1");
    outbox.setState("k", "v2");
    expect(outbox.getState("k")).toBe("v2");
  });

  it("getNextReadyDelayMs: 0 si hay un PENDING vencido, >0 si está en backoff, null si no hay nada", () => {
    const outbox = new SqliteOutbox(dbPath);
    expect(outbox.getNextReadyDelayMs()).toBeNull();

    const [id] = enqueueN(outbox, 1);
    expect(outbox.getNextReadyDelayMs()).toBe(0);

    rawDb()
      .prepare("UPDATE outbox_events SET next_attempt_at_utc=? WHERE id=?")
      .run(new Date(Date.now() + 60_000).toISOString(), id);
    const delay = outbox.getNextReadyDelayMs();
    expect(delay).toBeGreaterThan(50_000);
    expect(delay).toBeLessThanOrEqual(60_000);
  });

  it("onChanged notifica en enqueue y la desuscripción funciona", () => {
    const outbox = new SqliteOutbox(dbPath);
    const cb = vi.fn();
    const off = outbox.onChanged(cb);

    outbox.enqueue({ type: "FACTS_SNAPSHOT", payload: { x: 1 } });
    expect(cb).toHaveBeenCalledTimes(1);

    off();
    outbox.enqueue({ type: "FACTS_SNAPSHOT", payload: { x: 2 } });
    expect(cb).toHaveBeenCalledTimes(1);
  });
});
