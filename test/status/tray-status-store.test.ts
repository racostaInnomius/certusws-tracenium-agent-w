// test/status/tray-status-store.test.ts
//
// Regression coverage for TrayStatusStore's markJobStarted/markJobFinished
// — specifically the `jobs.current` tracking added so the tray apps can
// show an "Active Job" tab and a menu-bar badge while a job is running.
// No test existed for this store before.
//
// Uses a real temp directory (mkdtempSync) rather than mocking `fs` —
// TrayStatusStore does real file I/O (write-to-tmp + rename) and that
// behavior (atomic-ish writes, JSON round-trip) is part of what's worth
// verifying, not incidental plumbing to stub out.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

let tmpDir: string;
let statusDir: string;

vi.mock("../../src/bootstrap/paths", () => ({
  ensureAgentStatusDir: () => {
    fs.mkdirSync(statusDir, { recursive: true });
    return statusDir;
  },
  getTrayStatusFilePath: () => path.join(statusDir, "tray-status.json"),
  getLegacyAgentStatusDir: () => null,
}));

vi.mock("../../src/plugins/pmp/state", () => ({
  loadPmpState: () => ({ status: undefined, rebootRequired: undefined, lastError: undefined }),
}));

vi.mock("../../src/update/update-state", () => ({
  loadUpdateState: () => ({ status: undefined, lastCheckedAtUtc: undefined, lastCompletedAtUtc: undefined, lastError: undefined }),
}));

vi.mock("systeminformation", () => ({
  default: {
    osInfo: async () => ({}),
    system: async () => ({}),
    cpu: async () => ({}),
    mem: async () => ({ total: 0 }),
    networkInterfaces: async () => [],
    networkInterfaceDefault: async () => "",
  },
}));

let TrayStatusStore: typeof import("../../src/status/tray-status-store").TrayStatusStore;

beforeEach(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tray-status-test-"));
  statusDir = path.join(tmpDir, "status");
  vi.resetModules();
  ({ TrayStatusStore } = await import("../../src/status/tray-status-store"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("TrayStatusStore — active job tracking", () => {
  it("markJobStarted with a jobId sets jobs.current", () => {
    const store = new TrayStatusStore();
    const snapshot = store.markJobStarted("patch_install", "job-1");

    expect(snapshot.jobs.current).toEqual(
      expect.objectContaining({ jobId: "job-1", jobType: "patch_install" })
    );
    expect(snapshot.jobs.current?.startedAtUtc).toBeTruthy();
    expect(snapshot.jobs.lastJobType).toBe("patch_install");
    expect(snapshot.jobs.lastJobStatus).toBe("in_progress");
  });

  it("markJobStarted without a jobId leaves jobs.current untouched", () => {
    const store = new TrayStatusStore();
    store.markJobStarted("facts_snapshot", "job-1");
    const snapshot = store.markJobStarted("facts_snapshot");

    // No jobId on this call — the previously-tracked active job (if
    // any) is left as-is rather than being silently wiped.
    expect(snapshot.jobs.current?.jobId).toBe("job-1");
  });

  it("markJobFinished clears jobs.current when the jobId matches", () => {
    const store = new TrayStatusStore();
    store.markJobStarted("patch_install", "job-1");
    const snapshot = store.markJobFinished("patch_install", "success", "job-1");

    expect(snapshot.jobs.current).toBeNull();
    expect(snapshot.jobs.lastJobStatus).toBe("success");
  });

  it("markJobFinished does NOT clear jobs.current for a mismatched (stale) jobId", () => {
    // Guards against an out-of-order finish for an older job stomping
    // a newer job's in-progress state.
    const store = new TrayStatusStore();
    store.markJobStarted("patch_install", "job-2");
    const snapshot = store.markJobFinished("patch_install", "failed", "job-1");

    expect(snapshot.jobs.current?.jobId).toBe("job-2");
  });

  it("markJobFinished with no jobId clears jobs.current unconditionally (back-compat)", () => {
    const store = new TrayStatusStore();
    store.markJobStarted("patch_install", "job-1");
    const snapshot = store.markJobFinished("patch_install", "success");

    expect(snapshot.jobs.current).toBeNull();
  });

  it("persists jobs.current across a save/load round trip", () => {
    const store = new TrayStatusStore();
    store.markJobStarted("patch_install", "job-1");

    const reloaded = store.load();
    expect(reloaded?.jobs.current).toEqual(
      expect.objectContaining({ jobId: "job-1", jobType: "patch_install" })
    );
  });
});

describe("TrayStatusStore — self-service Software Catalog", () => {
  const item = { packageId: "1", name: "Zoom", version: "6.1.0" };

  it("updateCatalog writes items + catalogVersion", () => {
    const store = new TrayStatusStore();
    const snapshot = store.updateCatalog([item], "abc123");

    expect(snapshot.catalog?.catalogVersion).toBe("abc123");
    expect(snapshot.catalog?.items).toEqual([item]);
    expect(snapshot.catalog?.updatedAtUtc).toBeTruthy();
  });

  it("is a no-op when catalogVersion matches what's already on disk", () => {
    const store = new TrayStatusStore();
    const first = store.updateCatalog([item], "abc123");
    const firstUpdatedAt = first.catalog?.updatedAtUtc;

    const second = store.updateCatalog(
      [{ ...item, name: "Zoom (renamed, but same version hash)" }],
      "abc123"
    );

    // Same version — the store must not have rewritten the block (or
    // the top-level updatedAtUtc), even though the payload differs.
    expect(second.catalog?.updatedAtUtc).toBe(firstUpdatedAt);
    expect(second.catalog?.items).toEqual([item]);
  });

  it("rewrites when catalogVersion changes", () => {
    const store = new TrayStatusStore();
    store.updateCatalog([item], "abc123");
    const second = store.updateCatalog([], "def456");

    expect(second.catalog?.catalogVersion).toBe("def456");
    expect(second.catalog?.items).toEqual([]);
  });

  it("persists across a save/load round trip", () => {
    const store = new TrayStatusStore();
    store.updateCatalog([item], "abc123");

    const reloaded = store.load();
    expect(reloaded?.catalog?.items).toEqual([item]);
    expect(reloaded?.catalog?.catalogVersion).toBe("abc123");
  });
});

// ── El estado de conexión: transiciones, no opiniones ────────────────
//
// ⚠️ EL PORTAL Y EL ICONO NO PUEDEN DECIR COSAS DISTINTAS.
//
// El 2026-09-10 un equipo pasó una hora con el portal en verde y el
// icono en Offline. La conexión estaba sana —los latidos salían sin un
// solo fallo y el servidor los recibía—, pero un vigilante averiado
// llamaba a `markGrpcDisconnected()` cada 30 s sobre esa conexión sana.
//
// Dos defectos se sumaban, y hacen falta los dos arreglados:
//
//   1. Las marcas reescribían su fecha aunque el estado ya fuera ése,
//      así que `lastDisconnectedAtUtc` dejó de significar «cuándo nos
//      caímos» para significar «la última vez que alguien lo dijo».
//   2. `connected` sólo volvía a `true` al CONECTAR. Como la conexión
//      no se había caído, no había reconexión que lo corrigiera: un
//      detector equivocado tenía veto permanente sobre lo que ve el
//      usuario.
describe("TrayStatusStore — estado de conexión idempotente", () => {
  it("marcar conectado dos veces no mueve la fecha: es una transición", () => {
    const store = new TrayStatusStore();
    const primera = store.markGrpcConnected();
    const marca = primera.grpc?.lastConnectedAtUtc;
    expect(marca).toBeTruthy();

    const segunda = store.markGrpcConnected();

    expect(segunda.grpc?.connected).toBe(true);
    expect(segunda.grpc?.lastConnectedAtUtc).toBe(marca);
  });

  it("⚠️ marcar desconectado en bucle no mueve la fecha", () => {
    // El síntoma exacto: `lastDisconnectedAtUtc` avanzando sola porque
    // un vigilante repetía su opinión cada 30 s.
    const store = new TrayStatusStore();
    store.markGrpcConnected();
    const primera = store.markGrpcDisconnected();
    const marca = primera.grpc?.lastDisconnectedAtUtc;
    expect(marca).toBeTruthy();

    for (let i = 0; i < 5; i++) store.markGrpcDisconnected();

    const final = store.markGrpcDisconnected();
    expect(final.grpc?.connected).toBe(false);
    expect(final.grpc?.lastDisconnectedAtUtc).toBe(marca);
  });

  it("una transición de verdad SÍ mueve la fecha", () => {
    // Reloj falso: las dos transiciones caen en el mismo milisegundo si
    // se deja al reloj real, y entonces el test no distinguiría «no
    // reescribió» de «reescribió el mismo valor» — que es justo la
    // diferencia que tiene que probar.
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date("2026-09-10T10:00:00.000Z"));
      const store = new TrayStatusStore();
      store.markGrpcConnected();
      const caida = store.markGrpcDisconnected();
      expect(caida.grpc?.lastDisconnectedAtUtc).toBe("2026-09-10T10:00:00.000Z");

      vi.setSystemTime(new Date("2026-09-10T10:05:00.000Z"));
      store.markGrpcConnected();
      const segundaCaida = store.markGrpcDisconnected();

      expect(segundaCaida.grpc?.lastDisconnectedAtUtc).toBe("2026-09-10T10:05:00.000Z");
    } finally {
      vi.useRealTimers();
    }
  });

  it("⚠️ un falso 'desconectado' se cura con el siguiente latido", () => {
    // La propiedad que impide que las dos verdades diverjan: el latido
    // que mueve el `last_seen_at` del backend es el mismo hecho que
    // reafirma el estado del agente. Si el latido pasa, los dos dicen
    // lo mismo.
    const store = new TrayStatusStore();
    store.markGrpcConnected();
    expect(store.load()?.grpc?.connected).toBe(true);

    store.markGrpcDisconnected(); // el vigilante se equivoca
    expect(store.load()?.grpc?.connected).toBe(false);

    store.markGrpcConnected(); // lo que hace el latido correcto
    expect(store.load()?.grpc?.connected).toBe(true);
  });

  it("el latido no resucita un estado caído por sí mismo", () => {
    // `markHeartbeat` sólo mueve su propia marca: quien afirma que hay
    // conexión es el camino que tiene la prueba, no el reloj.
    const store = new TrayStatusStore();
    store.markGrpcConnected();
    store.markGrpcDisconnected();

    const tras = store.markHeartbeat();

    expect(tras.grpc?.connected).toBe(false);
    expect(tras.grpc?.lastHeartbeatAtUtc).toBeTruthy();
  });

  it("sobrevive al ida y vuelta por disco", () => {
    const store = new TrayStatusStore();
    store.markGrpcConnected();
    const marca = store.load()?.grpc?.lastConnectedAtUtc;

    const otro = new TrayStatusStore();
    expect(otro.load()?.grpc?.connected).toBe(true);
    expect(otro.load()?.grpc?.lastConnectedAtUtc).toBe(marca);
  });
});

describe("⚠️ el arranque no puede borrar lo que no sabe recuperar", () => {
  // De dónde viene (este Mac, 25-sep-2026): la pestaña Catalog decía "Nothing
  // available right now" con DOS paquetes de autoservicio publicados en T1. El
  // log del agente tenía `catalogResponse applied { itemCount: 1 }` y el
  // fichero `"catalog": null`.
  //
  // `writeStartupSnapshot` es el único escritor que construye el snapshot
  // desde cero en vez de partir del actual, así que borraba el catálogo en
  // cada arranque. Y el catálogo sólo se pide una vez por conexión, de modo
  // que un reinicio después de recibirlo dejaba la pestaña vacía hasta la
  // siguiente reconexión — en un equipo estable, mañana.

  /** Un contexto mínimo: writeStartupSnapshot sólo lee estos cuatro sitios. */
  const ctx = {
    config: { agentVersion: "1.1.80", coreVersion: "1.1.80" },
    enrollment: { deviceId: "dev-1", tenantId: "1" },
    policy: { getVersion: () => "v1", getHash: () => "h1" },
    policyRuntime: { snapshot: () => ({ plugins: ["amp"], modules: [], features: {} }) },
  } as any;

  it("el catálogo sobrevive al reinicio", () => {
    const store = new TrayStatusStore();
    store.updateCatalog(
      [{ id: "pkg-1", name: "Paquete", version: "1.0", vendor: "ACME" } as any],
      "ver-1"
    );

    const afterRestart = store.writeStartupSnapshot(ctx);

    expect(afterRestart.catalog?.items).toHaveLength(1);
    expect(afterRestart.catalog?.catalogVersion).toBe("ver-1");
  });

  it("⚠️ la sesión remota NO sobrevive: ninguna aguanta un reinicio", () => {
    // Arrastrarla dejaría la franja encendida diciendo que alguien mira una
    // pantalla que ya no mira nadie. Una alarma falsa entrena a la persona a
    // ignorar la siguiente, que sí será real.
    const store = new TrayStatusStore();
    store.setRemoteSession({
      active: true,
      sessionId: "sess-1",
      capability: "rcp.screen",
      controlling: false,
      recording: true,
    } as any);

    const afterRestart = store.writeStartupSnapshot(ctx);

    expect(afterRestart.remoteSession).toBeUndefined();
  });

  it("y sin nada previo no inventa un catálogo", () => {
    const store = new TrayStatusStore();
    const snapshot = store.writeStartupSnapshot(ctx);
    expect(snapshot.catalog).toBeUndefined();
  });
});
