// Un recibo de pkgutil que no se pudo LEER no se desinstaló.
//
// ⚠️ iMac-de-iMac-2.local (T1), 30-sep 05:33Z: un `installer` con la cola de
// PackageKit atascada colgó `pkgutil`, y el escaneo se quedó sin recibos: 18
// «Software removed» (Zoom, Wacom, Tracenium Agent…) que volvieron a las
// 11:32 como «Software installed».

import { beforeEach, describe, expect, it, vi } from "vitest";
import { carryOverUnreadReceipts } from "../../src/domain/macos-receipt-carryover";

// ── El proveedor de macOS, con pkgutil y el disco simulados ────────────

const pkgutil = vi.hoisted(() => ({
  listFails: false,
  infoFails: new Set<string>(),
  pkgs: ["us.zoom.pkg.videomeeting", "com.wacom.TabletInstaller"],
}));

vi.mock("child_process", () => {
  const execFile = (cmd: string, args: string[], opts: any, cb?: any) => {
    const done = typeof opts === "function" ? opts : cb;
    if (cmd === "/usr/sbin/pkgutil" && args[0] === "--pkgs") {
      if (pkgutil.listFails) return done(Object.assign(new Error("Command failed: timeout"), { killed: true }));
      return done(null, { stdout: pkgutil.pkgs.join("\n"), stderr: "" });
    }
    if (cmd === "/usr/sbin/pkgutil" && args[0] === "--pkg-info") {
      if (pkgutil.infoFails.has(args[1])) return done(new Error("Command failed: timeout"));
      return done(null, { stdout: `package-id: ${args[1]}\nversion: 6.1.10\nvolume: /\nlocation: /\ninstall-time: 1720000000\n`, stderr: "" });
    }
    return done(new Error(`not mocked: ${cmd}`));
  };
  return { execFile, default: { execFile } };
});

// Sin .app ni brew: sólo recibos, para aislar el caso.
vi.mock("fs", async (orig) => {
  const real: any = await orig();
  const promises = { ...real.promises, readdir: vi.fn(async () => []), access: vi.fn(async () => undefined) };
  return { ...real, promises, default: { ...real, promises } };
});

vi.mock("systeminformation", () => {
  const stub = {
    system: vi.fn(async () => ({ manufacturer: "Apple Inc.", model: "iMac18,3", serial: "X", uuid: "u", virtual: false })),
    cpu: vi.fn(async () => ({ manufacturer: "Intel", brand: "Core i5", cores: 4, physicalCores: 4 })),
    mem: vi.fn(async () => ({ total: 8_589_934_592 })),
    osInfo: vi.fn(async () => ({ platform: "darwin", distro: "macOS", release: "12.7.6" })),
    diskLayout: vi.fn(async () => []),
    fsSize: vi.fn(async () => []),
    battery: vi.fn(async () => ({ hasBattery: false })),
  };
  return { ...stub, default: stub };
});

const baseline = vi.hoisted(() => ({ rows: [] as any[] }));
vi.mock("../../src/domain/software-baseline-repo", () => ({
  loadSoftwareBaseline: vi.fn(() => baseline.rows),
  upsertSoftwareBaseline: vi.fn((apps: any[]) => {
    for (const a of apps) {
      baseline.rows = baseline.rows.filter((r) => r.installId !== a.installId);
      baseline.rows.push(a);
    }
  }),
  deleteSoftwareByIds: vi.fn((ids: string[]) => {
    baseline.rows = baseline.rows.filter((r) => !ids.includes(r.installId));
  }),
}));
vi.mock("../../src/plugins/amp/providers/printers-cups", () => ({ collectCupsPrinters: vi.fn(async () => []) }));

import os from "os";

const ctx = {
  config: { agentVersion: "test" },
  enrollment: { tenantId: "t1", deviceId: "d1" },
  priv: { call: vi.fn(async () => ({ ok: false, error: { code: "not_implemented" } })) },
  logger: { info() {}, warn() {}, error() {}, debug() {} },
} as any;

const removedNames = (amp: any) => (amp.software.delta?.removed ?? []).map((a: any) => a.packageFamilyName ?? a.name);

describe("macOS: recibos de pkgutil que no se pudieron leer", () => {
  beforeEach(() => {
    baseline.rows = [];
    pkgutil.listFails = false;
    pkgutil.infoFails = new Set();
    (os as any).platform = () => "darwin";
  });

  async function primeroBienLuego(fallo: () => void) {
    const { macProvider } = await import("../../src/plugins/amp/providers/macos");
    await macProvider.collect(ctx); // siembra la línea base con Zoom y Wacom
    fallo();
    return macProvider.collect(ctx);
  }

  it("⭐ pkgutil --pkgs colgado: no se da ningún recibo por desinstalado", async () => {
    const amp: any = await primeroBienLuego(() => (pkgutil.listFails = true));
    expect(removedNames(amp)).toEqual([]);
    expect(baseline.rows.map((r) => r.packageFamilyName).sort()).toEqual(["com.wacom.TabletInstaller", "us.zoom.pkg.videomeeting"]);
  });

  it("⭐ --pkg-info de un recibo falla: ése se conserva, no es un huérfano", async () => {
    const amp: any = await primeroBienLuego(() => pkgutil.infoFails.add("us.zoom.pkg.videomeeting"));
    expect(removedNames(amp)).toEqual([]);
  });

  it("un recibo que de verdad ya no está (pkgutil ya no lo lista) SÍ se va", async () => {
    const amp: any = await primeroBienLuego(() => (pkgutil.pkgs = ["com.wacom.TabletInstaller"]));
    expect(removedNames(amp)).toEqual(["us.zoom.pkg.videomeeting"]);
    pkgutil.pkgs = ["us.zoom.pkg.videomeeting", "com.wacom.TabletInstaller"];
  });
});

describe("carryOverUnreadReceipts", () => {
  const app = (installId: string, source: string, pfn: string) => ({ installId, source, packageFamilyName: pfn, name: pfn }) as any;
  const zoom = app("z", "pkgutil", "us.zoom.pkg.videomeeting");
  const bundle = app("b", "macos-app-bundle", "com.google.Chrome");

  it("sin huecos devuelve el escaneo tal cual", () => {
    const actual = [bundle];
    expect(carryOverUnreadReceipts(actual, [zoom], { all: false, ids: new Set() }).apps).toBe(actual);
  });

  it("sólo recibos de pkgutil, nunca un .app que falta", () => {
    const r = carryOverUnreadReceipts([], [zoom, bundle], { all: true, ids: new Set() });
    expect(r.apps).toEqual([zoom]);
  });

  it("con un hueco concreto, sólo ese recibo", () => {
    const wacom = app("w", "pkgutil", "com.wacom.TabletInstaller");
    const r = carryOverUnreadReceipts([], [zoom, wacom], { all: false, ids: new Set(["com.wacom.TabletInstaller"]) });
    expect(r.apps).toEqual([wacom]);
  });
});
