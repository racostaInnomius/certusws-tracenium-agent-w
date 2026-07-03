// test/plugins/amp-providers.test.ts
//
// Sprint 2 — P1. Providers AMP (windows / macos / linux).
//
// QUÉ se prueba y POR QUÉ se elige esta frontera:
//
// El inventario HW/SW de los providers NO parsea strings crudos de
// systeminformation/WMI/dpkg dentro de este repo — esa lógica vive en
// el privsvc (proceso privilegiado, repos separados). Los providers de
// agente reciben o bien objetos ya estructurados (Windows software vía
// `ctx.priv.call("software.inventory")`) o llaman a `systeminformation`
// (que aquí NO ejercitamos, es I/O nativo). La NORMALIZACIÓN real y
// determinista que sí vive en el repo es:
//
//   1. `normalizeApp` (src/domain/normalize-app.ts) — el mapeo de una
//      RawApp a los campos normalizados (installId estable, display
//      name/publisher, source). La ejercitamos con FIXTURES de RawApp
//      con forma real (registro Windows, homebrew, dpkg, pkgutil).
//
//   2. El contrato de `security` en macOS/Linux: status "unknown"
//      EXPLÍCITO cuando el privsvc no implementa security.compliance
//      (Phase 5 en Linux). Esto se testea driveando el provider con
//      `ctx.priv.call` mockeado + `si`/baseline-repo mockeados, sin
//      tocar disco ni binarios nativos.
//
// FRONTERAS MOCKEADAS:
//   - "systeminformation" → stub de si.system/cpu/mem/diskLayout/fsSize
//     (los providers lo llaman en collect*Hardware; no queremos I/O).
//   - software-baseline-repo → in-memory (evita tocar la DB del agente).
//   - printers-cups / printers-windows → collectores vacíos (evitan
//     spawnear lpstat / privsvc y aislan el test al eje software+security).
//   - os.platform() → forzado por-suite para pasar los guards de plataforma.
//
// NO se cargan node-pty ni node-datachannel: ninguno de estos módulos
// los importa.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Mocks de frontera (hoisted por vitest) ───────────────────────────
vi.mock("systeminformation", () => {
  const stub = {
    system: vi.fn(async () => ({
      manufacturer: "Dell Inc.",
      model: "Latitude 7420",
      version: "1.2.3",
      serial: "ABC123",
      uuid: "uuid-xyz",
      virtual: false
    })),
    cpu: vi.fn(async () => ({
      manufacturer: "Intel",
      brand: "Core i7-1185G7",
      cores: 8,
      physicalCores: 4
    })),
    mem: vi.fn(async () => ({ total: 34_359_738_368 })),
    osInfo: vi.fn(async () => ({ platform: "windows", distro: "Windows 11" })),
    diskLayout: vi.fn(async () => [{ name: "NVMe", size: 512_000_000_000 }]),
    fsSize: vi.fn(async () => [{ fs: "C:", size: 512_000_000_000, used: 100 }])
  };
  return { ...stub, default: stub };
});

// Baseline repo: in-memory, para que la primera corrida sea "first run"
// (previous vacío) y el provider devuelva items completos, sin tocar
// better-sqlite3 ni el disco.
const baselineState: { rows: any[] } = { rows: [] };
vi.mock("../../src/domain/software-baseline-repo", () => ({
  loadSoftwareBaseline: vi.fn(() => baselineState.rows),
  upsertSoftwareBaseline: vi.fn((apps: any[]) => {
    baselineState.rows.push(...apps);
  }),
  deleteSoftwareByIds: vi.fn((ids: string[]) => {
    baselineState.rows = baselineState.rows.filter(
      (r) => !ids.includes(r.installId)
    );
  })
}));

// Printer collectors → empty. Aísla el test al eje software+security y
// evita spawnear lpstat (CUPS) o pedir printers al privsvc.
vi.mock("../../src/plugins/amp/providers/printers-cups", () => ({
  collectCupsPrinters: vi.fn(async () => [])
}));
vi.mock("../../src/plugins/amp/providers/printers-windows", () => ({
  collectWindowsPrinters: vi.fn(async () => [])
}));

import os from "os";

// ── Helpers ──────────────────────────────────────────────────────────

function makeCtx(privCall: (req: any) => Promise<any>) {
  return {
    config: { agentVersion: "test-9.9.9" },
    enrollment: { tenantId: "t1", deviceId: "d1" },
    priv: { call: vi.fn(privCall) },
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} }
  } as any;
}

/** Router del privsvc: responde por método. */
function privRouter(handlers: Record<string, (req: any) => any>) {
  return async (req: any) => {
    const h = handlers[req.method];
    if (!h) return { ok: false, error: { code: "not_implemented" } };
    return h(req);
  };
}

beforeEach(() => {
  baselineState.rows = [];
  vi.clearAllMocks();
});

// ─────────────────────────────────────────────────────────────────────
// 1. normalizeApp — mapeo de RawApp → campos normalizados
//    (fixtures con forma real de cada collector).
// ─────────────────────────────────────────────────────────────────────
describe("AMP normalizeApp — mapeo de inventario a campos normalizados", () => {
  // Importado de forma perezosa para que los mocks de arriba ya estén activos.
  let normalizeApp: typeof import("../../src/domain/normalize-app").normalizeApp;
  let generateInstallId: typeof import("../../src/domain/normalize-app").generateInstallId;

  beforeEach(async () => {
    const mod = await import("../../src/domain/normalize-app");
    normalizeApp = mod.normalizeApp;
    generateInstallId = mod.generateInstallId;
  });

  it("registro Windows: normaliza name/version/publisher y produce installId sha256 estable", () => {
    // Forma real de un item de `software.inventory` (privsvc win32-registry).
    const raw = {
      name: "  Google Chrome ",
      version: "126.0.6478.127",
      publisher: "Google LLC",
      installLocation: "C:\\Program Files\\Google\\Chrome",
      packageFamilyName: null,
      source: "win32-registry"
    };
    const n = normalizeApp(raw)!;
    expect(n).toBeTruthy();
    // cleanString colapsa espacios y hace trim.
    expect(n.rawName).toBe("Google Chrome");
    expect(n.version).toBe("126.0.6478.127");
    expect(n.source).toBe("win32-registry");
    expect(n.installId).toMatch(/^sha256:[0-9a-f]{64}$/);
    // installId es determinista para la misma identidad técnica.
    expect(n.installId).toBe(
      generateInstallId({
        name: "google chrome",
        source: "win32-registry",
        packageFamilyName: undefined,
        publisher: "google llc"
      })
    );
  });

  it("nombre vacío/whitespace → null (filtrado del inventario)", () => {
    expect(normalizeApp({ name: "   ", source: "win32-registry" })).toBeNull();
    expect(normalizeApp({ name: null, source: "dpkg" })).toBeNull();
  });

  it("source-only publishers (dpkg/homebrew/pkgutil) NO contaminan la identidad", () => {
    // Cuando el publisher ES el collector (dpkg/homebrew/pkgutil), la
    // identidad NO debe usarlo — si no, cambiar de collector rompería el
    // installId. Verificamos que dpkg-como-publisher produce el mismo
    // installId que sin publisher.
    const withCollectorPub = normalizeApp({
      name: "htop",
      version: "3.2.1",
      publisher: "dpkg",
      packageFamilyName: "htop",
      source: "dpkg"
    })!;
    const noPub = normalizeApp({
      name: "htop",
      version: "3.2.1",
      publisher: undefined,
      packageFamilyName: "htop",
      source: "dpkg"
    })!;
    expect(withCollectorPub.installId).toBe(noPub.installId);
  });

  it("installId es INDEPENDIENTE del display name (canonical id pkgutil vs display)", () => {
    // La identidad técnica usa rawName.toLowerCase(); mejorar el display
    // name luego no debe producir removed+added falsos.
    const pkgutil = normalizeApp({
      name: "com.microsoft.onenote.mac",
      version: "16.0",
      packageFamilyName: "com.microsoft.onenote.mac",
      source: "pkgutil"
    })!;
    const recomputed = generateInstallId({
      name: "com.microsoft.onenote.mac",
      source: "pkgutil",
      packageFamilyName: "com.microsoft.onenote.mac",
      publisher: undefined
    });
    expect(pkgutil.installId).toBe(recomputed);
  });

  it("homebrew: version se conserva; source normalizado a lowercase", () => {
    const n = normalizeApp({
      name: "wget",
      version: "1.21.4",
      publisher: "homebrew",
      installLocation: "/opt/homebrew",
      packageFamilyName: "wget",
      source: "homebrew"
    })!;
    expect(n.version).toBe("1.21.4");
    expect(n.source).toBe("homebrew");
  });
});

// ─────────────────────────────────────────────────────────────────────
// 2. Contrato de security stubs (macOS / Linux) — status "unknown"
//    EXPLÍCITO. Estos tests fijan el contrato Phase 5: cuando esos
//    handlers lleguen, ESTOS tests son los que hay que cambiar.
// ─────────────────────────────────────────────────────────────────────
describe("AMP security stubs — contrato 'unknown' (Phase 5)", () => {
  const realPlatform = os.platform;

  // Restaurar os.platform tras cada test de plataforma para no
  // filtrar el override a otras suites.
  afterEach(() => {
    (os as any).platform = realPlatform;
  });

  it("macOS: bitlocker/defender/firewall = 'unknown' cuando privsvc NO implementa security.compliance", async () => {
    (os as any).platform = () => "darwin";
    const { macProvider } = await import("../../src/plugins/amp/providers/macos");

    // privsvc: software.inventory no aplica en macOS (usa collectMacSoftware
    // via execFile, que fallará silenciosamente → []), security.compliance
    // devuelve not_implemented (ok:false).
    const ctx = makeCtx(
      privRouter({
        "security.compliance": () => ({ ok: false, error: { code: "not_implemented" } })
      })
    );

    const amp = await macProvider.collect(ctx);
    expect(amp.security.bitlocker?.status).toBe("unknown");
    expect(amp.security.defender?.status).toBe("unknown");
    expect(amp.security.firewall?.status).toBe("unknown");
  });

  it("macOS: cuando privsvc SÍ devuelve posture, mapea filevault→bitlocker, gatekeeper→defender, firewall→firewall", async () => {
    (os as any).platform = () => "darwin";
    const { macProvider } = await import("../../src/plugins/amp/providers/macos");

    const ctx = makeCtx(
      privRouter({
        "security.compliance": () => ({
          ok: true,
          result: {
            filevault: { status: "enabled" },
            gatekeeper: { status: "enabled" },
            sip: { status: "enabled" },
            firewall: { status: "disabled" }
          }
        })
      })
    );

    const amp = await macProvider.collect(ctx);
    // El provider macOS reetiqueta filevault como el slot "bitlocker"
    // (cross-platform disk-encryption) y gatekeeper como "defender".
    expect(amp.security.bitlocker?.status).toBe("enabled");
    expect(amp.security.defender?.status).toBe("enabled");
    expect(amp.security.firewall?.status).toBe("disabled");
  });

  it("Linux: bitlocker/defender SIEMPRE 'unknown' (N/A), firewall mapea desde posture cuando existe (Phase 5)", async () => {
    (os as any).platform = () => "linux";
    const { linuxProvider } = await import("../../src/plugins/amp/providers/linux");

    // Phase 5 aún no implementado → ok:false → todo unknown.
    const ctxUnknown = makeCtx(
      privRouter({
        "security.compliance": () => ({ ok: false, error: { code: "not_implemented" } })
      })
    );
    const ampUnknown = await linuxProvider.collect(ctxUnknown);
    expect(ampUnknown.security.bitlocker?.status).toBe("unknown");
    expect(ampUnknown.security.defender?.status).toBe("unknown");
    expect(ampUnknown.security.firewall?.status).toBe("unknown");

    // Simulación de Phase 5: privsvc devuelve firewall real. bitlocker /
    // defender DEBEN quedarse "unknown" (no aplican en Linux); sólo
    // firewall refleja el posture.
    const ctxFw = makeCtx(
      privRouter({
        "security.compliance": () => ({
          ok: true,
          result: { firewall: { status: "enabled" } }
        })
      })
    );
    const ampFw = await linuxProvider.collect(ctxFw);
    expect(ampFw.security.bitlocker?.status).toBe("unknown");
    expect(ampFw.security.defender?.status).toBe("unknown");
    expect(ampFw.security.firewall?.status).toBe("enabled");
  });

  it("Linux: priv.call que LANZA (pipe en reconexión) degrada a 'unknown' sin abortar la colección", async () => {
    (os as any).platform = () => "linux";
    const { linuxProvider } = await import("../../src/plugins/amp/providers/linux");

    const ctx = makeCtx(async () => {
      throw new Error("IPC pipe mid-reconnect");
    });

    const amp = await linuxProvider.collect(ctx);
    expect(amp.security.firewall?.status).toBe("unknown");
    // La colección completa devolvió un AmpNamespace (no lanzó).
    expect(amp).toHaveProperty("software");
    expect(amp).toHaveProperty("hardware");
  });
});

// ─────────────────────────────────────────────────────────────────────
// 3. Windows software inventory — normalización desde privsvc structured
//    result (items[] / apps[] fallback).
// ─────────────────────────────────────────────────────────────────────
describe("AMP Windows — normalización de software.inventory (contrato items/apps)", () => {
  const realPlatform = os.platform;
  beforeEach(() => {
    (os as any).platform = () => "win32";
  });
  afterEach(() => {
    (os as any).platform = realPlatform;
  });

  it("acepta 'items' (contrato actual) y normaliza cada RawApp", async () => {
    const { collectWindowsSoftwareInventory } = await import(
      "../../src/plugins/amp/providers/windows"
    );
    const ctx = makeCtx(
      privRouter({
        "software.inventory": () => ({
          ok: true,
          result: {
            items: [
              { name: "7-Zip", version: "24.07", publisher: "Igor Pavlov", source: "win32-registry" },
              { name: "Mozilla Firefox", version: "127.0", publisher: "Mozilla", source: "win32-registry" },
              { name: "", version: "0", publisher: "x" } // se filtra (name vacío)
            ]
          }
        })
      })
    );

    const inv = await collectWindowsSoftwareInventory(ctx);
    expect(inv.count).toBe(2);
    expect(inv.apps.map((a: any) => a.rawName).sort()).toEqual([
      "7-Zip",
      "Mozilla Firefox"
    ]);
    expect(inv.apps.every((a: any) => a.installId.startsWith("sha256:"))).toBe(true);
  });

  it("fallback a 'apps' (contrato viejo) cuando no hay 'items'", async () => {
    const { collectWindowsSoftwareInventory } = await import(
      "../../src/plugins/amp/providers/windows"
    );
    const ctx = makeCtx(
      privRouter({
        "software.inventory": () => ({
          ok: true,
          result: { apps: [{ name: "Notepad++", version: "8.6", source: "win32-registry" }] }
        })
      })
    );
    const inv = await collectWindowsSoftwareInventory(ctx);
    expect(inv.count).toBe(1);
    expect(inv.apps[0].rawName).toBe("Notepad++");
  });

  it("resp.ok=false → lanza con el código/mensaje del privsvc", async () => {
    const { collectWindowsSoftwareInventory } = await import(
      "../../src/plugins/amp/providers/windows"
    );
    const ctx = makeCtx(
      privRouter({
        "software.inventory": () => ({
          ok: false,
          error: { code: "ACCESS_DENIED", message: "not elevated" }
        })
      })
    );
    await expect(collectWindowsSoftwareInventory(ctx)).rejects.toThrow(/ACCESS_DENIED/);
  });

  it("collect(): inventario no vacío en first-run → items completos + hasChanges + security desde privsvc", async () => {
    const { windowsProvider } = await import("../../src/plugins/amp/providers/windows");
    const ctx = makeCtx(
      privRouter({
        "security.compliance": () => ({
          ok: true,
          result: {
            bitlocker: { status: "enabled" },
            defender: { status: "enabled" },
            firewall: { status: "enabled" }
          }
        }),
        "software.inventory": () => ({
          ok: true,
          result: { items: [{ name: "Slack", version: "4.38", source: "win32-registry" }] }
        })
      })
    );

    const amp = await windowsProvider.collect(ctx);
    expect(amp.security.bitlocker?.status).toBe("enabled");
    expect(amp.software.hasChanges).toBe(true);
    expect(amp.software.count).toBe(1);
    expect(amp.software.items?.[0].rawName).toBe("Slack");
    // hardware viene de si.* (mock) — manufacturer del stub.
    expect((amp.hardware.static as any).system.manufacturer).toBe("Dell Inc.");
  });

  it("collect(): inventario VACÍO → limpia baseline y hasChanges=true con items=[]", async () => {
    // sembramos baseline con 1 fila para verificar deleteSoftwareByIds.
    const repo = await import("../../src/domain/software-baseline-repo");
    baselineState.rows = [{ installId: "sha256:old" }];

    const { windowsProvider } = await import("../../src/plugins/amp/providers/windows");
    const ctx = makeCtx(
      privRouter({
        "security.compliance": () => ({ ok: false, error: { code: "x" } }),
        "software.inventory": () => ({ ok: true, result: { items: [] } })
      })
    );

    const amp = await windowsProvider.collect(ctx);
    expect(amp.software.count).toBe(0);
    expect(amp.software.items).toEqual([]);
    expect(amp.software.hasChanges).toBe(true);
    expect(repo.deleteSoftwareByIds).toHaveBeenCalledWith(["sha256:old"]);
  });
});
