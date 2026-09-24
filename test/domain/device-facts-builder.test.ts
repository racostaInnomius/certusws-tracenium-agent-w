// test/domain/device-facts-builder.test.ts
//
// buildDeviceFacts es el punto donde el agente reensambla el namespace
// `amp` final que viaja por el wire. Históricamente reconstruía
// `amp = { hardware, security, software }` y DEJABA CAER `amp.printers`
// que los providers sí recolectaban → toda la tubería de printers
// (providers + backend applyPrinterDelta + tabla device_printers + UI)
// esperaba datos que NUNCA se enviaban. Este suite fija el contrato:
//
//   - printers presentes en la entrada  ⇒ presentes en la salida (mismo shape/delta)
//   - printers ausentes                 ⇒ la clave NO aparece (no se inventa)
//   - software se preserva igual (regresión hermana)
//
// FRONTERAS MOCKEADAS:
//   - "systeminformation" → stub de las 14 llamadas que buildHardwareNamespace
//     realmente consume (no hay I/O nativo en el test).

import { describe, it, expect, vi } from "vitest";
import nodeOs from "node:os";

vi.mock("systeminformation", () => {
  const stub = {
    // ⚠️ `arch` MIENTE A PROPÓSITO. systeminformation lo obtiene lanzando un
    // proceso, y en máquinas reales de la flota eso vuelve vacío (el mismo
    // motivo por el que distro/release tienen fallback a os-release). El
    // colector debe tomarlo de `os.arch()`, y este valor imposible lo prueba.
    osInfo: vi.fn(async () => ({ platform: "linux", distro: "Ubuntu", release: "22.04", kernel: "5.15", arch: "mentira-de-si" })),
    system: vi.fn(async () => ({
      manufacturer: "Dell Inc.",
      model: "Latitude 7420",
      version: "1.0",
      serial: "SER123",
      uuid: "uuid-abc",
      sku: "SKU1",
      virtual: false
    })),
    baseboard: vi.fn(async () => ({ manufacturer: "Dell", model: "0ABC" })),
    chassis: vi.fn(async () => ({ type: "Laptop" })),
    bios: vi.fn(async () => ({ vendor: "Dell", version: "1.2.3" })),
    cpu: vi.fn(async () => ({ manufacturer: "Intel", brand: "Core i7", cores: 8, physicalCores: 4 })),
    mem: vi.fn(async () => ({ total: 34_359_738_368 })),
    memLayout: vi.fn(async () => [{ size: 17_179_869_184, type: "DDR4" }]),
    diskLayout: vi.fn(async () => [{ name: "NVMe", type: "SSD", size: 512_000_000_000 }]),
    graphics: vi.fn(async () => ({ controllers: [] })),
    networkInterfaces: vi.fn(async () => [] as any[]),
    networkInterfaceDefault: vi.fn(async () => null as any),
    users: vi.fn(async () => [] as any[]),
    fsSize: vi.fn(async () => [{ fs: "/", type: "ext4", size: 512_000_000_000, used: 100, mount: "/" }]),
    battery: vi.fn(async () => ({ hasBattery: true, percent: 64, isCharging: false, acConnected: false }))
  };
  return { ...stub, default: stub };
});

import { buildDeviceFacts } from "../../src/domain/device-facts-builder";
import type { Namespaces } from "../../src/domain/device-facts";

function makeCtx(): any {
  return {
    enrollment: {
      deviceId: "dev-1",
      tenantId: "tenant-1",
      enrolledAtUtc: "2026-01-01T00:00:00.000Z",
      bootstrap: { capabilities: [], channel: "stable" }
    },
    config: { agentVersion: "1.1.26", coreVersion: "1.0.0" },
    policyRuntime: { getEnabledPlugins: () => [] as string[] }
  };
}

describe("buildDeviceFacts — amp namespace passthrough", () => {
  it("preserves amp.printers collected by the provider (the regression)", async () => {
    const namespaces: Namespaces = {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: { count: 0, delta: null, items: [], hasChanges: false },
        printers: {
          count: 2,
          delta: null,
          items: [
            { printerId: "p1", name: "HP LaserJet", isDefault: true } as any,
            { printerId: "p2", name: "PDF", isDefault: false } as any
          ],
          hasChanges: true
        }
      }
    } as any;

    const facts = await buildDeviceFacts(makeCtx(), namespaces);

    expect(facts.namespaces.amp?.printers).toBeDefined();
    expect(facts.namespaces.amp?.printers?.count).toBe(2);
    expect(facts.namespaces.amp?.printers?.hasChanges).toBe(true);
    expect(facts.namespaces.amp?.printers?.items?.length).toBe(2);
  });

  it("carries a printers slim-delta (items elided) through unchanged", async () => {
    const namespaces: Namespaces = {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: { count: 5, delta: null, items: undefined, hasChanges: false },
        printers: {
          count: 3,
          delta: { added: [], removed: [{ printerId: "p9" } as any], changed: [] } as any,
          items: undefined,
          hasChanges: true
        }
      }
    } as any;

    const facts = await buildDeviceFacts(makeCtx(), namespaces);

    expect(facts.namespaces.amp?.printers?.count).toBe(3);
    expect(facts.namespaces.amp?.printers?.items).toBeUndefined();
    expect(facts.namespaces.amp?.printers?.delta).toBeTruthy();
    expect(facts.namespaces.amp?.printers?.hasChanges).toBe(true);
  });

  // machineScope/userScope (2026-09-10) son lo que separa "no se pudo leer" de
  // "no tiene impresoras". El literal del builder los tiraba: el backend veía
  // un inventario vacío y lo pintaba como cero.
  it("pasa amp.printers.machineScope/userScope (la lectura ciega no es un cero)", async () => {
    const namespaces: Namespaces = {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: { count: 0, delta: null, items: [], hasChanges: false },
        printers: { count: 0, delta: null, items: [], hasChanges: true, machineScope: "timeout", userScope: "no_user_hive" }
      }
    } as any;

    const facts = await buildDeviceFacts(makeCtx(), namespaces);

    expect(facts.namespaces.amp?.printers).toEqual({
      count: 0, delta: null, items: [], hasChanges: true, machineScope: "timeout", userScope: "no_user_hive"
    });
  });

  it("no inventa machineScope/userScope donde sólo hay una lectura (macOS/Linux)", async () => {
    const namespaces: Namespaces = {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: { count: 0, delta: null, items: [], hasChanges: false },
        printers: { count: 1, delta: null, items: [{ printerId: "p1" } as any], hasChanges: true }
      }
    } as any;

    const facts = await buildDeviceFacts(makeCtx(), namespaces);

    expect("machineScope" in (facts.namespaces.amp?.printers as any)).toBe(false);
    expect("userScope" in (facts.namespaces.amp?.printers as any)).toBe(false);
  });

  it("pasa amp.browserExtensions con scope y profiles (lista blanca del builder)", async () => {
    const namespaces: Namespaces = {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: { count: 0, delta: null, items: [], hasChanges: false },
        browserExtensions: { count: 1, delta: null, items: [{ installId: "chrome|u|Default|x" } as any], hasChanges: true, scope: "collected", profiles: 3, profileErrors: 1 }
      }
    } as any;
    const facts = await buildDeviceFacts(makeCtx(), namespaces);
    expect(facts.namespaces.amp?.browserExtensions).toEqual({ count: 1, delta: null, items: [{ installId: "chrome|u|Default|x" }], hasChanges: true, scope: "collected", profiles: 3, profileErrors: 1 });
    const withPolicy = await buildDeviceFacts(makeCtx(), {
      amp: { ...(namespaces as any).amp, browserExtensions: { ...(namespaces as any).amp.browserExtensions, policy: [{ browser: "chrome", list: "blocklist", status: "written", present: ["x"], foreign: 0 }] } }
    } as any);
    expect(withPolicy.namespaces.amp?.browserExtensions?.policy).toEqual([{ browser: "chrome", list: "blocklist", status: "written", present: ["x"], foreign: 0 }]);
  });

  it("omits printers when the provider collected none", async () => {
    const namespaces: Namespaces = {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: { count: 0, delta: null, items: [], hasChanges: false }
      }
    } as any;

    const facts = await buildDeviceFacts(makeCtx(), namespaces);

    expect(facts.namespaces.amp).toBeDefined();
    expect("printers" in (facts.namespaces.amp as any)).toBe(false);
  });

  it("still preserves the software inventory alongside printers", async () => {
    const namespaces: Namespaces = {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: {
          count: 1,
          delta: null,
          items: [{ installId: "app-1", name: "Firefox" } as any],
          hasChanges: true
        },
        printers: { count: 0, delta: null, items: [], hasChanges: false }
      }
    } as any;

    const facts = await buildDeviceFacts(makeCtx(), namespaces);

    expect(facts.namespaces.amp?.software?.count).toBe(1);
    expect(facts.namespaces.amp?.software?.items?.length).toBe(1);
    expect(facts.namespaces.amp?.printers?.count).toBe(0);
  });
});

// Segunda vez que este allowlist se come un namespace entero. La primera fue
// printers; la segunda, la ubicación: el agente 1.1.29 recolectaba geo y
// geoStatus en cada tick y buildDeviceFacts los descartaba aquí, así que el
// backend recibía amp = {hardware, security, software, printers} y la UI
// concluía "este agente es muy viejo para reportar posición" sobre agentes
// recién instalados.
describe("buildDeviceFacts — amp.geo / amp.geoStatus passthrough", () => {
  function ampWith(extra: Record<string, unknown>): Namespaces {
    return {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: { count: 0, delta: null, items: [], hasChanges: false },
        ...extra
      }
    } as any;
  }

  it("⚠️ conserva el arranque que lee el proveedor (bootTimeUtc + uptimeSeconds)", async () => {
    // La regresión: el runtime del proveedor se sustituía por el de
    // buildHardwareNamespace, que no lo lleva. T111: 0 de 55 con Last boot.
    const out: any = await buildDeviceFacts(makeCtx(), {
      amp: {
        hardware: {
          static: {} as any,
          runtime: { bootTimeUtc: "2026-09-15T06:12:00.000Z", uptimeSeconds: 33120 } as any
        },
        security: { status: "unknown" } as any,
        software: { count: 0, delta: null, items: [], hasChanges: false }
      } as any
    });
    expect(out.namespaces.amp.hardware.runtime).toMatchObject({
      bootTimeUtc: "2026-09-15T06:12:00.000Z",
      uptimeSeconds: 33120,
      memoryBytes: 34_359_738_368
    });
  });

  it("⭐ la batería viaja en runtime (nunca se mandaba: 0 de 83 equipos en prod)", async () => {
    const out: any = await buildDeviceFacts(makeCtx(), {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: { count: 0, delta: null, items: [], hasChanges: false }
      } as any
    });
    expect(out.namespaces.amp.hardware.runtime.battery).toEqual({ present: true, percent: 64, isCharging: false, acConnected: false });
    // Y NO en static: el backend deduplica por el hash de static.
    expect(out.namespaces.amp.hardware.static).not.toHaveProperty("battery");
  });

  it("no inventa el arranque si el proveedor no lo leyó, pero pasa un null explícito", async () => {
    const base = { security: { status: "unknown" } as any, software: { count: 0, delta: null, items: [], hasChanges: false } };
    const sinDato: any = await buildDeviceFacts(makeCtx(), { amp: { hardware: { static: {} as any, runtime: {} as any }, ...base } as any });
    expect(sinDato.namespaces.amp.hardware.runtime).not.toHaveProperty("bootTimeUtc");
    const nulo: any = await buildDeviceFacts(makeCtx(), {
      amp: { hardware: { static: {} as any, runtime: { bootTimeUtc: null, uptimeSeconds: 12 } as any }, ...base } as any
    });
    expect(nulo.namespaces.amp.hardware.runtime).toMatchObject({ bootTimeUtc: null, uptimeSeconds: 12 });
  });

  it("preserves a position reported by the OS", async () => {
    const geo = { lat: 19.432608, lon: -99.133209, accuracyM: 38, collectedAtUtc: "2026-08-11T18:00:00.000Z" };
    const facts = await buildDeviceFacts(makeCtx(), ampWith({ geo }));
    expect((facts.namespaces.amp as any)?.geo).toEqual(geo);
  });

  it("preserves geoStatus on the ticks that carry NO position", async () => {
    // The whole point of the field: it explains the empty ticks, which are the
    // overwhelming majority. Dropping it here is what made every device look
    // like it was running an ancient agent.
    for (const status of ["disabled", "unsupported", "denied", "unavailable"]) {
      const facts = await buildDeviceFacts(makeCtx(), ampWith({ geoStatus: status }));
      expect((facts.namespaces.amp as any)?.geoStatus).toBe(status);
      expect((facts.namespaces.amp as any)?.geo).toBeUndefined();
    }
  });

  it("carries both together when a fix was obtained", async () => {
    const facts = await buildDeviceFacts(
      makeCtx(),
      ampWith({
        geoStatus: "ok",
        geo: { lat: 0, lon: 32.5, accuracyM: null, collectedAtUtc: "2026-08-11T18:00:00.000Z" }
      })
    );
    expect((facts.namespaces.amp as any)?.geoStatus).toBe("ok");
    // lat 0 is the equator, not "missing" — it must survive the rebuild.
    expect((facts.namespaces.amp as any)?.geo?.lat).toBe(0);
  });

  it("does not invent the keys when the collector reported neither", async () => {
    // An agent with the plugin disabled must produce byte-identical output to
    // one that predates the feature.
    const facts = await buildDeviceFacts(makeCtx(), ampWith({}));
    expect((facts.namespaces.amp as any)?.geo).toBeUndefined();
    expect((facts.namespaces.amp as any)?.geoStatus).toBeUndefined();
  });
});

describe("buildDeviceFacts — strips internal hasChanges from scp/pmp/cdp (B8)", () => {
  // Los tres tipos documentan hasChanges como "internal-only: el builder
  // lo quita antes de enviar". Hasta 2026-08-13 esa promesa era falsa:
  // el spread inicial lo dejaba pasar al wire tal cual. Este suite fija
  // la promesa. El hasChanges de amp.software / amp.printers es OTRO
  // campo (contrato real del wire con amp-projection) y debe seguir.
  it("removes namespace-level hasChanges but keeps the rest of the evidence", async () => {
    const namespaces: Namespaces = {
      scp: {
        schemaVersion: "2.0",
        collector: { plugin: "scp", version: "1.4.0" } as any,
        hasChanges: true,
        firewall: { enabled: true }
      } as any,
      pmp: {
        schemaVersion: "1.0",
        collector: { plugin: "pmp", version: "1.0.0" },
        hasChanges: true,
        overall: { status: "ok" }
      } as any,
      cdp: {
        schemaVersion: "1.0",
        collector: { plugin: "cdp", version: "1.0.0" },
        collectedAt: "2026-08-13T00:00:00Z",
        hasChanges: true,
        truncated: false,
        stores: []
      } as any
    };

    const facts = await buildDeviceFacts(makeCtx(), namespaces);

    expect(facts.namespaces.scp).toBeDefined();
    expect((facts.namespaces.scp as any).hasChanges).toBeUndefined();
    expect((facts.namespaces.scp as any).firewall).toEqual({ enabled: true });

    expect((facts.namespaces.pmp as any).hasChanges).toBeUndefined();
    expect((facts.namespaces.pmp as any).overall).toEqual({ status: "ok" });

    expect((facts.namespaces.cdp as any).hasChanges).toBeUndefined();
    expect((facts.namespaces.cdp as any).stores).toEqual([]);
  });

  it("keeps amp.software.hasChanges — that one IS wire contract", async () => {
    const namespaces: Namespaces = {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: { count: 1, delta: null, items: [], hasChanges: true }
      } as any
    };

    const facts = await buildDeviceFacts(makeCtx(), namespaces);
    expect((facts.namespaces.amp as any).software.hasChanges).toBe(true);
  });

  it("does not invent scp/pmp/cdp keys when the input lacks them", async () => {
    const facts = await buildDeviceFacts(makeCtx(), {} as Namespaces);
    expect(facts.namespaces.scp).toBeUndefined();
    expect(facts.namespaces.pmp).toBeUndefined();
    expect(facts.namespaces.cdp).toBeUndefined();
  });
});

describe("buildDeviceFacts — la arquitectura del equipo", () => {
  // ⚠️ POR QUÉ EXISTE ESTE CAMPO.
  //
  // Hasta el 7-sep-2026 `arch` no estaba en NINGUNA parte: ni en el control DB,
  // ni en la del tenant, ni en el payload crudo — `static.os` guardaba
  // distro/kernel/platform/release y nada más. Y no era falta de recolección:
  // providers/windows.ts calculaba `os.arch()` y lo tiraba sin usarlo, igual
  // que pasó con `uptimeSeconds` y con `antivirus.products`.
  //
  // El catálogo global (ADR-0016) lo necesita para decidir qué binario le toca
  // a cada equipo, y la alternativa era adivinarlo del modelo de CPU.
  it("viaja en static.os", async () => {
    const namespaces = {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: { count: 0, delta: null, items: [], hasChanges: false }
      }
    } as any;

    const facts = await buildDeviceFacts(makeCtx(), namespaces);
    const osBlock: any = (facts.namespaces.amp?.hardware as any)?.static?.os;

    expect(osBlock?.arch).toBeTruthy();
  });

  // ⚠️ LA ASERCIÓN QUE IMPORTA, Y NO ES "vale arm64".
  //
  // Comparar contra un literal fijaría la máquina donde corre el test, no la
  // propiedad. Lo que se afirma es el ORIGEN: sale de `os.arch()`, que Node da
  // sin shell ni PATH, y NO de systeminformation, cuyo stub aquí devuelve un
  // valor imposible.
  it("sale de os.arch(), no de systeminformation", async () => {
    const namespaces = {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: { count: 0, delta: null, items: [], hasChanges: false }
      }
    } as any;

    const facts = await buildDeviceFacts(makeCtx(), namespaces);
    const osBlock: any = (facts.namespaces.amp?.hardware as any)?.static?.os;

    expect(osBlock.arch).toBe(nodeOs.arch());
    expect(osBlock.arch).not.toBe("mentira-de-si");
  });

  // No rompe lo que ya viajaba en ese bloque.
  it("no desplaza a platform ni kernel", async () => {
    const namespaces = {
      amp: {
        hardware: { static: {} as any, runtime: {} as any },
        security: { status: "unknown" } as any,
        software: { count: 0, delta: null, items: [], hasChanges: false }
      }
    } as any;

    const facts = await buildDeviceFacts(makeCtx(), namespaces);
    const osBlock: any = (facts.namespaces.amp?.hardware as any)?.static?.os;

    expect(["windows", "macos", "linux"]).toContain(osBlock.platform);
    expect(osBlock.kernel).toBe("5.15");
  });
});
