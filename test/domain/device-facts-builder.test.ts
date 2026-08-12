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

vi.mock("systeminformation", () => {
  const stub = {
    osInfo: vi.fn(async () => ({ platform: "linux", distro: "Ubuntu", release: "22.04", kernel: "5.15" })),
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
    fsSize: vi.fn(async () => [{ fs: "/", type: "ext4", size: 512_000_000_000, used: 100, mount: "/" }])
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
