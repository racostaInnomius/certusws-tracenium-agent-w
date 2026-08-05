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
