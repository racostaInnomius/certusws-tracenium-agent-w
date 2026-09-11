// test/domain/device-facts-arch.test.ts
//
// Que `os-arch.ts` conteste bien no sirve de nada si el colector no lo llama,
// y en este repo eso ya pasó tres veces: printers, geo y `uptimeSeconds` se
// recolectaban correctamente y se caían en el camino al wire. Este suite mide
// el CABLEADO, no el cálculo — que hay un test aparte para eso.
//
// FRONTERAS MOCKEADAS:
//   - "systeminformation" → el mismo stub de 14 llamadas que usa
//     device-facts-builder.test.ts (sin I/O nativo).
//   - "./os-arch" → devuelve centinelas imposibles. Si el colector volviera a
//     leer `os.arch()` a secas, el centinela no aparecería y este test fallaría;
//     un valor realista ("arm64") lo habría dejado pasar en el host equivocado.

import { describe, it, expect, vi } from "vitest";

vi.mock("systeminformation", () => {
  const stub = {
    osInfo: vi.fn(async () => ({
      platform: "windows",
      distro: "Microsoft Windows 11 Pro",
      release: "11",
      kernel: "10.0.26100",
      arch: "mentira-de-si"
    })),
    system: vi.fn(async () => ({
      manufacturer: "QEMU",
      model: "QEMU Virtual Machine",
      version: "1.0",
      serial: "SER-LAB02",
      uuid: "uuid-lab02",
      sku: "SKU1",
      virtual: true
    })),
    baseboard: vi.fn(async () => ({ manufacturer: "QEMU", model: "virt" })),
    chassis: vi.fn(async () => ({ type: "Virtual Machine" })),
    bios: vi.fn(async () => ({ vendor: "EDK II", version: "1.0" })),
    cpu: vi.fn(async () => ({ manufacturer: "Apple", brand: "Apple M-series", cores: 8, physicalCores: 8 })),
    mem: vi.fn(async () => ({ total: 8_589_934_592 })),
    memLayout: vi.fn(async () => [{ size: 8_589_934_592, type: "DRAM" }]),
    diskLayout: vi.fn(async () => [{ name: "QEMU HARDDISK", type: "SSD", size: 68_719_476_736 }]),
    graphics: vi.fn(async () => ({ controllers: [] })),
    networkInterfaces: vi.fn(async () => [] as any[]),
    networkInterfaceDefault: vi.fn(async () => null as any),
    users: vi.fn(async () => [] as any[]),
    fsSize: vi.fn(async () => [{ fs: "C:", type: "NTFS", size: 68_719_476_736, used: 100, mount: "C:" }])
  };
  return { ...stub, default: stub };
});

// Centinelas imposibles: ninguna arquitectura real se llama así, de modo que
// sólo pueden haber llegado por la función que decimos.
const OS_ARCH_SENTINEL = "arch-del-sistema";

vi.mock("../../src/domain/os-arch", () => ({
  reportedOsArch: vi.fn(() => OS_ARCH_SENTINEL),
  detectOsArch: vi.fn(() => "arm64" as const)
}));

import nodeOs from "os";
import { buildDeviceFacts } from "../../src/domain/device-facts-builder";
import { reportedOsArch, detectOsArch } from "../../src/domain/os-arch";

function makeCtx(): any {
  return {
    enrollment: {
      deviceId: "dev-lab02",
      tenantId: "1",
      enrolledAtUtc: "2026-09-01T00:00:00.000Z",
      bootstrap: { capabilities: [], channel: "stable" }
    },
    config: { agentVersion: "1.1.71", coreVersion: "1.1.71" },
    policyRuntime: { getEnabledPlugins: () => [] as string[] }
  };
}

describe("buildDeviceFacts — de dónde sale el arch que ve el portal", () => {
  it("⭐ hardware.static.os.arch es el del SISTEMA, no el de `os.arch()`", async () => {
    // Este es el campo que el backend copia a `host_current_status.arch` (vía
    // deriveOsFields) y que el portal pinta en la columna Arch de Hardware
    // Inventory. Con `os.arch()`, W11-JPR-LAB02 salía x64.
    const facts = await buildDeviceFacts(makeCtx(), { amp: {} } as any);
    const osBlock = (facts.namespaces.amp as any).hardware.static.os;

    expect(osBlock.arch).toBe(OS_ARCH_SENTINEL);
    expect(reportedOsArch).toHaveBeenCalled();
  });

  it("la del proceso viaja al lado, sin pisar a la del sistema", async () => {
    const facts = await buildDeviceFacts(makeCtx(), { amp: {} } as any);
    const osBlock = (facts.namespaces.amp as any).hardware.static.os;

    expect(osBlock.processArch).toBe(nodeOs.arch());
    expect(osBlock.processArch).not.toBe(osBlock.arch);
  });

  it("⚠️ tampoco sale de `osInfo.arch`, que en la flota real vuelve vacío", async () => {
    // El stub de si devuelve "mentira-de-si" a propósito: si apareciera en el
    // payload, el colector habría vuelto a la fuente que lanza un proceso.
    const facts = await buildDeviceFacts(makeCtx(), { amp: {} } as any);
    const osBlock = (facts.namespaces.amp as any).hardware.static.os;

    expect(osBlock.arch).not.toBe("mentira-de-si");
    expect(osBlock.processArch).not.toBe("mentira-de-si");
  });

  it("⭐ agent.arch —el que elige el .msi de un agent_update— usa la misma fuente", async () => {
    // Las dos respuestas tienen que coincidir: si el inventario dice arm64 y
    // el envelope dice x64, el equipo se actualiza por la rama equivocada y
    // sigue emulado para siempre.
    const facts = await buildDeviceFacts(makeCtx(), { amp: {} } as any);

    expect(facts.agent.arch).toBe("arm64");
    expect(detectOsArch).toHaveBeenCalled();
  });
});
