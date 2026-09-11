// test/domain/os-arch.test.ts
//
// El caso que se escapó en producción el 2026-09-11: W11-JPR-LAB02 (tenant 1),
// una VM Windows 11 ARM64 sobre Apple Silicon que instaló el .msi arm64 y a la
// que el portal pintaba `Arch = x64` en Asset Management → Hardware Inventory.
// Los macOS arm64 salían bien y por eso nadie lo vio antes: en macOS los dos
// paquetes son nativos, así que preguntar por la arquitectura del PROCESO da
// por casualidad la respuesta correcta. En Windows on ARM, no.
//
// Este suite fija las dos preguntas por separado y, sobre todo, fija que quien
// informa contesta la del SISTEMA. Un test que sólo mirase el caso nativo
// pasaría exactamente igual con el bug dentro.
//
// ⚠️ La sonda se INYECTA en vez de tocar `process.env`: la máquina emulada no
// está en el CI, y un test que dependa del host donde corre mediría el host.

import { describe, it, expect } from "vitest";
import {
  detectOsArch,
  reportedOsArch,
  resolveOsArch,
  currentArchProbe,
  type ArchProbe
} from "../../src/domain/os-arch";

/** Windows 11 ARM64 con el agente corriendo x64 bajo emulación: WOW64 publica
 *  la arquitectura NATIVA en ARCHITEW6432 y la del proceso en ARCHITECTURE. */
const WIN_ARM64_EMULANDO_X64: ArchProbe = {
  platform: "win32",
  processArch: "x64",
  env: { PROCESSOR_ARCHITECTURE: "AMD64", PROCESSOR_ARCHITEW6432: "ARM64" }
};

/** Windows 11 ARM64 con el agente arm64 nativo: ARCHITEW6432 no existe. */
const WIN_ARM64_NATIVO: ArchProbe = {
  platform: "win32",
  processArch: "arm64",
  env: { PROCESSOR_ARCHITECTURE: "ARM64" }
};

/** Windows x64 de toda la vida. */
const WIN_X64_NATIVO: ArchProbe = {
  platform: "win32",
  processArch: "x64",
  env: { PROCESSOR_ARCHITECTURE: "AMD64" }
};

describe("os-arch — Windows on ARM ejecutando el agente emulado", () => {
  it("⭐ EL BUG: un proceso x64 sobre ARM64 se reporta arm64, no x64", () => {
    // `os.arch()` diría "x64" aquí, y eso es lo que llegaba al portal.
    expect(reportedOsArch(WIN_ARM64_EMULANDO_X64)).toBe("arm64");
  });

  it("la del proceso NO se pierde: sigue disponible al lado de la del sistema", () => {
    // Las dos juntas son el diagnóstico «este equipo está emulando». Si el
    // arreglo hubiese sido sustituir un valor por otro, esta señal
    // desaparecería y la próxima investigación tendría que ir al equipo.
    expect(WIN_ARM64_EMULANDO_X64.processArch).toBe("x64");
    expect(detectOsArch(WIN_ARM64_EMULANDO_X64)).toBe("arm64");
  });

  it("el self-update pide el binario arm64, no el x64 que está corriendo", () => {
    // Sin esto el equipo se queda clavado en la rama x64 para siempre: se
    // actualiza, sigue emulado, y vuelve a pedir x64.
    expect(resolveOsArch(WIN_ARM64_EMULANDO_X64)).toBe("arm64");
  });

  it("x86 de 32 bits sobre ARM64 también es una máquina arm64", () => {
    expect(
      reportedOsArch({
        platform: "win32",
        processArch: "ia32",
        env: { PROCESSOR_ARCHITECTURE: "x86", PROCESSOR_ARCHITEW6432: "ARM64" }
      })
    ).toBe("arm64");
  });

  it("x86 de 32 bits sobre x64 es una máquina x64", () => {
    expect(
      reportedOsArch({
        platform: "win32",
        processArch: "ia32",
        env: { PROCESSOR_ARCHITECTURE: "x86", PROCESSOR_ARCHITEW6432: "AMD64" }
      })
    ).toBe("x64");
  });
});

describe("os-arch — los casos nativos no cambian", () => {
  it("Windows ARM64 nativo → arm64", () => {
    expect(reportedOsArch(WIN_ARM64_NATIVO)).toBe("arm64");
    expect(resolveOsArch(WIN_ARM64_NATIVO)).toBe("arm64");
  });

  it("Windows x64 nativo → x64", () => {
    expect(reportedOsArch(WIN_X64_NATIVO)).toBe("x64");
    expect(resolveOsArch(WIN_X64_NATIVO)).toBe("x64");
  });

  it("macOS arm64 → arm64 (el caso que YA salía bien y no debe romperse)", () => {
    expect(reportedOsArch({ platform: "darwin", processArch: "arm64", env: {} })).toBe("arm64");
  });

  it("Linux arm64 y x64 salen por el arch del proceso", () => {
    expect(reportedOsArch({ platform: "linux", processArch: "arm64", env: {} })).toBe("arm64");
    expect(reportedOsArch({ platform: "linux", processArch: "x64", env: {} })).toBe("x64");
  });

  it("⚠️ las variables de Windows NO se miran fuera de Windows", () => {
    // Un contenedor Linux puede llevarlas heredadas de cualquier sitio. La
    // plataforma decide qué fuente es válida.
    expect(
      reportedOsArch({
        platform: "linux",
        processArch: "x64",
        env: { PROCESSOR_ARCHITEW6432: "ARM64" }
      })
    ).toBe("x64");
  });
});

describe("os-arch — cuando no se puede saber", () => {
  it("entorno de Windows recortado: cae al proceso en vez de inventarse una", () => {
    expect(reportedOsArch({ platform: "win32", processArch: "arm64", env: {} })).toBe("arm64");
  });

  it("⚠️ informar y elegir binario se separan en una arquitectura que no publicamos", () => {
    const riscv: ArchProbe = { platform: "linux", processArch: "riscv64", env: {} };

    // Informar dice la verdad: un `riscv64` disfrazado de x64 en el inventario
    // es justo la mentira que ADR-0016 convertiría en un paquete equivocado.
    expect(detectOsArch(riscv)).toBeNull();
    expect(reportedOsArch(riscv)).toBe("riscv64");

    // Elegir binario no admite «no sé» —sólo hay dos ramas publicadas— y
    // mantiene el desempate histórico.
    expect(resolveOsArch(riscv)).toBe("x64");
  });
});

describe("os-arch — la escotilla TRACENIUM_ARCH", () => {
  it("manda sobre todo lo demás, y manda en las CUATRO respuestas", () => {
    // El camino de actualización ya la respetaba (sus tests la usan para fijar
    // el arch del host). Si forzara el instalador arm64 mientras el inventario
    // sigue diciendo x64, volveríamos a tener dos verdades.
    const forzado: ArchProbe = {
      ...WIN_X64_NATIVO,
      env: { ...WIN_X64_NATIVO.env, TRACENIUM_ARCH: "arm64" }
    };
    expect(resolveOsArch(forzado)).toBe("arm64");
    expect(reportedOsArch(forzado)).toBe("arm64");
  });

  it("un valor que no es ninguna de las dos se ignora", () => {
    expect(
      reportedOsArch({ ...WIN_X64_NATIVO, env: { ...WIN_X64_NATIVO.env, TRACENIUM_ARCH: "sí" } })
    ).toBe("x64");
  });
});

describe("os-arch — la sonda por defecto", () => {
  it("es la forma que leen los llamadores reales, que no pasan nada", () => {
    // Los cuatro sitios del agente llaman sin argumentos. Si la sonda por
    // defecto dejara de leer `process`, los tests de arriba seguirían verdes
    // midiendo fixtures y producción quedaría sin fuente.
    const probe = currentArchProbe();
    expect(probe.platform).toBe(process.platform);
    expect(probe.processArch).toBe(process.arch);
    expect(probe.env.PATH).toBe(process.env.PATH);

    expect(reportedOsArch()).toBe(reportedOsArch(probe));
  });
});
