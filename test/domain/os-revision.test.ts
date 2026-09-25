// test/domain/os-revision.test.ts
//
// La revisión de Windows (UBR): el número que dice si un equipo está parcheado.
//
// El caso de campo: 25-sep-2026, RDP caído en `msi-erp` (tenant 111) por un
// defecto documentado de KB5122882. La pregunta era «¿qué otros equipos están en
// esa build?» y el inventario no podía contestarla: guardaba `10.0.20348`, que
// es Windows Server 2022 y no dice nada sobre parches. Lo dice `20348.5622`.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const execFileSync = vi.fn();
vi.mock("child_process", () => ({ execFileSync: (...a: any[]) => execFileSync(...a) }));

const { readOsRevision, composeFullVersion, CURRENT_VERSION_KEY } = await import(
  "../../src/domain/os-revision"
);

/** Una salida de `reg query … /v UBR` tal como la escribe reg.exe. */
const UBR_OUT = (hex: string) =>
  `\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\r\n    UBR    REG_DWORD    ${hex}\r\n\r\n`;

const realPlatform = process.platform;
function setPlatform(p: string) {
  Object.defineProperty(process, "platform", { value: p, configurable: true });
}

beforeEach(() => {
  execFileSync.mockReset();
  setPlatform("win32");
});
afterEach(() => setPlatform(realPlatform));

describe("readOsRevision", () => {
  it("lee el UBR de msi-erp y lo devuelve como entero", () => {
    execFileSync.mockReturnValue(UBR_OUT("0x15f6"));
    expect(readOsRevision()).toEqual({ revision: 5622 });
  });

  it("pregunta por la llave y el valor correctos", () => {
    execFileSync.mockReturnValue(UBR_OUT("0x15f6"));
    readOsRevision();

    const [file, args] = execFileSync.mock.calls[0];
    expect(file).toBe("reg.exe");
    expect(args).toContain(CURRENT_VERSION_KEY);
    expect(args).toContain("UBR");
    // La vista de 64: un proceso de 32 bits sería redirigido a WOW6432Node.
    expect(args).toContain("/reg:64");
  });

  // ⚠️ EL ERROR QUE ESTE MÓDULO EXISTE PARA NO COMETER. `Number("")` es 0, y la
  // revisión 0 es una build REAL (una RTM sin actualizar). Si una lectura
  // fallida se convirtiera en 0, el inventario afirmaría algo falso en vez de
  // admitir que no sabe — y el equipo aparecería como el MENOS parcheado de la
  // flota justo por no haberse podido leer.
  it("no confunde una lectura fallida con la revisión 0", () => {
    execFileSync.mockImplementation(() => {
      throw Object.assign(new Error("x"), { status: 1, stderr: "ERROR: no se encontró" });
    });

    const r = readOsRevision();
    expect(r.revision).toBeNull();
    expect(r.revision).not.toBe(0);
    expect(r.detail).toBeTruthy();
  });

  it("sí acepta la revisión 0 cuando el registro la dice de verdad", () => {
    execFileSync.mockReturnValue(UBR_OUT("0x0"));
    expect(readOsRevision()).toEqual({ revision: 0 });
  });

  it("explica el fallo en vez de tragárselo", () => {
    execFileSync.mockImplementation(() => {
      throw Object.assign(new Error("spawn EPERM"), { code: "EPERM" });
    });

    const { revision, detail } = readOsRevision();
    expect(revision).toBeNull();
    expect(detail).toMatch(/reg\.exe/);
  });

  // Fuera de Windows no es un dato que falte: es un concepto que no existe.
  it("no intenta nada fuera de Windows, y lo dice", () => {
    setPlatform("darwin");
    expect(readOsRevision()).toEqual({ revision: null, detail: "not windows" });
    expect(execFileSync).not.toHaveBeenCalled();
  });
});

describe("composeFullVersion", () => {
  it("compone build y revisión", () => {
    expect(composeFullVersion("10.0.20348", 5622)).toBe("10.0.20348.5622");
  });

  // Sin revisión NO se inventa un `.0`: eso afirmaría una build que no se leyó.
  it("devuelve la build sola cuando no hay revisión", () => {
    expect(composeFullVersion("10.0.20348", null)).toBe("10.0.20348");
  });

  it("no compone sobre un release ausente o vacío", () => {
    expect(composeFullVersion(null, 5622)).toBeNull();
    expect(composeFullVersion("   ", 5622)).toBeNull();
    expect(composeFullVersion(undefined, null)).toBeNull();
  });

  it("no compone sobre algo que no es una cadena", () => {
    expect(composeFullVersion(20348, 5622)).toBeNull();
  });

  it("distingue las dos revisiones que convivían en la flota de T111", () => {
    // 9 servidores en .5622 (con KB5122882) y los equipos en 26200.9457/.9550.
    expect(composeFullVersion("10.0.26200", 9457)).toBe("10.0.26200.9457");
    expect(composeFullVersion("10.0.26200", 9550)).toBe("10.0.26200.9550");
    expect(composeFullVersion("10.0.26200", 9457)).not.toBe(
      composeFullVersion("10.0.26200", 9550)
    );
  });
});
