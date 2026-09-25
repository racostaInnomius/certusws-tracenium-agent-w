// test/bootstrap/registry.test.ts
//
// La lectura del registro que sobrevive a un servicio.
//
// El caso de campo: DanielA-PC (tenant 111). La llave existía —`reg query`
// desde una consola devolvía `https://api.tracenium.com`— y el agente caía al
// fallback en cada arranque, hablando con `localhost:3000` durante semanas.
// El valor estaba; la lectura no llegaba.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const execFileSync = vi.fn();
vi.mock("child_process", () => ({ execFileSync: (...a: any[]) => execFileSync(...a) }));

const { readRegistryValue, readRegistryValueInView, parseRegQueryValue } = await import(
  "../../src/bootstrap/registry"
);

const KEY = "HKLM\\Software\\CertusWS\\Tracenium";
const OUT = (name: string, value: string) =>
  `\r\nHKEY_LOCAL_MACHINE\\Software\\CertusWS\\Tracenium\r\n    ${name}    REG_SZ    ${value}\r\n\r\n`;

const realPlatform = process.platform;
function setPlatform(p: string) {
  Object.defineProperty(process, "platform", { value: p, configurable: true });
}

beforeEach(() => {
  execFileSync.mockReset();
  setPlatform("win32");
});
afterEach(() => setPlatform(realPlatform));

describe("readRegistryValue · invoca reg.exe sin cmd.exe de por medio", () => {
  // ⚠️ ESTE ES EL ARREGLO. `execSync` en Windows ejecuta
  // `cmd.exe /d /s /c "reg query …"`, lo que añade dos dependencias que una
  // consola interactiva siempre tiene y el entorno de un servicio no
  // necesariamente: ComSpec/PATH para encontrar cmd.exe, y permiso para que un
  // servicio genere procesos hijo. Un EDR que restringe eso bloquea un
  // `cmd.exe` colgando de un servicio mucho antes que un `reg.exe` a secas.
  it("ejecuta el binario directo, no una línea de shell", () => {
    execFileSync.mockReturnValue(OUT("ServerBaseUrl", "https://api.tracenium.com"));

    readRegistryValue(KEY, "ServerBaseUrl");

    const [file, args, opts] = execFileSync.mock.calls[0];
    expect(file).toBe("reg.exe");
    expect(Array.isArray(args)).toBe(true);
    // Ni rastro de cmd.exe ni de una cadena con el comando entero.
    expect(String(file)).not.toMatch(/cmd/i);
    expect(opts.windowsHide).toBe(true);
    // stderr capturado: es el renglón que explica el fallo.
    expect(opts.stdio).toEqual(["ignore", "pipe", "pipe"]);
    expect(opts.timeout).toBeGreaterThan(0);
  });

  // Un proceso de 32 bits que lee HKLM\Software\… es redirigido en silencio a
  // WOW6432Node, donde el instalador de 64 bits nunca escribió. `/reg:64` fija
  // la vista sin depender de la arquitectura del proceso.
  it("pide la vista de 64 bits explícitamente", () => {
    execFileSync.mockReturnValue(OUT("ServerBaseUrl", "https://api.tracenium.com"));

    readRegistryValue(KEY, "ServerBaseUrl");

    expect(execFileSync.mock.calls[0][1]).toContain("/reg:64");
  });

  it("devuelve el valor cuando la vista de 64 responde", () => {
    execFileSync.mockReturnValue(OUT("ServerBaseUrl", "https://api.tracenium.com"));
    expect(readRegistryValue(KEY, "ServerBaseUrl")).toEqual({
      value: "https://api.tracenium.com",
    });
  });

  it("cae a la vista de 32 sólo si la de 64 no trae nada", () => {
    execFileSync
      .mockImplementationOnce(() => { throw Object.assign(new Error("nope"), { status: 1 }); })
      .mockImplementationOnce(() => OUT("ServerBaseUrl", "https://legacy.example"));

    expect(readRegistryValue(KEY, "ServerBaseUrl").value).toBe("https://legacy.example");
    expect(execFileSync.mock.calls[1][1]).toContain("/reg:32");
  });
});

describe("readRegistryValue · el fallo se explica, no se traga", () => {
  // ⚠️ EL `catch {}` MUDO ERA EL DAÑO REAL. Sin esto, "no pude leer el
  // registro" y "la llave no existe" son indistinguibles, y el equipo se pasa
  // semanas roto sin una línea que lo diga.
  it("nombra el spawn bloqueado cuando reg.exe no llegó a correr", () => {
    execFileSync.mockImplementation(() => {
      throw Object.assign(new Error("spawn EPERM"), { code: "EPERM" });
    });

    const { value, detail } = readRegistryValue(KEY, "ServerBaseUrl");
    expect(value).toBeNull();
    expect(detail).toMatch(/could not run reg\.exe/);
    expect(detail).toMatch(/EPERM/);
  });

  it("distingue un reg.exe que sí corrió y falló", () => {
    execFileSync.mockImplementation(() => {
      throw Object.assign(new Error("x"), { status: 1, stderr: "ERROR: no se encontró la clave" });
    });

    const { detail } = readRegistryValue(KEY, "Ausente");
    expect(detail).toMatch(/exited 1/);
    // El texto crudo se adjunta: reg.exe escribe en el idioma del sistema, así
    // que clasificar por su contenido falla justo en el equipo del cliente.
    expect(detail).toMatch(/no se encontró la clave/);
  });

  it("reporta las DOS vistas cuando ninguna respondió", () => {
    execFileSync.mockImplementation(() => {
      throw Object.assign(new Error("x"), { code: "ENOENT" });
    });

    const { detail } = readRegistryValue(KEY, "ServerBaseUrl");
    expect(detail).toMatch(/reg:64/);
    expect(detail).toMatch(/reg:32/);
  });

  it("no intenta un spawn imposible fuera de Windows", () => {
    setPlatform("darwin");
    expect(readRegistryValue(KEY, "ServerBaseUrl")).toEqual({
      value: null,
      detail: "not windows",
    });
    expect(execFileSync).not.toHaveBeenCalled();
  });
});

describe("readRegistryValueInView · parseo", () => {
  it("lee un valor con espacios sin truncarlo", () => {
    expect(parseRegQueryValue("X", OUT("X", "C:\\Program Files\\Tracenium"))).toBe(
      "C:\\Program Files\\Tracenium"
    );
  });

  // Salida con la llave pero sin el valor: eso NO es un valor vacío, es un
  // fallo de lectura, y tiene que decirlo.
  it("trata una salida sin el valor como fallo, con motivo", () => {
    execFileSync.mockReturnValue("HKEY_LOCAL_MACHINE\\Software\\CertusWS\\Tracenium\r\n");
    const r = readRegistryValueInView(KEY, "ServerBaseUrl", "64");
    expect(r.value).toBeNull();
    expect(r.detail).toMatch(/unparseable|empty/);
  });
});

describe("parseRegQueryValue · valores numéricos", () => {
  const NUM = (name: string, type: string, value: string) =>
    `\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\r\n    ${name}    ${type}    ${value}\r\n\r\n`;

  // ⚠️ EL CASO QUE MOTIVA ESTO. `UBR` es la revisión de Windows: el número que
  // separa un equipo parcheado de uno que no lo está. Es REG_DWORD, y mientras
  // sólo se admitían REG_SZ/REG_EXPAND_SZ este módulo era incapaz de leerlo —
  // devolvía null con «unparseable», que se lee como «la llave no está».
  it("lee un REG_DWORD y lo devuelve en decimal", () => {
    expect(parseRegQueryValue("UBR", NUM("UBR", "REG_DWORD", "0x15f6"))).toBe("5622");
  });

  it("acepta mayúsculas en el hexadecimal", () => {
    expect(parseRegQueryValue("UBR", NUM("UBR", "REG_DWORD", "0x15F6"))).toBe("5622");
  });

  it("acepta un decimal por si reg.exe lo imprime así", () => {
    expect(parseRegQueryValue("UBR", NUM("UBR", "REG_DWORD", "5622"))).toBe("5622");
  });

  // Un QWORD pasa de MAX_SAFE_INTEGER; con Number se redondearía sin avisar.
  it("no redondea un REG_QWORD grande", () => {
    expect(parseRegQueryValue("Big", NUM("Big", "REG_QWORD", "0x20000000000001"))).toBe(
      "9007199254740993"
    );
  });

  it("devuelve null ante un numérico ilegible en vez de la cadena cruda", () => {
    expect(parseRegQueryValue("UBR", NUM("UBR", "REG_DWORD", "no-es-un-numero"))).toBeNull();
  });

  // La razón de leer el tipo en un grupo aparte es no cambiar lo que ya
  // funcionaba: una cadena sigue saliendo tal cual, sin pasar por el decimal.
  it("no toca los valores de cadena", () => {
    expect(parseRegQueryValue("Path", NUM("Path", "REG_SZ", "0x15f6"))).toBe("0x15f6");
    expect(parseRegQueryValue("V", NUM("V", "REG_EXPAND_SZ", "%SystemRoot%\\x"))).toBe(
      "%SystemRoot%\\x"
    );
  });

  // Un tipo que no se sabe interpretar (binario, multi-cadena) sigue siendo un
  // null honesto: media lectura de un REG_BINARY no es un valor.
  it("sigue ignorando los tipos que no sabe leer", () => {
    expect(parseRegQueryValue("B", NUM("B", "REG_BINARY", "deadbeef"))).toBeNull();
    expect(parseRegQueryValue("M", NUM("M", "REG_MULTI_SZ", "a\\0b"))).toBeNull();
  });
});
