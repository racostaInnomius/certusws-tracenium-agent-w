// test/bootstrap/config-server-base-url.test.ts
//
// De dónde sale la URL del backend, y qué pasa cuando no se puede averiguar.
//
// EL CASO DE CAMPO
//
// DanielA-PC (tenant 111) se pasó semanas fallando cada agent_update con
//
//   update_failed: AggregateError(2): connect ECONNREFUSED ::1:3000;
//                                     connect ECONNREFUSED 127.0.0.1:3000
//
// El agente no intentaba salir a internet: se conectaba a sí mismo. A
// `http://localhost:3000` sólo se llega por el fallback, y al fallback sólo se
// llega si la variable de entorno está vacía Y la lectura del registro no
// devolvió nada. La llave existía y era correcta; la lectura era lo que
// fallaba.
//
// El daño no fue el fallo de lectura —eso se arregla— sino que el fallback lo
// convirtiera en un estado permanente, silencioso e indistinguible de una
// máquina de desarrollo.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const readRegistryValue = vi.fn();
vi.mock("../../src/bootstrap/registry", () => ({
  readRegistryValue: (...a: any[]) => readRegistryValue(...a),
}));

const realPlatform = process.platform;
function setPlatform(p: string) {
  Object.defineProperty(process, "platform", { value: p, configurable: true });
}

/** config.ts resuelve todo en IIFEs al cargar el módulo: hay que reimportarlo. */
async function loadConfig() {
  vi.resetModules();
  return (await import("../../src/bootstrap/config")).config;
}

beforeEach(() => {
  readRegistryValue.mockReset();
  readRegistryValue.mockReturnValue({ value: null, detail: "sin probar" });
  delete process.env.SERVER_BASE_URL;
  delete process.env.CERT_RENEWAL_BASE_URL;
  process.env.GRPC_ENDPOINT = "grpc.tracenium.com:443";
});
afterEach(() => setPlatform(realPlatform));

describe("serverBaseUrl · orden de resolución", () => {
  it("la variable de entorno gana", async () => {
    setPlatform("win32");
    process.env.SERVER_BASE_URL = "https://staging.tracenium.com";
    readRegistryValue.mockReturnValue({ value: "https://api.tracenium.com" });

    expect((await loadConfig()).serverBaseUrl).toBe("https://staging.tracenium.com");
    // ⚠️ No "no se llamó nunca": certRenewalBaseUrl lee SU llave igual. Lo que
    // hay que afirmar es que no se consultó ESTE valor.
    const leidos = readRegistryValue.mock.calls.map((c: any[]) => c[1]);
    expect(leidos).not.toContain("ServerBaseUrl");
  });

  it("sin variable, lee el registro", async () => {
    setPlatform("win32");
    readRegistryValue.mockReturnValue({ value: "https://api.tracenium.com" });

    expect((await loadConfig()).serverBaseUrl).toBe("https://api.tracenium.com");
    expect(readRegistryValue.mock.calls[0][1]).toBe("ServerBaseUrl");
  });
});

describe("serverBaseUrl · cuando no se puede resolver", () => {
  // ⚠️ LA REGRESIÓN QUE ESTE ARCHIVO EXISTE PARA IMPEDIR.
  //
  // El MSI SIEMPRE escribe la llave, así que en un Windows instalado la única
  // forma de llegar aquí es que la LECTURA fallara — un equipo roto, no el
  // portátil de un desarrollador. Devolver localhost ahí es lo que dejó a
  // DanielA-PC conectándose a sí mismo durante semanas, con los updates
  // fallando y la renovación del certificado apuntando al mismo sitio.
  it("en Windows NO inventa localhost", async () => {
    setPlatform("win32");
    readRegistryValue.mockReturnValue({
      value: null,
      detail: "[reg:64] could not run reg.exe (EPERM)",
    });

    const url = (await loadConfig()).serverBaseUrl;
    expect(url).toBeFalsy();
    expect(String(url)).not.toMatch(/localhost|127\.0\.0\.1/);
  });

  // Sin resolver, `getApiBaseUrl` (update-service.ts) lanza
  // `update_api_base_url_missing`: un error con nombre que viaja en el ACK, en
  // vez de un ECONNREFUSED a ::1:3000 que no dice nada de la causa. Aquí se
  // fija el contrato del que depende: el valor tiene que ser falsy.
  it("deja el valor falsy para que getApiBaseUrl lance su error nombrado", async () => {
    setPlatform("win32");
    readRegistryValue.mockReturnValue({ value: null, detail: "[reg:64] EPERM" });

    expect((await loadConfig()).serverBaseUrl).toBeFalsy();
  });

  // Fuera de Windows no hay registro que leer: ahí el fallback SÍ es correcto,
  // es el caso del desarrollador con nada configurado.
  it("fuera de Windows conserva el fallback de desarrollo", async () => {
    setPlatform("darwin");
    readRegistryValue.mockReturnValue({ value: null, detail: "not windows" });

    expect((await loadConfig()).serverBaseUrl).toBe("http://localhost:3000");
  });
});

describe("certRenewalBaseUrl", () => {
  // cert-renewal.ts hace `certRenewalBaseUrl || serverBaseUrl`. Con los dos
  // sin resolver la renovación se queda sin destino — y un certificado que no
  // renueva saca al equipo de la flota cuando caduca.
  it("es opcional, pero no se inventa un destino", async () => {
    setPlatform("win32");
    readRegistryValue.mockReturnValue({ value: null, detail: "[reg:64] EPERM" });

    const config = await loadConfig();
    expect(config.certRenewalBaseUrl).toBeUndefined();
    expect(String(config.certRenewalBaseUrl)).not.toMatch(/localhost/);
  });

  it("usa el valor del registro cuando está", async () => {
    setPlatform("win32");
    readRegistryValue.mockImplementation((_k: string, name: string) =>
      name === "CertRenewalBaseUrl"
        ? { value: "https://pki.tracenium.com" }
        : { value: "https://api.tracenium.com" }
    );

    expect((await loadConfig()).certRenewalBaseUrl).toBe("https://pki.tracenium.com");
  });
});
