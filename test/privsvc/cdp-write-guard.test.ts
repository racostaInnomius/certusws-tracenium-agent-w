// test/privsvc/cdp-write-guard.test.ts
//
// ADR-0011 fase 1 — la allowlist de destinos escribibles.
//
// ⚠️ NADA invoca todavía estos guards: la fase 3 (`cdp.cert.install`)
// será quien los use. El ADR ordena así las fases porque es la única
// forma de que la defensa no se recorte por presión de calendario cuando
// la funcionalidad ya esté a medio camino. Los tests van con la defensa,
// no con el uso.
//
// Se prueba la ALLOWLIST, que es lógica pura. La validación de cadena
// depende del verificador del sistema y se comprobó EN VIVO en esta Mac:
//   leaf + intermedia → confía · leaf solo → no · autofirmado ajeno → no
// Reproducir eso en CI exigiría una PKI de juguete y un trust store
// manipulable; el valor estaría en la fase 3, con la ruta que lo usa.

import { describe, it, expect } from "vitest";
import { isWritableKeychain } from "../../privsvc/macos/src/cdp-write-guard";
import { isWritablePath } from "../../privsvc/linux/src/cdp-write-guard";

describe("macOS — allowlist de llaveros", () => {
  it("acepta SOLO el llavero de la máquina", () => {
    expect(isWritableKeychain("/Library/Keychains/System.keychain")).toBe(true);
  });

  it("⚠️ NUNCA el bundle de raíces que envía Apple", () => {
    // Otorgar confianza es la amenaza que este ADR existe para gobernar.
    // Además SIP lo protege, así que un intento ni siquiera fallaría de
    // forma limpia.
    expect(
      isWritableKeychain("/System/Library/Keychains/SystemRootCertificates.keychain")
    ).toBe(false);
  });

  it("⚠️ no se deja engañar por un llavero de usuario con el mismo nombre", () => {
    // Comparar por nombre de fichero en vez de por ruta completa sería
    // regalar el gate: cualquiera puede crear un System.keychain en su
    // carpeta.
    expect(isWritableKeychain("/Users/ana/Library/Keychains/System.keychain")).toBe(false);
  });

  it("rechaza vacío, nulo y no-cadena", () => {
    for (const v of ["", "   ", null, undefined, 42]) {
      expect(isWritableKeychain(v as any), String(v)).toBe(false);
    }
  });
});

describe("Linux — allowlist de rutas", () => {
  it("acepta directorios de configuración de servicio", () => {
    for (const p of ["/etc/nginx", "/etc/nginx/ssl/site.pem", "/etc/letsencrypt/live/x/fullchain.pem"]) {
      expect(isWritablePath(p), p).toBe(true);
    }
  });

  it("⚠️ NUNCA los directorios de anclas del sistema", () => {
    // Escribir ahí y correr update-ca-* es otorgar confianza.
    for (const p of [
      "/etc/ssl/certs",
      "/etc/ssl/certs/evil.pem",
      "/usr/local/share/ca-certificates/evil.crt",
      "/etc/pki/ca-trust/source/anchors/evil.pem"
    ]) {
      expect(isWritablePath(p), p).toBe(false);
    }
  });

  it("⚠️ un `..` no puede salirse de la allowlist", () => {
    // Sin normalizar, "/etc/nginx/../ssl/certs/evil.pem" pasaría por
    // empezar con una ruta permitida.
    expect(isWritablePath("/etc/nginx/../ssl/certs/evil.pem")).toBe(false);
    expect(isWritablePath("/etc/nginx/../../root/.ssh/authorized_keys")).toBe(false);
  });

  it("⚠️ un prefijo parecido no cuela", () => {
    // "/etc/nginx-evil" empieza por "/etc/nginx". Sin exigir el
    // separador, entraría.
    expect(isWritablePath("/etc/nginx-evil/x.pem")).toBe(false);
    expect(isWritablePath("/etc/httpd2/x.pem")).toBe(false);
  });

  it("rechaza vacío, nulo y no-cadena", () => {
    for (const v of ["", "  ", null, undefined, 7]) {
      expect(isWritablePath(v as any), String(v)).toBe(false);
    }
  });
});
