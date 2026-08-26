// test/plugins/cdp-login-keychains.test.ts
//
// Descubrimiento de login keychains por usuario en macOS — fase C.
//
// Es el equivalente de los stores CurrentUser de Windows, y cerrarlo
// elimina una asimetria: teniamos visibilidad de los certificados por
// usuario en Windows y ninguna en Mac.
//
// ⚠️ Solo se leen CERTIFICADOS, que son publicos. `hasPrivateKey` se
// queda en false a proposito: averiguarlo exigiria `find-identity`
// contra un keychain BLOQUEADO mientras el usuario no ha iniciado
// sesion, y forzarlo seria pedir credenciales de una persona. Marcarlo
// true sin comprobarlo seria inventar evidencia que nadie recogio — la
// misma decision que en CdpUserCertificates.cs para Windows.

import fs from "fs";
import os from "os";
import path from "path";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { discoverLoginKeychains } from "../../src/plugins/cdp/providers/macos";

let root: string;

/** Crea un /Users falso con la estructura real de macOS. */
function makeProfile(user: string, keychainFile: string | null) {
  const dir = path.join(root, user, "Library", "Keychains");
  fs.mkdirSync(dir, { recursive: true });
  if (keychainFile) fs.writeFileSync(path.join(dir, keychainFile), "x");
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-users-"));
});
afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe("discoverLoginKeychains", () => {
  it("encuentra el formato moderno y el heredado", () => {
    makeProfile("ana", "login.keychain-db");
    makeProfile("beto", "login.keychain");

    const found = discoverLoginKeychains(root);
    const users = found.map((f) => f.user).sort();

    expect(users).toContain("ana");
    // `login.keychain` a secas sigue apareciendo en perfiles migrados
    // desde macOS antiguos. Dejarlo fuera significaria no ver nada
    // precisamente en los equipos mas viejos, que suelen tener peor
    // higiene.
    expect(users).toContain("beto");
  });

  it("prefiere el formato moderno cuando conviven", () => {
    // Un perfil migrado puede conservar los dos ficheros; leer ambos
    // duplicaria cada certificado del usuario en el inventario.
    makeProfile("carla", null);
    const dir = path.join(root, "carla", "Library", "Keychains");
    fs.writeFileSync(path.join(dir, "login.keychain"), "x");
    fs.writeFileSync(path.join(dir, "login.keychain-db"), "x");

    const carla = discoverLoginKeychains(root).filter((f) => f.user === "carla");
    expect(carla).toHaveLength(1);
    expect(carla[0].keychainPath).toMatch(/login\.keychain-db$/);
  });

  it("ignora los perfiles que no son de una persona", () => {
    makeProfile("Shared", "login.keychain-db");
    makeProfile("Guest", "login.keychain-db");
    makeProfile(".localized", "login.keychain-db");

    const users = discoverLoginKeychains(root).map((f) => f.user);
    expect(users).not.toContain("Shared");
    expect(users).not.toContain("Guest");
    expect(users).not.toContain(".localized");
  });

  it("ignora un perfil sin keychain", () => {
    makeProfile("dani", null);
    expect(discoverLoginKeychains(root).map((f) => f.user)).not.toContain("dani");
  });

  it("no sigue enlaces simbolicos", () => {
    // Esto corre como root: un enlace plantado en el perfil de un
    // usuario podria apuntar a cualquier fichero del disco y hacernos
    // leerlo. `lstat` lo corta de raiz.
    const dir = path.join(root, "eva", "Library", "Keychains");
    fs.mkdirSync(dir, { recursive: true });
    const target = path.join(root, "objetivo-secreto");
    fs.writeFileSync(target, "x");
    fs.symlinkSync(target, path.join(dir, "login.keychain-db"));

    expect(discoverLoginKeychains(root).map((f) => f.user)).not.toContain("eva");
  });

  it("un /Users inexistente no revienta el escaneo", () => {
    // El colector de macOS corre entero dentro de un try por proveedor,
    // pero esta funcion no debe ser la que lo dispare.
    expect(discoverLoginKeychains(path.join(root, "no-existe"))).toEqual([]);
  });

  it("tiene tope: un Mac compartido no puede alargar el escaneo sin limite", () => {
    const big = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-many-"));
    try {
      for (let i = 0; i < 40; i += 1) {
        const dir = path.join(big, `u${String(i).padStart(2, "0")}`, "Library", "Keychains");
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, "login.keychain-db"), "x");
      }
      expect(discoverLoginKeychains(big)).toHaveLength(25);
    } finally {
      fs.rmSync(big, { recursive: true, force: true });
    }
  });
});
