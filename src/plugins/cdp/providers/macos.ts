// src/plugins/cdp/providers/macos.ts
//
// macOS CDP collector. Phase A scope: System keychain + system trust
// roots, read with /usr/bin/security (execFile with argv array — never
// a shell, per the AMP macOS convention).
//
// hasPrivateKey: `security find-identity` lists certs that have a
// matching private key ("identities") as SHA-1 hashes; we intersect
// with the parsed items.
//
// Fase C (2026-08-26): tambien los LOGIN KEYCHAINS por usuario. Es el
// equivalente en macOS de los stores CurrentUser de Windows, y cerrarlo
// aqui elimina una asimetria incomoda — teniamos visibilidad de los
// certificados por usuario en Windows y ninguna en Mac.

import fs from "fs";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import type { CdpCertItem, CdpStoreInfo } from "../../../domain/cdp-types";
import { parseCertToItem, splitPemBundle } from "../parse-cert";

const execFileAsync = promisify(execFile);

const SECURITY_BIN = "/usr/bin/security";
const EXEC_TIMEOUT_MS = 20000;
// A System keychain with hundreds of certs can exceed the default 1MB.
const EXEC_MAX_BUFFER = 16 * 1024 * 1024;

const SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain";
const SYSTEM_ROOTS_KEYCHAIN =
  "/System/Library/Keychains/SystemRootCertificates.keychain";

/** Donde viven los perfiles de usuario en macOS. */
const USERS_DIR = "/Users";

/**
 * Tope de perfiles a recorrer.
 *
 * Un Mac compartido —un aula, un quiosco— puede acumular decenas de
 * perfiles viejos. Cada uno es un `security` que se lanza, asi que sin
 * tope el escaneo crece sin limite en el equipo que menos interesa.
 */
const MAX_LOGIN_KEYCHAINS = 25;

/**
 * Perfiles que no son de una persona. `Shared` y `Guest` son de macOS,
 * y los que empiezan por punto son metadatos del sistema de ficheros.
 */
function isRealUserProfile(name: string): boolean {
  if (name.startsWith(".")) return false;
  return name !== "Shared" && name !== "Guest";
}

/**
 * Login keychains presentes en el equipo.
 *
 * `login.keychain-db` es el formato desde macOS Sierra; `login.keychain`
 * sigue apareciendo en perfiles migrados desde versiones antiguas, y
 * dejarlo fuera significaria no ver nada precisamente en los equipos mas
 * viejos, que son los que peor higiene suelen tener.
 */
export function discoverLoginKeychains(usersDir = USERS_DIR): Array<{ user: string; keychainPath: string }> {
  let entries: string[];
  try {
    entries = fs.readdirSync(usersDir);
  } catch {
    return [];
  }

  const found: Array<{ user: string; keychainPath: string }> = [];
  for (const name of entries.sort()) {
    if (!isRealUserProfile(name)) continue;
    if (found.length >= MAX_LOGIN_KEYCHAINS) break;

    for (const file of ["login.keychain-db", "login.keychain"]) {
      const keychainPath = path.join(usersDir, name, "Library", "Keychains", file);
      let stat: fs.Stats;
      try {
        // lstat y no stat: un enlace simbolico plantado en el perfil de
        // un usuario podria apuntar a cualquier sitio del disco, y esto
        // corre como root.
        stat = fs.lstatSync(keychainPath);
      } catch {
        continue;
      }
      if (!stat.isFile()) continue;
      found.push({ user: name, keychainPath });
      break; // un formato por usuario, el nuevo primero
    }
  }
  return found;
}

export type MacosCdpResult = {
  items: CdpCertItem[];
  stores: CdpStoreInfo[];
  parseFailures: number;
  /**
   * Login keychains encontrados y efectivamente leidos.
   *
   * ⚠️ Existe para que un fallo NO sea silencioso. En produccion el
   * agente corre como root leyendo el keychain de OTRA persona, y ese
   * caso concreto no se ha podido verificar (hace falta una Mac con dos
   * perfiles y sudo). Si root no pudiera leerlos, la funcion devolveria
   * cero certificados sin quejarse — exactamente la forma de capacidad
   * a oscuras que este plugin ya ha sufrido tres veces.
   *
   * Con estos dos numeros, "encontrados 3, leidos 0" es un sintoma
   * visible en el log y en el propio inventario, no un silencio.
   */
  loginKeychains: { discovered: number; read: number };
};

async function readKeychainPems(keychainPath: string): Promise<string[]> {
  const { stdout } = await execFileAsync(
    SECURITY_BIN,
    ["find-certificate", "-a", "-p", keychainPath],
    { timeout: EXEC_TIMEOUT_MS, maxBuffer: EXEC_MAX_BUFFER }
  );
  return splitPemBundle(stdout);
}

/** SHA-1 hashes (lowercase, no colons) of certs that have a private key. */
async function readIdentityHashes(): Promise<Set<string>> {
  try {
    const { stdout } = await execFileAsync(
      SECURITY_BIN,
      ["find-identity", "-v", SYSTEM_KEYCHAIN],
      { timeout: EXEC_TIMEOUT_MS, maxBuffer: EXEC_MAX_BUFFER }
    );

    const hashes = new Set<string>();
    for (const match of stdout.matchAll(/\b([0-9A-F]{40})\b/g)) {
      hashes.add(match[1].toLowerCase());
    }
    return hashes;
  } catch {
    // find-identity fails on keychains with zero identities — that just
    // means "no cert here has a private key", not a collector error.
    return new Set();
  }
}

export async function collectMacosCdp(): Promise<MacosCdpResult> {
  const items: CdpCertItem[] = [];
  const stores: CdpStoreInfo[] = [];
  let parseFailures = 0;
  let loginDiscovered = 0;
  let loginRead = 0;

  const identityHashes = await readIdentityHashes();

  const targets: Array<{ store: CdpStoreInfo; keychainPath: string }> = [
    {
      store: { id: "keychain/system", name: "System.keychain", scope: "machine" },
      keychainPath: SYSTEM_KEYCHAIN
    },
    {
      store: {
        id: "keychain/system-roots",
        name: "SystemRootCertificates.keychain",
        scope: "system-roots"
      },
      keychainPath: SYSTEM_ROOTS_KEYCHAIN
    }
  ];

  // ── Login keychains por usuario ──────────────────────────────────
  //
  // Fallo blando y deliberado, igual que en Windows: un keychain que no
  // se puede leer —bloqueado, corrupto, un perfil a medio migrar— no
  // puede costar el escaneo de maquina que acaba de funcionar.
  //
  // ⚠️ `hasPrivateKey` se queda en false a proposito. Averiguarlo exige
  // `find-identity` contra un keychain que esta BLOQUEADO mientras el
  // usuario no ha iniciado sesion, y forzarlo seria pedir credenciales
  // de una persona. Marcar true sin comprobarlo seria inventar
  // evidencia que nadie recogio — la misma decision que se tomo en
  // CdpUserCertificates.cs.
  //
  // Solo se leen CERTIFICADOS, que son publicos por naturaleza. Ninguna
  // clave privada se toca ni se exporta.
  const loginKeychains = discoverLoginKeychains();
  loginDiscovered = loginKeychains.length;
  for (const { user, keychainPath } of loginKeychains) {
    targets.push({
      store: {
        id: `keychain/login/${user}`,
        name: `login.keychain (${user})`,
        scope: "user"
      },
      keychainPath
    });
  }

  for (const target of targets) {
    let pems: string[];
    try {
      pems = await readKeychainPems(target.keychainPath);
    } catch (err: any) {
      // One unreadable keychain (SIP changes, missing file on future
      // macOS) must not kill the scan of the other.
      parseFailures += 1;
      continue;
    }

    stores.push(target.store);
    if (target.store.scope === "user") loginRead += 1;

    for (const pem of pems) {
      const item = parseCertToItem(pem, { store: target.store });
      if (!item) {
        parseFailures += 1;
        continue;
      }
      if (item.fingerprintSha1 && identityHashes.has(item.fingerprintSha1)) {
        item.hasPrivateKey = true;
      }
      items.push(item);
    }
  }

  return {
    items,
    stores,
    parseFailures,
    loginKeychains: { discovered: loginDiscovered, read: loginRead }
  };
}
