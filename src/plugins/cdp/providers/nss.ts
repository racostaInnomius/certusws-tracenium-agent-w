// src/plugins/cdp/providers/nss.ts
//
// Almacenes NSS — Firefox, Thunderbird y demás software de Mozilla.
//
// ── Por qué merece la pena para 5 equipos de 76 ─────────────────────
//
// Firefox tiene su PROPIO almacén de confianza, independiente del
// sistema operativo. Una CA importada ahí es invisible para todo lo
// demás que recolecta CDP: no está en el store de Windows, ni en el
// llavero de macOS, ni en el bundle de la distro. Es exactamente el
// hueco donde una CA de proxy interceptor o una raíz corporativa se
// instala sin dejar rastro en ninguno de los sitios que ya miramos.
//
// Medido en la flota el 2026-08-31: 5 equipos de 76 tienen Firefox
// (T1 tres, T111 uno, T113 uno). Pocos, pero son 5 almacenes de
// confianza que hoy no vemos en absoluto.
//
// ── El formato, verificado contra una base REAL ─────────────────────
//
// ⚠️ Nada de esto se dedujo: se midió sobre un `cert9.db` fabricado con
// `certutil` y un certificado conocido, y se comprobó que la huella
// SHA-256 del DER extraído coincide con la del original.
//
//   · `cert9.db` es SQLite y tiene UNA tabla: `nssPublic`.
//   · Las columnas son atributos PKCS#11 en hexadecimal: `a0` es
//     CKA_CLASS, `a3` CKA_LABEL, `a11` CKA_VALUE.
//   · `a0` guarda la clase como 4 bytes: `00000001` = CKO_CERTIFICATE.
//     `0000000B` (11) es CKO_NSS_TRUST, la fila de confianza, que NO es
//     un certificado y hay que excluir o se cuela como parseo fallido.
//   · `a11` es el DER tal cual.
//
// Se lee con `better-sqlite3`, que el agente ya empaqueta: no hace falta
// `certutil` ni ninguna herramienta de NSS en el endpoint.
//
// ⚠️ `cert8.db` (formato Berkeley DB, anterior a Firefox 58) NO se lee.
// No es SQLite, exigiría un parser propio, y el software que lo usa
// lleva años sin recibir actualizaciones. Se DETECTA y se reporta como
// store ilegible, que es más honesto que ignorarlo en silencio: un
// equipo con cert8.db tiene un almacén de confianza que no estamos
// mirando, y eso el operador debería saberlo.

import fs from "fs";
import os from "os";
import path from "path";
import type { CdpCertItem, CdpStoreInfo, CdpUnreadableStore } from "../../../domain/cdp-types";
import { parseCertToItem } from "../parse-cert";

/** CKO_CERTIFICATE en el `a0` de 4 bytes, tal como lo guarda NSS. */
const CKO_CERTIFICATE_HEX = "00000001";

/** Tope de perfiles. Un equipo compartido acumula perfiles viejos. */
const MAX_PROFILES = 20;

/** Un cert9.db normal ronda los 30 KB; uno gigante no es un cert9.db. */
const MAX_DB_BYTES = 64 * 1024 * 1024;

export type NssResult = {
  items: CdpCertItem[];
  stores: CdpStoreInfo[];
  parseFailures: number;
  /** Bases encontradas que no se pudieron leer (incluye cert8.db). */
  unreadable: Array<{ path: string; reason: string }>;
  /** Las que SI son un almacen que inventariamos y hoy no se leyo
   *  (cert8.db no: nunca se lee, nunca estuvo en la baseline). */
  unreadableStores: CdpUnreadableStore[];
};

/**
 * Directorios donde Mozilla guarda perfiles, por plataforma.
 *
 * Se enumeran los perfiles de TODOS los usuarios porque el agente corre
 * como root/SYSTEM y el punto ciego es por usuario: el certificado que
 * importó una persona en su Firefox no está en ningún sitio compartido.
 */
export function mozillaProfileRoots(homeDirs: string[], platform = os.platform()): string[] {
  const roots: string[] = [];
  for (const home of homeDirs) {
    if (platform === "darwin") {
      roots.push(
        path.join(home, "Library", "Application Support", "Firefox", "Profiles"),
        path.join(home, "Library", "Thunderbird", "Profiles")
      );
    } else if (platform === "win32") {
      roots.push(
        path.join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
        path.join(home, "AppData", "Roaming", "Thunderbird", "Profiles")
      );
    } else {
      roots.push(
        path.join(home, ".mozilla", "firefox"),
        path.join(home, ".thunderbird")
      );
    }
  }
  return roots;
}

/** Directorios personales del equipo. */
export function homeDirectories(platform = os.platform()): string[] {
  const base = platform === "darwin" ? "/Users" : platform === "win32" ? "C:\\Users" : "/home";
  try {
    return fs
      .readdirSync(base)
      .filter((n) => !n.startsWith(".") && !["Shared", "Guest", "Public", "Default"].includes(n))
      .map((n) => path.join(base, n));
  } catch {
    return [];
  }
}

export type FoundDb = { dbPath: string; profile: string; legacy: boolean };

/** Bases NSS bajo los directorios de perfiles dados. */
export function discoverNssDatabases(profileRoots: string[]): FoundDb[] {
  const found: FoundDb[] = [];
  for (const root of profileRoots) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(root, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (found.length >= MAX_PROFILES) return found;
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
      const dir = path.join(root, entry.name);
      const moderno = path.join(dir, "cert9.db");
      const heredado = path.join(dir, "cert8.db");
      if (fs.existsSync(moderno)) {
        found.push({ dbPath: moderno, profile: entry.name, legacy: false });
      } else if (fs.existsSync(heredado)) {
        // Se registra para poder DECIRLO, no para leerlo.
        found.push({ dbPath: heredado, profile: entry.name, legacy: true });
      }
    }
  }
  return found;
}

/**
 * Certificados de un `cert9.db`.
 *
 * Se abre en SOLO LECTURA e inmutable: Firefox puede estar corriendo con
 * la base abierta, y un lector normal se encontraría con el bloqueo o —
 * peor— intentaría recuperar el WAL y ESCRIBIRÍA en el perfil de una
 * persona. Un inventario no toca lo que inventaría.
 */
export function readNssCertificates(dbPath: string): Buffer[] {
  // Import perezoso: better-sqlite3 es un módulo nativo y cargarlo en
  // plataformas donde no hay ninguna base NSS sería pagar por nada.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const Database = require("better-sqlite3");
  const db = new Database(dbPath, { readonly: true, fileMustExist: true });
  try {
    const rows = db
      .prepare(
        // `hex(a0) = '00000001'` deja fuera las filas CKO_NSS_TRUST
        // (clase 11), que no llevan certificado: sin este filtro
        // entrarían como parseos fallidos y ensuciarían el contador.
        `SELECT a11 AS der FROM nssPublic WHERE hex(a0) = ? AND a11 IS NOT NULL`
      )
      .all(CKO_CERTIFICATE_HEX) as Array<{ der: Buffer }>;
    return rows.map((r) => r.der).filter((b) => Buffer.isBuffer(b) && b.length > 0);
  } finally {
    try {
      db.close();
    } catch {
      /* cerrar no puede costar el escaneo */
    }
  }
}

export async function collectNssStores(): Promise<NssResult> {
  const result: NssResult = { items: [], stores: [], parseFailures: 0, unreadable: [], unreadableStores: [] };

  const bases = discoverNssDatabases(mozillaProfileRoots(homeDirectories()));

  for (const { dbPath, profile, legacy } of bases) {
    if (legacy) {
      result.unreadable.push({
        path: dbPath,
        reason: "cert8.db (formato heredado, anterior a Firefox 58) — no se lee"
      });
      continue;
    }

    const store: CdpStoreInfo = {
      id: `nss/${profile}`,
      name: `NSS ${dbPath}`,
      // `user`: es el almacén de una persona, no del equipo. Y NO
      // `system-roots`: NSS no es el bundle del sistema operativo, así
      // que aquí la presencia SÍ es una decisión de alguien.
      scope: "user"
    };
    const unreadable = (reason: string) => {
      result.unreadable.push({ path: dbPath, reason });
      result.unreadableStores.push({ id: store.id, name: store.name, reason });
    };

    try {
      const stat = fs.statSync(dbPath);
      if (stat.size > MAX_DB_BYTES) {
        unreadable("demasiado grande");
        continue;
      }
    } catch (err: any) {
      // ENOENT = el perfil se borro: sus certificados se fueron de verdad.
      if (err?.code === "ENOENT") continue;
      unreadable(String(err?.message || err));
      continue;
    }

    let ders: Buffer[];
    try {
      ders = readNssCertificates(dbPath);
    } catch (err: any) {
      // Fallo blando: una base bloqueada o corrupta no puede costar el
      // resto del escaneo.
      unreadable(String(err?.message || err));
      continue;
    }

    result.stores.push(store);
    for (const der of ders) {
      const item = parseCertToItem(der, { store, hasPrivateKey: false });
      if (item) result.items.push({ ...item, source: "nss" });
      else result.parseFailures += 1;
    }
  }

  return result;
}
