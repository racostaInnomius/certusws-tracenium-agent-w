// src/plugins/cdp/providers/java-stores.ts
//
// Java keystore discovery for CDP — cross-platform (win/mac/linux).
// Real deployments frequently keep TLS certs for Java apps in JKS /
// PKCS12 keystores, invisible to the OS cert stores. Two sources:
//
//   1. JVM `cacerts` trust stores — auto-discovered from the standard
//      install roots per platform. Reported with scope "system-roots"
//      (vendor-shipped trust bundles, fleet-identical noise by default;
//      the interesting signal — an admin-injected private CA — surfaces
//      via the includeRoots toggle today and fleet-mode diffing in
//      Phase B).
//   2. Operator-configured keystore files (`policy.cdp.javaKeystorePaths`)
//      — the app keystores that actually break production when they
//      expire. Reported with scope "machine" so they land in the
//      default views and the cdp_cert_expiry alert.
//
// Parsing strategy:
//   * JKS (magic 0xFEEDFEED): parsed in-process with jks.ts — no
//     password needed (certs are plaintext; encrypted keys are skipped
//     unread). Key entries mark the leaf cert hasPrivateKey=true.
//   * PKCS12 (JDK 9+ default; cacerts since JDK 18): shelled out to the
//     JVM's own `keytool -list -rfc` with the conventional "changeit"
//     password (read-only; also satisfies passwordless PKCS12).
//     Operator keystores that are PKCS12 with a real password are
//     reported as a store error, not silently skipped.

import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";
import type { AgentContext } from "../../../core/agent-context";
import type { CdpCertItem, CdpStoreInfo, CdpUnreadableStore } from "../../../domain/cdp-types";
import { parseCertToItem, splitPemBundle } from "../parse-cert";
import { looksLikeJks, parseJks } from "../jks";

const execFileAsync = promisify(execFile);

const KEYTOOL_TIMEOUT_MS = 30000;
const KEYTOOL_MAX_BUFFER = 32 * 1024 * 1024;
const MAX_STORE_BYTES = 16 * 1024 * 1024;

type JavaRoot = {
  /** Directory whose children are candidate Java homes. */
  parent: string;
  /** Only children whose name starts with this (case-insensitive). */
  namePrefix?: string;
  /** Appended to each child to reach the actual Java home. */
  suffix?: string;
};

function defaultRootsFor(platform: NodeJS.Platform): JavaRoot[] {
  if (platform === "darwin") {
    return [
      { parent: "/Library/Java/JavaVirtualMachines", suffix: "Contents/Home" },
      // Homebrew: /opt/homebrew/opt/openjdk[@NN] → …/libexec/openjdk.jdk/Contents/Home
      { parent: "/opt/homebrew/opt", namePrefix: "openjdk", suffix: "libexec/openjdk.jdk/Contents/Home" },
      { parent: "/usr/local/opt", namePrefix: "openjdk", suffix: "libexec/openjdk.jdk/Contents/Home" }
    ];
  }
  if (platform === "linux") {
    return [
      { parent: "/usr/lib/jvm" },
      { parent: "/usr/lib64/jvm" },
      { parent: "/usr/java" },
      { parent: "/opt/java" },
      { parent: "/opt", namePrefix: "jdk" }
    ];
  }
  if (platform === "win32") {
    return [
      { parent: "C:\\Program Files\\Java" },
      { parent: "C:\\Program Files (x86)\\Java" },
      { parent: "C:\\Program Files\\Eclipse Adoptium" },
      { parent: "C:\\Program Files\\Eclipse Foundation" },
      { parent: "C:\\Program Files\\Microsoft", namePrefix: "jdk" },
      { parent: "C:\\Program Files\\Zulu" },
      { parent: "C:\\Program Files\\Amazon Corretto" }
    ];
  }
  return [];
}

function listChildren(root: JavaRoot): string[] {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(root.parent, { withFileTypes: true });
  } catch {
    return [];
  }
  const prefix = root.namePrefix?.toLowerCase();
  return entries
    .filter((e) => e.isDirectory() || e.isSymbolicLink())
    .filter((e) => !prefix || e.name.toLowerCase().startsWith(prefix))
    .map((e) => (root.suffix ? path.join(root.parent, e.name, root.suffix) : path.join(root.parent, e.name)));
}

/** Java homes → their cacerts files, deduped by realpath. */
export function discoverJavaCacerts(roots: JavaRoot[]): Array<{ javaHome: string; cacertsPath: string }> {
  const seen = new Set<string>();
  const found: Array<{ javaHome: string; cacertsPath: string }> = [];

  for (const root of roots) {
    for (const home of listChildren(root)) {
      for (const rel of ["lib/security/cacerts", "jre/lib/security/cacerts"]) {
        const candidate = path.join(home, rel);
        let real: string;
        try {
          real = fs.realpathSync(candidate);
        } catch {
          continue;
        }
        if (seen.has(real)) continue;
        try {
          if (!fs.statSync(real).isFile()) continue;
        } catch {
          continue;
        }
        seen.add(real);
        found.push({ javaHome: home, cacertsPath: real });
      }
    }
  }

  return found;
}

function storeIdFor(kind: "cacerts" | "keystore", realPath: string): string {
  const hash = crypto.createHash("sha256").update(realPath).digest("hex").slice(0, 12);
  return `java/${kind}/${hash}`;
}

function keytoolBinFor(javaHome: string): string {
  return path.join(javaHome, "bin", os.platform() === "win32" ? "keytool.exe" : "keytool");
}

async function readViaKeytool(keytoolBin: string, storePath: string): Promise<string[]> {
  const { stdout } = await execFileAsync(
    keytoolBin,
    ["-list", "-rfc", "-keystore", storePath, "-storepass", "changeit"],
    { timeout: KEYTOOL_TIMEOUT_MS, maxBuffer: KEYTOOL_MAX_BUFFER, windowsHide: true }
  );
  return splitPemBundle(stdout);
}

function readStoreFileSafe(storePath: string): Buffer | null {
  try {
    const stat = fs.statSync(storePath);
    if (!stat.isFile() || stat.size === 0 || stat.size > MAX_STORE_BYTES) return null;
    return fs.readFileSync(storePath);
  } catch {
    return null;
  }
}

export type JavaStoreError = { store: string; message: string };

export type JavaStoresResult = {
  items: CdpCertItem[];
  stores: CdpStoreInfo[];
  parseFailures: number;
  storeErrors: JavaStoreError[];
  /** Subconjunto de storeErrors: almacenes que EXISTEN y no se leyeron.
   *  «path not found» no esta aqui: un keystore que ya no existe se ha
   *  ido de verdad, y sus certificados son bajas legitimas. */
  unreadable: CdpUnreadableStore[];
};

type CollectOptions = {
  /** Test seam: override discovery roots. */
  roots?: JavaRoot[];
  /** Test seam: override configured keystore paths. */
  keystorePaths?: string[];
};

function parseStoreBuffer(
  buf: Buffer,
  store: CdpStoreInfo,
  result: JavaStoresResult
): void {
  const entries = parseJks(buf);
  for (const entry of entries) {
    entry.certsDer.forEach((der, idx) => {
      const item = parseCertToItem(der, {
        store,
        // JKS key entries: the leaf (first in chain) is the cert the
        // store holds a private key for. We never touched that key —
        // this is structural metadata from the entry tag alone.
        hasPrivateKey: entry.type === "key" && idx === 0
      });
      if (item) {
        item.source = "java-store";
        result.items.push(item);
      } else {
        result.parseFailures += 1;
      }
    });
  }
}

function parsePemList(pems: string[], store: CdpStoreInfo, result: JavaStoresResult): void {
  for (const pem of pems) {
    const item = parseCertToItem(pem, { store });
    if (item) {
      item.source = "java-store";
      result.items.push(item);
    } else {
      result.parseFailures += 1;
    }
  }
}

export async function collectJavaStores(
  ctx: AgentContext,
  options: CollectOptions = {}
): Promise<JavaStoresResult> {
  const result: JavaStoresResult = { items: [], stores: [], parseFailures: 0, storeErrors: [], unreadable: [] };
  const unreadable = (store: CdpStoreInfo, reason: string) => {
    result.storeErrors.push({ store: store.name.replace(/^Java cacerts - /, ""), message: reason });
    result.unreadable.push({ id: store.id, name: store.name, reason });
  };

  const roots = options.roots ?? defaultRootsFor(os.platform());
  const cacertsList = discoverJavaCacerts(roots);

  // ── 1. JVM cacerts trust stores ──────────────────────────────────
  for (const { javaHome, cacertsPath } of cacertsList) {
    const store: CdpStoreInfo = {
      id: storeIdFor("cacerts", cacertsPath),
      // Separador ASCII a propósito. El guion largo que había aquí
      // llegaba destrozado a la base de datos en una fila de cada
      // varios cientos — `Java cacerts ??` y `Java cacerts ???` —, y
      // como los agregados de la UI se agrupan por NOMBRE, cada
      // destrozo aparecía como un store distinto que no existe.
      //
      // El literal del fuente era UTF-8 correcto, así que el daño
      // ocurre en tránsito y es intermitente. Perseguirlo por toda la
      // pila cuesta mucho más de lo que vale un guion: un carácter no
      // ASCII dentro de un identificador legible no aporta nada y sí
      // abre esta clase de fallo. La identidad de la fila es `id`
      // (derivado de la ruta), así que cambiar el nombre no huérfana
      // nada; las filas ya destrozadas se reemplazan en el siguiente
      // escaneo.
      name: `Java cacerts - ${cacertsPath}`,
      scope: "system-roots"
    };

    const buf = readStoreFileSafe(cacertsPath);
    if (buf === null) {
      unreadable(store, "unreadable or oversized");
      continue;
    }

    try {
      if (looksLikeJks(buf)) {
        result.stores.push(store);
        parseStoreBuffer(buf, store, result);
      } else {
        // PKCS12 cacerts (JDK 18+, or repacked) — use the JVM's own keytool.
        const pems = await readViaKeytool(keytoolBinFor(javaHome), cacertsPath);
        result.stores.push(store);
        parsePemList(pems, store, result);
      }
    } catch (err: any) {
      unreadable(store, err?.message || String(err));
    }
  }

  // ── 2. Operator-configured application keystores ─────────────────
  const configured = options.keystorePaths ?? ctx.policyRuntime.getCdpJavaKeystorePaths();

  for (const rawPath of configured) {
    let real: string;
    try {
      real = fs.realpathSync(rawPath);
    } catch {
      result.storeErrors.push({ store: rawPath, message: "path not found" });
      continue;
    }

    const store: CdpStoreInfo = {
      id: storeIdFor("keystore", real),
      name: real,
      scope: "machine"
    };

    const buf = readStoreFileSafe(real);
    if (buf === null) {
      unreadable(store, "unreadable or oversized");
      continue;
    }

    try {
      if (looksLikeJks(buf)) {
        result.stores.push(store);
        parseStoreBuffer(buf, store, result);
      } else if (cacertsList.length > 0) {
        // PKCS12 app keystore: best-effort with the conventional
        // password via any discovered JVM's keytool. A real password
        // means keytool fails → surfaced as a store error so the
        // operator KNOWS the path isn't being inventoried.
        const pems = await readViaKeytool(keytoolBinFor(cacertsList[0].javaHome), real);
        result.stores.push(store);
        parsePemList(pems, store, result);
      } else {
        unreadable(store, "PKCS12 keystore but no JVM found for keytool fallback");
      }
    } catch (err: any) {
      unreadable(store, err?.message || String(err));
    }
  }

  if (result.storeErrors.length > 0) {
    ctx.logger?.warn?.("CDP: some Java keystores could not be read", {
      errors: result.storeErrors
    });
  }

  return result;
}
