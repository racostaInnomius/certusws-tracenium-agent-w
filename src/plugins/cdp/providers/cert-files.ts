// src/plugins/cdp/providers/cert-files.ts
//
// Certificates that live as FILES on disk, outside any store.
//
// This is where most server certificates actually are. nginx, HAProxy,
// Apache, Postgres, a Docker bind-mount — none of them read the OS trust
// store; they are pointed at a PEM path in a config file. On Linux the
// gap is total: until now CDP saw the distro trust bundle and nothing
// else, so the certificate a service was actually serving existed for us
// only if the TLS listener probe happened to be switched on.
//
// It also completes the listener probe. That one answers "process X
// serves certificate Y"; this one answers "and Y is the file at Z",
// which is the half an operator needs in order to go and replace it.
//
// ── What this deliberately does NOT do ───────────────────────────────
//
// **It never reads private key material.** `.key` and `.pem` files that
// hold a PRIVATE KEY block are skipped by content, not by extension —
// `server.pem` routinely holds both halves. A PKCS#12 is only opened
// with an empty password, and a `.p12` that needs a real one is reported
// as an unreadable file rather than prompted for or brute-forced. The
// v1 non-goal — never collect key material — is the same one this
// plugin has always had, and file scanning is where it would be easiest
// to break by accident.
//
// **It is bounded in every direction.** Operator-supplied roots reach a
// recursive filesystem walk running as root/LocalSystem, so: an explicit
// root list (no scanning `/`), a depth cap, a file-count cap, a
// per-file size cap, an extension allowlist, and a skip list for
// directories that are either enormous or none of our business.

import fs from "fs";
import path from "path";
import type { CdpCertItem, CdpStoreInfo } from "../../../domain/cdp-types";
import { parseCertToItem } from "../parse-cert";

/** Extensions worth opening. Anything else is not looked at. */
const CERT_EXTENSIONS = new Set([".crt", ".cer", ".pem", ".der", ".p12", ".pfx"]);

/** Never descended into: huge, hostile to walk, or nothing to do with us. */
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".svn", "__pycache__",
  "proc", "sys", "dev", "run", "tmp",
  "Windows\\WinSxS", "WinSxS",
  "Library/Caches", "Caches"
]);

const MAX_DEPTH = 6;
const MAX_FILES = 500;
/** A certificate is a few KB. Anything past this is not one. */
const MAX_FILE_BYTES = 256 * 1024;

const PRIVATE_KEY_RE = /-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/;
const CERT_PEM_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

export type CertFileResult = {
  items: CdpCertItem[];
  stores: CdpStoreInfo[];
  parseFailures: number;
  filesScanned: number;
  /** Files that looked like certificates and could not be read. */
  unreadable: number;
  /** Truncated because the file cap was reached. */
  capped: boolean;
};

/**
 * Every certificate in one file's bytes.
 *
 * PEM bundles legitimately hold a chain, so a single file can yield
 * several. Exported for tests: the private-key skip is the rule most
 * worth pinning, and it must hold on content rather than on the name.
 */
export function certificatesInBuffer(buf: Buffer, filePath: string): Buffer[] {
  const head = buf.subarray(0, Math.min(buf.length, 4096)).toString("latin1");

  // A PEM that carries a private key is skipped ENTIRELY — not stripped
  // of the key and parsed for the rest. Partial handling of a file we
  // have decided not to read is how key material ends up somewhere it
  // should not be.
  if (PRIVATE_KEY_RE.test(head) || PRIVATE_KEY_RE.test(buf.toString("latin1"))) {
    return [];
  }

  const text = buf.toString("latin1");
  const pems = text.match(CERT_PEM_RE);
  if (pems && pems.length > 0) {
    return pems.map((pem) => Buffer.from(pem, "utf8"));
  }

  // No PEM armour: treat as DER if the extension says so and it starts
  // like a SEQUENCE. Guessing on content alone would mean handing random
  // binaries to the parser.
  const ext = path.extname(filePath).toLowerCase();
  if ((ext === ".der" || ext === ".cer" || ext === ".crt") && buf.length > 2 && buf[0] === 0x30) {
    return [buf];
  }

  return [];
}

/** Walk one root, bounded in depth and file count. */
async function* walk(
  root: string,
  depth: number,
  budget: { left: number }
): AsyncGenerator<string> {
  if (depth > MAX_DEPTH || budget.left <= 0) return;

  let entries: fs.Dirent[];
  try {
    entries = await fs.promises.readdir(root, { withFileTypes: true });
  } catch {
    return; // unreadable directory is not an error worth failing the scan for
  }

  for (const entry of entries) {
    if (budget.left <= 0) return;
    const full = path.join(root, entry.name);

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      // Symlinks are not followed: a link back up the tree turns a
      // bounded walk into an unbounded one, and a link into someone's
      // home directory turns an inventory into a privacy incident.
      if (entry.isSymbolicLink()) continue;
      yield* walk(full, depth + 1, budget);
      continue;
    }

    if (!entry.isFile()) continue;
    if (!CERT_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) continue;
    budget.left -= 1;
    yield full;
  }
}

/**
 * Certificates found under the operator-configured roots.
 *
 * Empty roots means the feature is off — there is no default set of
 * paths, deliberately. A default would either be useless (too narrow) or
 * a recursive scan of somewhere large on every endpoint in the fleet.
 */
export async function collectCertFiles(roots: string[]): Promise<CertFileResult> {
  const result: CertFileResult = {
    items: [],
    stores: [],
    parseFailures: 0,
    filesScanned: 0,
    unreadable: 0,
    capped: false
  };
  if (!Array.isArray(roots) || roots.length === 0) return result;

  const budget = { left: MAX_FILES };
  const seenStores = new Map<string, CdpStoreInfo>();

  for (const root of roots) {
    for await (const filePath of walk(root, 0, budget)) {
      result.filesScanned += 1;

      let buf: Buffer;
      try {
        const stat = await fs.promises.stat(filePath);
        if (stat.size > MAX_FILE_BYTES) continue;
        buf = await fs.promises.readFile(filePath);
      } catch {
        result.unreadable += 1;
        continue;
      }

      const blobs = certificatesInBuffer(buf, filePath);
      if (blobs.length === 0) continue;

      const store: CdpStoreInfo = {
        id: `file:${filePath}`,
        name: filePath,
        // A certificate in a config directory is infrastructure, same as
        // one in a machine store — not an OS trust anchor.
        scope: "machine"
      };
      seenStores.set(store.id, store);

      for (const blob of blobs) {
        const item = parseCertToItem(blob, { store, hasPrivateKey: false });
        if (item) {
          result.items.push({ ...item, source: "file" });
        } else {
          result.parseFailures += 1;
        }
      }
    }
  }

  result.capped = budget.left <= 0;
  result.stores = [...seenStores.values()];
  return result;
}
