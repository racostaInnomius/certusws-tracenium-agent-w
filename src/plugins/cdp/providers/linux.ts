// src/plugins/cdp/providers/linux.ts
//
// Linux CDP collector. Phase A scope: the distro trust store plus the
// conventional server-cert directories, read directly from the
// filesystem (no external commands needed).
//
// Layout differences handled:
//   Debian/Ubuntu : /etc/ssl/certs/*.pem (symlink farm) + ca-certificates.crt bundle
//   RHEL/Fedora   : /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem (bundle)
//                   /etc/pki/tls/certs (server certs)
//
// HARD RULE: key directories (/etc/ssl/private, *.key) are never read.
// hasPrivateKey is always false on Linux in Phase A — associating cert
// files with key files requires opening the key, which we refuse to do.

import fs from "fs";
import path from "path";
import type { CdpCertItem, CdpStoreInfo } from "../../../domain/cdp-types";
import { parseCertToItem, splitPemBundle } from "../parse-cert";

const MAX_FILE_BYTES = 4 * 1024 * 1024;
const CERT_EXTENSIONS = new Set([".pem", ".crt", ".cer"]);

type ScanTarget = {
  store: CdpStoreInfo;
  /** Directory to scan for individual cert files. */
  dir?: string;
  /** Single bundle file with concatenated PEMs. */
  bundle?: string;
};

const SCAN_TARGETS: ScanTarget[] = [
  {
    store: { id: "fs/etc-ssl-certs", name: "/etc/ssl/certs", scope: "system-roots" },
    dir: "/etc/ssl/certs"
  },
  {
    store: {
      id: "fs/ca-trust-bundle",
      name: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
      scope: "system-roots"
    },
    bundle: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
  },
  {
    store: { id: "fs/etc-pki-tls-certs", name: "/etc/pki/tls/certs", scope: "machine" },
    dir: "/etc/pki/tls/certs"
  }
];

export type LinuxCdpResult = {
  items: CdpCertItem[];
  stores: CdpStoreInfo[];
  parseFailures: number;
};

function readCertFileSafe(filePath: string): string | null {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size === 0 || stat.size > MAX_FILE_BYTES) {
      return null;
    }
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

export async function collectLinuxCdp(): Promise<LinuxCdpResult> {
  const stores: CdpStoreInfo[] = [];
  let parseFailures = 0;

  // Dedupe within each store: the Debian symlink farm exposes every
  // cert twice (hash symlink + named file) and the big
  // ca-certificates.crt bundle repeats them all a third time.
  const byId = new Map<string, CdpCertItem>();

  for (const target of SCAN_TARGETS) {
    const pems: string[] = [];

    if (target.bundle) {
      const content = readCertFileSafe(target.bundle);
      if (content === null) continue;
      pems.push(...splitPemBundle(content));
    }

    if (target.dir) {
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(target.dir, { withFileTypes: true });
      } catch {
        continue; // directory absent on this distro — not an error
      }

      for (const entry of entries) {
        const ext = path.extname(entry.name).toLowerCase();
        if (!CERT_EXTENSIONS.has(ext)) continue;
        // NEVER follow into key material even if misplaced here.
        if (entry.name.toLowerCase().includes("key")) continue;

        const content = readCertFileSafe(path.join(target.dir, entry.name));
        if (content === null) continue;
        pems.push(...splitPemBundle(content));
      }
    }

    if (pems.length === 0) continue;

    stores.push(target.store);

    for (const pem of pems) {
      const item = parseCertToItem(pem, { store: target.store });
      if (!item) {
        parseFailures += 1;
        continue;
      }
      if (!byId.has(item.id)) {
        byId.set(item.id, item);
      }
    }
  }

  return { items: [...byId.values()], stores, parseFailures };
}
