// src/plugins/cdp/providers/macos.ts
//
// macOS CDP collector. Phase A scope: System keychain + system trust
// roots, read with /usr/bin/security (execFile with argv array — never
// a shell, per the AMP macOS convention).
//
// hasPrivateKey: `security find-identity` lists certs that have a
// matching private key ("identities") as SHA-1 hashes; we intersect
// with the parsed items. Login keychains (per-user) are Phase C.

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

export type MacosCdpResult = {
  items: CdpCertItem[];
  stores: CdpStoreInfo[];
  parseFailures: number;
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

  return { items, stores, parseFailures };
}
