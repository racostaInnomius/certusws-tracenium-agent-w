// privsvc/linux/src/fileshares.ts
//
// Pure parsers + shapers for the Linux `smb` (Samba) and `shares` (NFS exports)
// evidence blocks. Dependency-free so the parsing is unit-testable without a
// running Samba/NFS server.
//
// File sharing is OPTIONAL on Linux — most endpoints run neither Samba nor an
// NFS server. So both blocks report `applicable: false` and OMIT their detail
// fields when the service isn't present, letting the backend evaluator mark the
// checks not_applicable (absent path) rather than scoring a host that simply
// doesn't share files.

// ── Samba (smb) ───────────────────────────────────────────────────

/**
 * Extract `server min protocol` from `testparm -s` output. testparm only prints
 * non-default parameters, so an ABSENT line means the modern default (SMB2_02)
 * is in effect — the caller treats that as SMB1 disabled.
 */
export function parseTestparmMinProtocol(stdout: string): string | undefined {
  const m = /^\s*server min protocol\s*=\s*(\S+)/im.exec(stdout || "");
  return m ? m[1] : undefined;
}

// Samba dialect names at or below SMB1 (NT1). Anything else — SMB2/SMB3, or the
// unset modern default — is not SMB1.
const SMB1_AND_BELOW = new Set(["CORE", "COREPLUS", "LANMAN1", "LANMAN2", "NT1", "SMB1"]);

export function deriveSmb1Enabled(minProtocol?: string): boolean {
  if (!minProtocol) return false; // modern Samba default is SMB2_02
  return SMB1_AND_BELOW.has(minProtocol.trim().toUpperCase());
}

// ── NFS exports (shares) ──────────────────────────────────────────

export interface NfsExportSummary {
  exportCount: number;
  /** Exports reachable by ANY host (`*`, `0.0.0.0/0`, or an old-style no-client line). */
  worldExportCount: number;
  /** Exports granting root access to clients (`no_root_squash`). */
  noRootSquashCount: number;
}

/**
 * Parse /etc/exports (+ /etc/exports.d/*.exports) content. Each non-comment line
 * is `<path> [client(opts)] [client(opts)] ...`. A client of `*` / `0.0.0.0/0`,
 * or a line with no client at all, exports to the world; an `no_root_squash`
 * option disables root squashing (a client's root becomes host root).
 */
export function parseExports(text: string): NfsExportSummary {
  let exportCount = 0;
  let worldExportCount = 0;
  let noRootSquashCount = 0;

  for (const raw of (text || "").split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const tokens = line.split(/\s+/);
    // tokens[0] is the export path; the rest are client specs.
    const clients = tokens.slice(1);
    exportCount += 1;

    if (clients.length === 0) {
      worldExportCount += 1; // old-style export with no client = everyone
      continue;
    }
    let world = false;
    let noRootSquash = false;
    for (const c of clients) {
      const host = c.replace(/\(.*$/, "").trim(); // strip "(opts)"
      const opts = /\(([^)]*)\)/.exec(c)?.[1] ?? "";
      if (host === "*" || host === "0.0.0.0/0" || host === "") world = true;
      if (/\bno_root_squash\b/.test(opts)) noRootSquash = true;
    }
    if (world) worldExportCount += 1;
    if (noRootSquash) noRootSquashCount += 1;
  }
  return { exportCount, worldExportCount, noRootSquashCount };
}

// ── Shapers (omit-for-NA) ─────────────────────────────────────────

export function shapeSmbEvidence(installed: boolean, smb1Enabled?: boolean, raw?: string): Record<string, unknown> {
  const out: Record<string, unknown> = { applicable: installed, installed };
  if (installed && typeof smb1Enabled === "boolean") {
    // Nested shape matches the shared cross-platform path `smb.smb1.enabled`.
    out.smb1 = { enabled: smb1Enabled };
  }
  if (raw) out.raw = raw;
  return out;
}

export function shapeSharesEvidence(summary: NfsExportSummary | null): Record<string, unknown> {
  // No NFS exports configured at all → not applicable; omit the counts so the
  // rules resolve not_applicable rather than scoring a non-file-server as clean.
  if (!summary || summary.exportCount === 0) {
    return { applicable: false, nfsExportCount: 0 };
  }
  return {
    applicable: true,
    nfsExportCount: summary.exportCount,
    worldExportCount: summary.worldExportCount,
    noRootSquashCount: summary.noRootSquashCount,
  };
}
