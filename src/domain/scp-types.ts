// src/domain/scp-types.ts
//
// SCP wire schema 2.0.
//
// Schema 2.0 flips the old contract: the agent no longer decides pass/fail
// and no longer ships a `checks[]` array or an `overall` block. It only
// reports *evidence* collected from the platform (firewall, defender,
// bitlocker, smb, shares, cipher suites, TLS protocols, patches, …) and
// the backend evaluator runs the catalog rules against that evidence.
//
// Everything that used to be "agent opinion" (score, per-check status,
// remediation prose) is now computed server-side against the Control-DB
// catalog. That means:
//   - The agent can add new evidence blocks without a server change.
//   - The catalog can change pass/fail logic without a fleet rollout.
//   - Findings keep a stable framework mapping snapshot regardless of
//     which agent version produced the evidence.
//
// Backward compatibility: the backend rejects schema < 2.0 outright
// (see certusws-tracenium/modules/grpc/controlplane.ts → validateScpPayload).

// -------- Wire-format types --------------------------------------------

export type ScpCollector = {
  plugin: "scp";
  /** Agent version that collected the evidence. Gates version-restricted
   *  catalog entries (e.g. macOS rules guarded by collector_version_min). */
  version: string;
};

/** Derived crypto evidence. The raw cipher/protocol arrays from the
 *  platform are expensive to evaluate in the server-side rule DSL, so
 *  the agent precomputes the flags the catalog references directly
 *  (`crypto.tls10Enabled`, `crypto.weakCiphers`, …). The raw arrays are
 *  kept under `ciphers` / `protocols` for diagnostics. */
export type ScpCryptoEvidence = {
  tls10Enabled?: boolean;
  tls11Enabled?: boolean;
  tls12Enabled?: boolean;
  tls13Enabled?: boolean;
  weakCiphers?: string[];
  ciphers?: unknown[];
  protocols?: unknown[];
};

export type ScpPatchesEvidence = {
  items?: unknown[];
  count?: number;
  lastScanUtc?: string;
};

/** Diagnostic block surfaced when the collector itself failed to run
 *  (e.g. PrivSvc unavailable). Carried as evidence so the UI can
 *  visualize "collector down" without inventing synthetic findings. */
export type ScpCollectorError = {
  message: string;
  phase?: string;
};

export type ScpNamespace = {
  schemaVersion: "2.0";
  collector: ScpCollector;

  /** Internal-only: scheduler flag used to decide whether to push the
   *  snapshot. The device-facts builder strips it before send. Kept on
   *  the type so the scheduler's existing hash/diff path compiles. */
  hasChanges: boolean;

  // Windows + cross-platform evidence blocks
  firewall?: unknown;
  defender?: unknown;
  bitlocker?: unknown;
  smb?: unknown;
  shares?: unknown;
  antivirus?: unknown;
  domain?: unknown;
  // Platform integrity (Windows). Passed through verbatim from the privsvc;
  // the backend catalog decides pass/fail. Expected shapes (see
  // certusws-tracenium migration 20260708_compliance_tpm_secureboot.sql):
  //   tpm        { present: bool, ready: bool, version: "2.0"|"1.2"|... }
  //   secureBoot { enabled: bool }
  // Absent on pre-1.2.0 agents / non-UEFI hosts → catalog marks the checks
  // not_applicable.
  tpm?: unknown;
  secureBoot?: unknown;
  crypto?: ScpCryptoEvidence;
  patches?: ScpPatchesEvidence;

  // macOS-specific evidence blocks
  filevault?: unknown;
  gatekeeper?: unknown;
  sip?: unknown;
  screenLock?: unknown;
  services?: unknown;
  softwareUpdate?: unknown;
  accounts?: unknown;

  // Linux-specific evidence blocks. Same `unknown` discipline as the
  // macOS blocks above — the privsvc shapes the raw posture into per-
  // check objects, the agent passes them through verbatim, and the
  // backend catalog evaluator (certusws-tracenium/db/migrations/...
  // compliance_catalog_seed.sql) decides pass/fail server-side. New
  // Linux catalog entries can land server-side without an agent
  // rollout, exactly as schema 2.0 promises.
  //
  // Block guide (filled in by privsvc/linux/src/security-posture.ts):
  //   ssh             effective sshd_config (output of `sshd -T`):
  //                   PermitRootLogin, PasswordAuthentication,
  //                   PubkeyAuthentication, KexAlgorithms, Ciphers,
  //                   MACs, MaxAuthTries, PermitEmptyPasswords, etc.
  //   selinux         mode (enforcing|permissive|disabled), policy
  //                   name (targeted|mls). RHEL-family only;
  //                   `{ applicable: false }` on Debian-family.
  //   apparmor        mode + profile counts. Debian-family only;
  //                   `{ applicable: false }` on RHEL-family.
  //   passwordPolicy  /etc/login.defs values (PASS_MIN_LEN, PASS_MAX_DAYS,
  //                   PASS_MIN_DAYS, PASS_WARN_AGE, ENCRYPT_METHOD).
  //   auditd          installed / enabled / active state of the audit
  //                   subsystem. Optional — many minimal images don't
  //                   ship auditd at all and the catalog handles that
  //                   via not_applicable.
  //   updates         pending patch posture per package manager
  //                   (apt/dnf/yum/zypper): updatesAvailable,
  //                   securityUpdatesAvailable, rebootRequired. Counts
  //                   are null (not 0) when a tool is missing/unparseable
  //                   so the catalog marks not_applicable rather than a
  //                   false "fully patched". Distinct from the shared
  //                   `patches` block, which is installed history (Win/mac).
  //   sysctl          curated kernel/network hardening knobs read from
  //                   /proc/sys, as a NESTED tree (dotted sysctl keys →
  //                   nested objects) so catalog rules address e.g.
  //                   `sysctl.net.ipv4.conf.all.rp_filter`. Absent knobs
  //                   are omitted → not_applicable.
  ssh?: unknown;
  selinux?: unknown;
  apparmor?: unknown;
  passwordPolicy?: unknown;
  //   registry        Windows. Valores de registro leídos a petición del
  //                   control plane (policy `compliance.registryProbes`),
  //                   indexados por la sonda literal `HKLM\...:Valor`.
  //                   Clave ausente → OMITIDA (nunca null): el evaluador
  //                   la trata como `onMissing`. Un solo colector abre
  //                   ~350 controles CIS sin tocar el agente por versión.
  registry?: unknown;
  //   mounts          filesystem hardening for tmp-style mounts
  //                   (tmp / var_tmp / dev_shm): separate + nodev /
  //                   nosuid / noexec. Non-separate targets omit their
  //                   option flags → not_applicable.
  //   pwquality       PAM password quality (/etc/security/pwquality.conf):
  //                   minlen, dictcheck, maxrepeat, etc. Modern complement
  //                   to the legacy passwordPolicy (/etc/login.defs). Only
  //                   explicitly-set knobs reported → unset → not_applicable.
  auditd?: unknown;
  updates?: unknown;
  sysctl?: unknown;
  mounts?: unknown;
  /** Linux encryption-at-rest (lsblk crypt-layer detection). Sprint 4. */
  diskEncryption?: unknown;
  pwquality?: unknown;

  collectorError?: ScpCollectorError;
};
