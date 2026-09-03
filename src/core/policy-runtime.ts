// src/core/policy-runtime.ts
import { parseProbeTarget, probeTargetKey, type ProbeTarget } from "../domain/probe-target";
import { EventEmitter } from "events";
import { PolicyStore } from "./policy-store";
import {
  parseGatewayConfig,
  type GatewayConfig
} from "../connectors/vcenter/gateway-config";
// Imported rather than re-implemented: the jail and the policy validator MUST
// agree on what counts as an acceptable path, and two copies of that rule
// would eventually drift — in a security control, silently. path-jail has no
// imports beyond node:fs / node:path, so this introduces no cycle.
import {
  sanitizeAbsolutePaths,
  type PathJailConfig
} from "../plugins/rcp/path-jail";

// RuntimePolicy
//
// The shape the agent reads from the persisted policy file. Two
// branches are recognized by the validator so we can roll out the
// "Policy v2" structure without breaking older policy documents in
// flight:
//
//   * Legacy (v1, pre-Sprint-1 of Policy v2): top-level
//     `inventory.intervalSeconds`, `compliance.intervalSeconds`, etc.
//     Still the wire format produced by older backends.
//
//   * Nested under `agent.*` (v2, "Agent Policy" block): all of the
//     same operational settings live under a single `agent` object
//     so the policy document has room for a sibling `security.*`
//     block in later sprints (see Policy v2 plan).
//
// Both branches read the same fields; the validator merges v2 → v1
// shape at parse time, so all the existing getters (and every gate
// in scheduler.ts) keep working unchanged. New code can read from
// either v1 or v2 input.
export type RuntimePolicy = {
  version?: string;
  inventory?: {
    intervalSeconds?: number;
  };
  compliance?: {
    intervalSeconds?: number;
    /**
     * Claves de registro de Windows que el PrivSvc debe leer y reportar
     * tal cual, con la forma `HKLM\Ruta\A\Clave:NombreDelValor`.
     *
     * La lista NO la conoce el agente: la deriva el control plane del
     * catálogo de compliance (todo check cuyo evaluador lee
     * `registry.<clave>`) y la inyecta en la policy al servirla. Así una
     * versión nueva de un benchmark CIS es un cambio de backend y no una
     * release del agente — que se auto-actualiza y tarda días en llegar
     * a toda la flota.
     *
     * Sólo HKLM. Las 352 sondas de los tres benchmarks CIS de Windows
     * viven ahí (medido 2026-09-03: 0 en HKCU), y el PrivSvc corre como
     * SYSTEM, cuyo HKCU no es el del usuario.
     */
    registryProbes?: string[];
  };
  patch?: {
    intervalSeconds?: number;
  };
  update?: {
    intervalSeconds?: number;
  };
  cdp?: {
    intervalSeconds?: number;
    /** Operator-configured Java keystore files (JKS/PKCS12) to
     *  inventory in addition to the auto-discovered JVM cacerts.
     *  Absolute paths; validated + capped in validatePolicy. */
    javaKeystorePaths?: string[];
    /** Opt-in: probe local TLS listeners to capture the certificate
     *  each service actually serves. Off by default — it is the only
     *  collector that opens sockets. Loopback only. */
    scanTlsListeners?: boolean;
    /** Optional narrowing: when non-empty, ONLY these ports are probed
     *  (still intersected with what is actually listening). */
    tlsListenerPorts?: number[];
    certFilePaths?: string[];
    /**
     * Rol Probe (fase 2, analisis de madurez 2026-09): objetivos TLS
     * remotos `host:port` que este equipo sondea para inventariar lo que
     * sirven y lo que negocian — balanceadores, appliances, bases de
     * datos, hipervisores sin agente. Solo lo que escriba el operador:
     * el agente no descubre. Saneado y acotado al recibir la policy.
     */
    probeTargets?: string[];
    /**
     * Conector AD CS (fase 4): en un equipo con el rol Certification
     * Authority, leer la base de emisiones por RequestID (incremental) y
     * reportarla. Opt-in: es una lectura grande y solo tiene sentido en
     * un CA server.
     */
    adcs?: { enabled?: boolean; maxPerScan?: number };
  };
  /** Remote Control tuning that isn't a simple on/off capability gate.
   *  The `features.remote*` flags decide WHETHER a capability runs; this
   *  block decides HOW it is constrained once it does. */
  rcp?: {
    file?: {
      /** Absolute subtrees `rcp.file` may reach. Empty/absent ⇒ the agent's
       *  platform defaults (user profiles, temp, app data). Replacing this
       *  list replaces the defaults entirely — it is not additive. */
      roots?: string[];
      /** Extra absolute subtrees to seal, merged with the agent's built-in
       *  deny list (its own credential directory, registry hives, /etc
       *  secrets). Deny always beats roots. */
      denyPaths?: string[];
      /** Extra file extensions to seal, merged with the built-in list of
       *  private-key / credential container formats. */
      denyExtensions?: string[];
    };
  };
  /** Infrastructure Gateway. Delivered ONLY in a per-device policy override,
   *  to the single host per site that has line-of-sight to vCenter — never in
   *  the tenant-wide policy. Deliberately NOT a `plugins.enabled` entry: the
   *  fleet plugins act on the endpoint they run on, this one brokers to a third
   *  party on behalf of the site. The PRESENCE of a valid block is the
   *  enablement, so there is no separate flag to drift out of sync, and a
   *  `vcenter_snapshot` job aimed at any other endpoint finds no config and is
   *  rejected. Shape is validated by connectors/vcenter/gateway-config.
   *  See ADR-0001 (A). */
  gateway?: {
    vcenter?: {
      url?: string;
      port?: number;
      /** SHA-256 pin. REQUIRED — vCenter certs are self-signed by the VMCA, so
       *  without it nothing authenticates the server we hand credentials to. */
      tlsThumbprintSha256?: string;
      /** Key into the gateway's OS credential store. NEVER the secret. */
      credentialRef?: string;
    };
    scope?: {
      datacenter?: string;
      folders?: string[];
    };
    snapshot?: {
      memory?: boolean;
      quiesce?: boolean;
      retentionHours?: number;
      maxConcurrent?: number;
      perVmTimeoutSec?: number;
    };
  };
  plugins?: {
    enabled?: string[];
  };
  modules?: {
    inventory?: boolean;
    update?: boolean;
    patch?: boolean;
    compliance?: boolean;
  };
  features?: {
    // realtimeInventory was an experimental flag that never shipped a
    // real consumer in the agent. Removed in Sprint 1 of Policy v2.
    // If an older policy document still carries the field, the
    // validator silently drops it.
    //
    // RCP capability gates — each maps to an `rcp.*` capability
    // advertised in Hello and checked in SessionManager.onOffer.
    remoteShell?: boolean;    // rcp.shell  (M1)
    remoteFile?: boolean;     // rcp.file   (M2.S1)
    remoteScreen?: boolean;   // rcp.screen (M3.S1)
    // User-attended approval: when true, the agent must obtain end-user consent
    // at the endpoint before opening any RCP session (SessionManager.onOffer
    // prompt). The backend fail-closes if the agent can't prompt (doesn't
    // advertise rcp.consent).
    remoteRequireConsent?: boolean;
    // Grabación de sesiones de pantalla (ADR-0012, decisión 2).
    //
    // ⚠️ APAGADO por defecto y así debe quedarse. Un tenant que no ha decidido
    // grabar no debe tener vídeo de las pantallas de sus usuarios en ningún
    // sitio, ni siquiera temporalmente en el disco del propio equipo — de ahí
    // que se descartara "grabar siempre y usar el toggle solo para retener".
    //
    // Afecta SOLO a rcp.screen. El shell ya deja transcript y el gestor de
    // ficheros deja auditoría de transferencias; ninguno de los dos expone lo
    // que la persona tiene delante en ese instante.
    //
    // El texto del consentimiento DEPENDE de este flag: si se graba, el
    // diálogo lo dice. Ver consent-text.ts.
    remoteRecordScreen?: boolean;
    selfUpdate?: boolean;
    // Device-info widget: when true, the Windows AgentTray shows the
    // always-visible top-center flyout with device info for support
    // calls. The tray reads this via tray-status.json (policy.features).
    // The in-window Device Info tab is NOT gated — only the flyout.
    deviceInfoWidget?: boolean;
    // Endpoint positioning: when true, the agent asks the OPERATING SYSTEM for
    // a coordinate (Windows Geolocation / macOS CoreLocation) and reports it in
    // amp.geo. Off by default and fail-closed everywhere: a coordinate is
    // personal data, and the backend re-checks this same switch before storing
    // anything. Deliberately separate from mam.locationTracking — company
    // phones and employee laptops are different populations.
    locationTracking?: boolean;
  };

  // Policy v2 — Agent Policy block. When present, the validator
  // merges these fields DOWN into the top-level legacy shape (e.g.
  // `agent.schedules.update.intervalSeconds` becomes
  // `policy.update.intervalSeconds`). v1 (top-level) and v2 (under
  // agent.*) can coexist in the same document during the migration;
  // v2 wins on conflict because it's the newer authoring path.
  agent?: {
    schedules?: {
      inventory?: { intervalSeconds?: number };
      compliance?: { intervalSeconds?: number };
      patch?: { intervalSeconds?: number };
      update?: { intervalSeconds?: number };
      cdp?: { intervalSeconds?: number };
    };
    plugins?: { enabled?: string[] };
    modules?: {
      inventory?: boolean;
      update?: boolean;
      patch?: boolean;
      compliance?: boolean;
    };
    features?: {
      remoteShell?: boolean;
      remoteFile?: boolean;
      remoteScreen?: boolean;
      remoteRequireConsent?: boolean;
      remoteRecordScreen?: boolean;
      selfUpdate?: boolean;
      deviceInfoWidget?: boolean;
      locationTracking?: boolean;
    };
  };

  // Policy v2 — Security Policy block (Sprint 2). Declares desired
  // posture for capabilities the agent can already CHECK (SCP
  // collectors) and OPTIONALLY enforce (pmp.remediate handlers).
  //
  // Per-capability `mode`:
  //   "auto"        : enforcer remediates on drift (only valid for
  //                   capabilities backed by a working pmp.remediate
  //                   handler — see SECURITY_CAPABILITY_REMEDIATORS
  //                   in src/security/enforcer.ts).
  //   "report-only" : enforcer reads state, logs drift, never
  //                   modifies the system. Default for every
  //                   capability — operators must explicitly flip
  //                   to "auto" per-item.
  //   "off"         : enforcer skips the capability entirely. The
  //                   SCP collector still reports raw evidence, but
  //                   the policy field is treated as "no opinion".
  //
  // Capabilities without an existing remediator (passwordPolicy,
  // bitlocker, usb, shares, localAccounts) are accepted in the
  // schema as placeholders. Setting mode="auto" on those is a no-op
  // until a future sprint ships the corresponding handlers — the
  // enforcer logs a debug line and moves on.
  security?: SecurityPolicy;
};

export type SecurityMode = "auto" | "report-only" | "off";

export type SecurityPolicy = {
  // Version of the security policy CATALOG the operator authored
  // against. Independent from the top-level policy `version` —
  // lets us bump the security schema (add fields, change defaults)
  // without invalidating every existing policy document.
  version?: string;

  // Default mode applied to capabilities that have a desired value
  // set but no explicit `mode`. Useful for a "fail-safe" override:
  // setting defaultMode="off" disables ALL security enforcement
  // even if individual capabilities are configured.
  defaultMode?: SecurityMode;

  // Minimum interval between successive AUTO remediation attempts
  // for the SAME checkId, in minutes. Defaults to 60. Operators in
  // change-tightened environments may want longer (e.g. 720 = 12h)
  // to ensure each remediation gets a full business-hours review
  // window before the agent retries. Short cooldowns are useful in
  // CI / lab fleets where rapid iteration matters more than churn.
  //
  // Bounds enforced by the backend validator: [1, 1440] minutes
  // (1 minute to 24 hours). Agent-side validator clamps the same
  // range — values outside are silently replaced with the default.
  cooldownMinutes?: number;

  // ── Functional (have an existing pmp.remediate handler) ─────────

  firewall?: {
    mode?: SecurityMode;
    required?: boolean;
  };

  ssh?: {
    mode?: SecurityMode;
    permitRootLogin?: "yes" | "no";       // → linux.ssh.root_login_disabled
    passwordAuthentication?: boolean;     // → linux.ssh.password_auth_disabled
    weakKexDisabled?: boolean;            // → linux.cryptography.weak_ssh_kex_disabled
  };

  tls?: {
    mode?: SecurityMode;
    legacyDisabled?: boolean;             // → windows.cryptography.legacy_tls_disabled
    weakCiphersDisabled?: boolean;        // → windows.cryptography.weak_ciphers_disabled
  };

  smb?: {
    mode?: SecurityMode;
    smbv1Disabled?: boolean;              // → windows.network_sharing.smbv1_disabled
  };

  // ── macOS (privsvc/macos/src/pmp-remediation.ts) ────────────────
  // On macOS the GPO-equivalent surface splits in two: things a root
  // agent can actually change (below), and things that need a
  // configuration profile from an MDM (restrictions, managed prefs,
  // PPPC) which no agent can apply. These are the first group.

  gatekeeper?: {
    mode?: SecurityMode;
    required?: boolean;                   // → macos.gatekeeper.enabled (READ + REMEDIATE)
  };

  remoteLogin?: {
    mode?: SecurityMode;
    disabled?: boolean;                   // → macos.remote_login.disabled (READ + REMEDIATE)
  };

  // ── macOS read-only (drift is visible, remediation is impossible) ──
  // Both have working READ handlers, so `report-only` gives real drift
  // reporting. Neither can be remediated headless, and privsvc returns
  // `unsupported_check` if asked:
  //   * SIP is only togglable from the Recovery OS (`csrutil enable`).
  //   * FileVault activation needs the user's password AND a Recovery
  //     Key prompt — not safely automatable without MDM escrow.
  // The backend validator rejects mode="auto" on these with
  // UNENFORCEABLE_DESIRED_STATE so the operator is told at authoring
  // time rather than discovering it in agent logs.

  sip?: {
    mode?: SecurityMode;
    required?: boolean;                   // → macos.sip.enabled (READ only)
  };

  filevault?: {
    mode?: SecurityMode;
    required?: boolean;                   // → macos.filevault.enabled (READ only)
  };

  // ── Placeholders (SCP collector exists, no remediator yet) ──────

  passwordPolicy?: {
    mode?: SecurityMode;
    passMaxDaysMax?: number;       // CIS recommends ≤ 365
    encryptMethod?: string;        // e.g. "SHA512" / "YESCRYPT"
  };

  bitlocker?: {
    mode?: SecurityMode;
    required?: boolean;
  };

  usb?: {
    mode?: SecurityMode;
    blocklist?: string[];          // VID:PID entries
    allowlist?: string[];
  };

  shares?: {
    mode?: SecurityMode;
    denyEveryoneFullControl?: boolean;
  };
};

type RuntimeModuleName = keyof NonNullable<RuntimePolicy["modules"]>;
type RuntimeFeatureName = keyof NonNullable<RuntimePolicy["features"]>;

// Features that were once part of the wire shape but have been
// removed in subsequent revisions. We accept them silently on input
// (so stale tenant policies don't 400 out the validator) but drop
// them before storing — no live consumer in the agent reads them.
//
// Currently:
//   * realtimeInventory — experimental flag, removed in Sprint 1 of
//     Policy v2; never wired to a real producer.
const DROPPED_FEATURE_NAMES = new Set<string>(["realtimeInventory"]);

function stripDroppedFeatures(input: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(input)) {
    if (!DROPPED_FEATURE_NAMES.has(k)) out[k] = v;
  }
  return out;
}

// Allowed values for SecurityPolicy.*.mode and .defaultMode. Anything
// outside this set is clamped to "report-only" — the safe choice
// (read state, never modify the system). Centralized constant so the
// enforcer and the validator agree on what's recognized.
const SECURITY_VALID_MODES = new Set<string>(["auto", "report-only", "off"]);

// Cooldown bounds (in minutes) for the per-checkId AUTO remediation
// throttle. Backend validator enforces the same range — anything
// outside is silently replaced with SECURITY_COOLDOWN_DEFAULT_MIN here
// so a buggy operator-supplied value can't break the enforcer's
// schedule arithmetic.
const SECURITY_COOLDOWN_MIN_MINUTES = 1;
const SECURITY_COOLDOWN_MAX_MINUTES = 1440; // 24h
const SECURITY_COOLDOWN_DEFAULT_MIN = 60;   // 1h — matches pre-B7 hardcoded value

// Capability keys we recognize on the wire. Unknown keys (typo,
// forward-compat from a newer backend) are silently dropped at parse
// time so the enforcer never iterates garbage.
const SECURITY_KNOWN_CAPABILITIES = new Set<string>([
  "firewall",
  "ssh",
  "tls",
  "smb",
  // macOS. Agents older than 1.1.26 drop these (unknown capability keys
  // are discarded at parse time), so a tenant policy carrying them is
  // safe to roll out ahead of the fleet update — it just does nothing
  // until the agent catches up.
  "gatekeeper",
  "remoteLogin",
  "sip",
  "filevault",
  "passwordPolicy",
  "bitlocker",
  "usb",
  "shares"
]);

function coerceMode(raw: unknown): SecurityMode {
  if (typeof raw === "string" && SECURITY_VALID_MODES.has(raw)) {
    return raw as SecurityMode;
  }
  return "report-only";
}

// Clamp the operator-supplied cooldown to the documented bounds.
// Returns the default if the value is missing, non-numeric, or
// outside [1, 1440]. Logged at debug-level so an out-of-range value
// is recoverable from an agent log without breaking enforcement.
function clampCooldownMinutes(raw: unknown, logger: any): number {
  if (raw === undefined || raw === null) return SECURITY_COOLDOWN_DEFAULT_MIN;
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n)) {
    logger?.debug?.("security policy: cooldownMinutes not an integer, using default", { raw });
    return SECURITY_COOLDOWN_DEFAULT_MIN;
  }
  if (n < SECURITY_COOLDOWN_MIN_MINUTES || n > SECURITY_COOLDOWN_MAX_MINUTES) {
    logger?.debug?.("security policy: cooldownMinutes out of range, using default", {
      raw: n,
      min: SECURITY_COOLDOWN_MIN_MINUTES,
      max: SECURITY_COOLDOWN_MAX_MINUTES
    });
    return SECURITY_COOLDOWN_DEFAULT_MIN;
  }
  return n;
}

// Validate + normalize the security block. Always returns a NEW
// object even if input was already clean — keeps the caller's
// reference-equality semantics predictable when policyChanged fires.
function sanitizeSecurityPolicy(input: any, logger: any): SecurityPolicy {
  if (!input || typeof input !== "object") {
    return { defaultMode: "report-only", cooldownMinutes: SECURITY_COOLDOWN_DEFAULT_MIN };
  }
  const out: SecurityPolicy = {
    version: typeof input.version === "string" ? input.version : undefined,
    defaultMode: coerceMode(input.defaultMode),
    cooldownMinutes: clampCooldownMinutes(input.cooldownMinutes, logger),
  };

  for (const [k, v] of Object.entries(input)) {
    if (k === "version" || k === "defaultMode" || k === "cooldownMinutes") continue;
    if (!SECURITY_KNOWN_CAPABILITIES.has(k)) {
      logger?.debug?.("security policy: dropping unknown capability", { capability: k });
      continue;
    }
    if (!v || typeof v !== "object" || Array.isArray(v)) continue;

    // Generic per-capability sanitizer: keep recognized fields,
    // clamp `mode` to the enum, leave everything else as-is.
    // Capability-specific value validation (e.g. "permitRootLogin
    // must be 'yes' or 'no'") would force a per-capability switch
    // here — we punt that to the backend validator + the enforcer,
    // since both are better-equipped to surface validation errors
    // back to the operator. Agent-side we just keep the field
    // alive so the enforcer can decide.
    const sanitized: any = { ...(v as object) };
    if ("mode" in sanitized) {
      sanitized.mode = coerceMode(sanitized.mode);
    }
    (out as any)[k] = sanitized;
  }

  return out;
}

// Bounds for cdp.javaKeystorePaths — a policy is operator-authored but
// still crosses a trust boundary before reaching a SYSTEM/root process,
// so paths are validated hard: absolute, bounded length, bounded count.
const CDP_KEYSTORE_PATHS_MAX = 50;
const CDP_KEYSTORE_PATH_MAXLEN = 512;

function sanitizeJavaKeystorePaths(input: unknown, logger: any): string[] {
  if (!Array.isArray(input)) return [];

  const out: string[] = [];
  const seen = new Set<string>();

  for (const raw of input) {
    if (out.length >= CDP_KEYSTORE_PATHS_MAX) {
      logger?.warn?.("cdp.javaKeystorePaths: cap reached, dropping remainder", {
        cap: CDP_KEYSTORE_PATHS_MAX
      });
      break;
    }
    if (typeof raw !== "string") continue;
    const trimmed = raw.trim();
    if (!trimmed || trimmed.length > CDP_KEYSTORE_PATH_MAXLEN) continue;
    // Absolute paths only: POSIX "/..." or Windows drive "C:\...".
    const isAbsolute = trimmed.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(trimmed);
    if (!isAbsolute) {
      logger?.debug?.("cdp.javaKeystorePaths: dropping non-absolute path", { path: trimmed });
      continue;
    }
    if (seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }

  return out;
}

// Extensions for the rcp.file deny list. Same trust-boundary reasoning as the
// path sanitizer: operator-authored, consumed by a root process. Must be a
// dot-prefixed token, no separators, bounded length and count.
const JAIL_EXTENSIONS_MAX = 32;

function sanitizeExtensions(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of input) {
    if (out.length >= JAIL_EXTENSIONS_MAX) break;
    if (typeof raw !== "string") continue;
    const ext = raw.trim().toLowerCase();
    if (!ext.startsWith(".") || ext.length < 2 || ext.length > 16) continue;
    if (/[\\/\0]/.test(ext)) continue;
    if (seen.has(ext)) continue;
    seen.add(ext);
    out.push(ext);
  }
  return out;
}

// Ports are operator-authored but reach a socket-opening loop, so the
// list is bounded and every entry must be a real TCP port number.
const CDP_TLS_PORTS_MAX = 64;

function sanitizeTlsListenerPorts(input: unknown, logger: any): number[] {
  if (!Array.isArray(input)) return [];

  const out: number[] = [];
  for (const raw of input) {
    if (out.length >= CDP_TLS_PORTS_MAX) {
      logger?.warn?.("cdp.tlsListenerPorts: cap reached, dropping remainder", {
        cap: CDP_TLS_PORTS_MAX
      });
      break;
    }
    const port = Number(raw);
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
    if (out.includes(port)) continue;
    out.push(port);
  }

  return out;
}

// Objetivos de sonda remota: operator-authored pero acaban en un socket
// hacia fuera del equipo, asi que forma estricta, sin loopback, acotados
// y deduplicados. La forma la decide UN parser compartido con el
// colector (domain/probe-target.ts).
const CDP_PROBE_TARGETS_MAX = 200;

export function sanitizeProbeTargets(input: unknown, logger?: any): string[] {
  if (!Array.isArray(input)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of input) {
    if (out.length >= CDP_PROBE_TARGETS_MAX) {
      logger?.warn?.("cdp.probeTargets: cap reached, dropping remainder", { cap: CDP_PROBE_TARGETS_MAX });
      break;
    }
    const t = parseProbeTarget(raw);
    if (!t) {
      logger?.debug?.("cdp.probeTargets: dropping invalid target", { raw: String(raw).slice(0, 80) });
      continue;
    }
    const key = probeTargetKey(t);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(key);
  }
  return out;
}

const DEFAULT_POLICY: RuntimePolicy = {
  inventory: {
    intervalSeconds: 21600 // 6h
  },
  compliance: {
    intervalSeconds: 28800 // 8h
  },
  patch: {
    intervalSeconds: 86400 // 24h
  },
  update: {
    // Was hardcoded to 6h (21600s) in scheduler.ts:343 before Sprint 1
    // of Policy v2. Pulled into policy so operators can tune how often
    // the agent's self-update probe runs (the actual install is still
    // gated by `modules.update` / `features.selfUpdate`).
    intervalSeconds: 21600 // 6h
  },
  cdp: {
    // Cert stores are near-static: 12h keeps expiry data fresh enough
    // for the default 30-day warn window while staying cheap. The
    // pipeline only runs at all when the tenant policy enables the
    // "cdp" plugin — the interval alone does not opt a device in.
    intervalSeconds: 43200 // 12h
  },
  plugins: {
    enabled: ["amp"]
  },
  modules: {
    inventory: true,
    update: true,
    patch: false,
    compliance: false
  },
  features: {
    remoteShell: false,
    remoteFile:  false,
    remoteScreen: false,
    remoteRequireConsent: false,
    // Fail closed, y aquí "cerrado" es NO grabar: un agente que no puede leer
    // su política no debe empezar a guardar vídeo de la pantalla de nadie.
    remoteRecordScreen: false,
    selfUpdate: true,
    deviceInfoWidget: false,
    // Fail closed. An agent that cannot read its policy must not start
    // collecting positions.
    locationTracking: false
  }
};

/**
 * Deja pasar sólo lo que el PrivSvc puede leer sin sorpresas.
 *
 * La lista la escribe el control plane, no un operador, pero la policy
 * viaja como JSON y cualquiera con el endpoint de "raw JSON" puede tocarla.
 * Lo que se acota:
 *   · sólo HKLM — el PrivSvc corre como SYSTEM y su HKCU no es el del
 *     usuario; una sonda HKCU devolvería el valor equivocado en silencio.
 *   · forma `HKLM\Ruta:Valor`, sin caracteres que puedan colarse en un
 *     nombre de subclave con otra intención.
 *   · tope de 2.000 entradas y 400 caracteres cada una. Los tres
 *     benchmarks CIS de Windows suman 352; el margen es holgado y a la vez
 *     impide que una policy corrupta convierta cada ciclo en un barrido
 *     del registro entero.
 */
export function sanitizeRegistryProbes(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (typeof item !== "string") continue;
    const probe = item.trim();
    if (probe.length === 0 || probe.length > 400) continue;
    if (!/^HKLM\\[^:*?"<>|\r\n]+:[^\\:*?"<>|\r\n]+$/i.test(probe)) continue;
    if (seen.has(probe)) continue;
    seen.add(probe);
    out.push(probe);
    if (out.length >= 2000) break;
  }
  return out;
}

export class PolicyRuntime extends EventEmitter {

  private policy: RuntimePolicy = DEFAULT_POLICY;

  constructor(private store: PolicyStore, private logger: any) {
    super();
  }

  // ---------- initialization ----------

  async init() {
    const loaded = this.store.getPolicy();

    if (!loaded) {
      this.logger?.info?.("PolicyRuntime: no stored policy, using defaults");
      this.policy = JSON.parse(JSON.stringify(DEFAULT_POLICY));
      return;
    }

    const validated = this.validatePolicy(loaded);

    this.policy = validated;

    this.logger?.info?.("PolicyRuntime initialized", {
      version: this.store.getVersion(),
      plugins: validated.plugins?.enabled
    });
  }

  // ---------- getters ----------

  getPolicy(): RuntimePolicy {
    return this.policy;
  }

  getInventoryInterval(): number {
    return this.policy.inventory?.intervalSeconds || DEFAULT_POLICY.inventory!.intervalSeconds!;
  }

  getComplianceInterval(): number {
    return this.policy.compliance?.intervalSeconds || DEFAULT_POLICY.compliance!.intervalSeconds!;
  }

  /**
   * Claves de registro que el colector SCP de Windows debe leer. Vacío
   * si la policy no las trae — el PrivSvc entonces no emite el bloque
   * `registry` y el catálogo resuelve esos controles como not_applicable,
   * que es lo correcto para un agente que aún no las recibe.
   */
  getRegistryProbes(): string[] {
    return this.policy.compliance?.registryProbes ?? [];
  }

  getPatchInterval(): number {
    return this.policy.patch?.intervalSeconds || DEFAULT_POLICY.patch!.intervalSeconds!;
  }

  getUpdateInterval(): number {
    return this.policy.update?.intervalSeconds || DEFAULT_POLICY.update!.intervalSeconds!;
  }

  getCdpInterval(): number {
    return this.policy.cdp?.intervalSeconds || DEFAULT_POLICY.cdp!.intervalSeconds!;
  }

  getCdpJavaKeystorePaths(): string[] {
    return this.policy.cdp?.javaKeystorePaths ?? [];
  }

  /** Opt-in gate for the TLS listener probe — off unless policy says so. */
  getCdpScanTlsListeners(): boolean {
    return this.policy.cdp?.scanTlsListeners === true;
  }

  /**
   * Rutas donde buscar certificados sueltos en disco.
   *
   * Sin default a propósito: lista vacía = función apagada. Un default
   * seria inutil (demasiado estrecho) o un escaneo recursivo de algo
   * grande en cada endpoint de la flota.
   */
  /** Conector AD CS: si leer la base de la CA, y cuantas filas por escaneo. */
  getCdpAdcs(): { enabled: boolean; maxPerScan: number } {
    const a = this.policy.cdp?.adcs;
    return { enabled: a?.enabled === true, maxPerScan: Number(a?.maxPerScan) || 2000 };
  }

  /** Objetivos remotos ya saneados, como pares host/port. */
  getCdpProbeTargets(): ProbeTarget[] {
    return (this.policy.cdp?.probeTargets ?? [])
      .map((s) => parseProbeTarget(s))
      .filter((t): t is ProbeTarget => t !== null);
  }

  getCdpCertFilePaths(): string[] {
    return this.policy.cdp?.certFilePaths ?? [];
  }

  getCdpTlsListenerPorts(): number[] {
    return this.policy.cdp?.tlsListenerPorts ?? [];
  }

  /**
   * Confinement config for `rcp.file`. Always returns an object — the jail
   * treats empty lists as "use the platform defaults", so an unset policy
   * yields the secure default posture rather than an unconstrained session.
   */
  getRcpFileJailConfig(): PathJailConfig {
    return {
      roots: this.policy.rcp?.file?.roots ?? [],
      denyPaths: this.policy.rcp?.file?.denyPaths ?? [],
      denyExtensions: this.policy.rcp?.file?.denyExtensions ?? []
    };
  }

  // Returns the security policy block, or null if the operator hasn't
  // authored one. Callers (the security enforcer in src/security/
  // enforcer.ts) treat null as "no security policy active — skip the
  // entire enforcement pipeline".
  //
  // We don't merge in defaults here because security capabilities are
  // OPT-IN: an unset capability means "no opinion", which is
  // semantically different from "default value applied". The
  // enforcer handles the per-capability default-mode resolution
  // (combining `security.defaultMode` with each capability's own
  // `mode`).
  getSecurityPolicy(): SecurityPolicy | null {
    return this.policy.security ?? null;
  }

  getEnabledPlugins(): string[] {
    return this.policy.plugins?.enabled || DEFAULT_POLICY.plugins!.enabled!;
  }

  isModuleEnabled(module: RuntimeModuleName): boolean {
    return this.policy.modules?.[module] ?? false;
  }

  isInventoryEnabled(): boolean {
    return this.isModuleEnabled("inventory");
  }

  isUpdateEnabled(): boolean {
    return this.isModuleEnabled("update") || this.isFeatureEnabled("selfUpdate");
  }

  isComplianceEnabled(): boolean {
    return this.isModuleEnabled("compliance");
  }

  isPatchEnabled(): boolean {
    return this.isModuleEnabled("patch");
  }

  isFeatureEnabled(feature: RuntimeFeatureName): boolean {
    return this.policy.features?.[feature] ?? false;
  }

  // ---------- update handling ----------

  async applyUpdate() {
    const newPolicy = this.store.getPolicy();

    if (!newPolicy) {
      this.logger?.warn?.("PolicyRuntime: update requested but no policy found in store");
      return;
    }

    const validated = this.validatePolicy(newPolicy);

    const previousVersion = this.store.getVersion();

    this.policy = validated;

    this.logger?.info?.("PolicyRuntime updated", {
      version: previousVersion,
      inventoryInterval: validated.inventory?.intervalSeconds,
      plugins: validated.plugins?.enabled
    });

    // notify runtime components
    this.emit("policyChanged", this.policy);

    // notify specialized listeners
    this.emit("inventoryIntervalChanged", this.getInventoryInterval());
    this.emit("patchIntervalChanged", this.getPatchInterval());
    this.emit("complianceIntervalChanged", this.getComplianceInterval());
    this.emit("updateIntervalChanged", this.getUpdateInterval());
    this.emit("cdpIntervalChanged", this.getCdpInterval());
    this.emit("pluginsChanged", this.getEnabledPlugins());
    this.emit("modulesChanged", this.listEnabledModules());
    this.emit("featuresChanged", this.policy.features);
    this.emit("securityPolicyChanged", this.getSecurityPolicy());
    // ADR-0013 — el rol de gateway es tambien el interruptor de la clave
    // que abre la credencial de vCenter. Se emite el bloque validado, no
    // un booleano: el oyente necesita saber que cambio, no solo que hubo
    // cambio.
    this.emit("gatewayChanged", this.gatewayConfig());
  }

  // ---------- validation ----------

  private validatePolicy(policy: any): RuntimePolicy {
    if (typeof policy !== "object" || policy === null) {
      return JSON.parse(JSON.stringify(DEFAULT_POLICY));
    }

    // ── Policy v2 merge: agent.* → top-level ──────────────────────
    //
    // The v2 authoring path nests operational settings under an
    // `agent` block so we can host a sibling `security` block in
    // later sprints. The agent runtime keeps reading from the
    // top-level fields (every existing getter + every gate in
    // scheduler.ts), so we copy v2 values DOWN to v1 positions
    // here. v2 wins on conflict because it's the newer source of
    // truth.
    //
    // realtimeInventory is intentionally dropped: it was an
    // experimental feature flag that never gained a consumer. Even
    // if a stale policy document carries it, the validator drops
    // it on the floor.
    const fromAgent = policy.agent ?? {};
    const fromSchedules = fromAgent.schedules ?? {};

    const mergedInventory = {
      intervalSeconds:
        fromSchedules.inventory?.intervalSeconds ??
        policy.inventory?.intervalSeconds ??
        DEFAULT_POLICY.inventory!.intervalSeconds
    };
    const mergedCompliance = {
      intervalSeconds:
        fromSchedules.compliance?.intervalSeconds ??
        policy.compliance?.intervalSeconds ??
        DEFAULT_POLICY.compliance!.intervalSeconds,
      // Este merge RECONSTRUYE `compliance` campo a campo, así que todo
      // lo que no se nombre aquí desaparece de la policy validada. La
      // lista de sondas de registro tiene que pasar explícitamente, o el
      // backend la inyecta y el agente la tira sin dejar rastro.
      registryProbes: sanitizeRegistryProbes(policy.compliance?.registryProbes)
    };
    const mergedPatch = {
      intervalSeconds:
        fromSchedules.patch?.intervalSeconds ??
        policy.patch?.intervalSeconds ??
        DEFAULT_POLICY.patch!.intervalSeconds
    };
    const mergedUpdate = {
      intervalSeconds:
        fromSchedules.update?.intervalSeconds ??
        policy.update?.intervalSeconds ??
        DEFAULT_POLICY.update!.intervalSeconds
    };
    const mergedCdp = {
      intervalSeconds:
        fromSchedules.cdp?.intervalSeconds ??
        policy.cdp?.intervalSeconds ??
        DEFAULT_POLICY.cdp!.intervalSeconds,
      javaKeystorePaths: sanitizeJavaKeystorePaths(
        policy.cdp?.javaKeystorePaths,
        this.logger
      ),
      scanTlsListeners: policy.cdp?.scanTlsListeners === true,
      tlsListenerPorts: sanitizeTlsListenerPorts(policy.cdp?.tlsListenerPorts, this.logger),
      certFilePaths: sanitizeJavaKeystorePaths(policy.cdp?.certFilePaths, this.logger),
      probeTargets: sanitizeProbeTargets(policy.cdp?.probeTargets, this.logger),
      adcs: {
        enabled: policy.cdp?.adcs?.enabled === true,
        maxPerScan: Math.min(Math.max(Number(policy.cdp?.adcs?.maxPerScan) || 2000, 50), 5000)
      }
    };
    // rcp.file confinement. Path lists get the same hard sanitation as
    // cdp.javaKeystorePaths — absolute only, bounded length, bounded count,
    // de-duplicated — because they reach a SYSTEM/root process. The jail
    // itself applies its built-in deny list on top of whatever survives
    // here, so a hostile or malformed policy can only ever NARROW access
    // relative to the defaults, never open the agent's own secrets.
    const mergedRcp = {
      file: {
        roots: sanitizeAbsolutePaths(policy.rcp?.file?.roots),
        denyPaths: sanitizeAbsolutePaths(policy.rcp?.file?.denyPaths),
        denyExtensions: sanitizeExtensions(policy.rcp?.file?.denyExtensions)
      }
    };
    const mergedPlugins = {
      enabled:
        fromAgent.plugins?.enabled ??
        policy.plugins?.enabled ??
        DEFAULT_POLICY.plugins!.enabled
    };
    const mergedModules = {
      ...DEFAULT_POLICY.modules,
      ...policy.modules,
      ...fromAgent.modules
    };
    const mergedFeatures = {
      ...DEFAULT_POLICY.features,
      // Drop the deprecated realtimeInventory at parse time. We
      // accept it on the wire but never read it after this point.
      ...(policy.features ? stripDroppedFeatures(policy.features) : {}),
      ...(fromAgent.features ? stripDroppedFeatures(fromAgent.features) : {})
    };

    // Security block — accept as-is for fields we recognize, drop
    // unknown keys. We validate cheaply: every capability sub-object
    // gets its `mode` clamped to the allowed enum, and unknown
    // capabilities (e.g. a typo or a future field arriving at an
    // older agent) are silently dropped so they don't surface as
    // garbage in `snapshot()`.
    const mergedSecurity = policy.security !== undefined
      ? sanitizeSecurityPolicy(policy.security, this.logger)
      : undefined;

    const validated: RuntimePolicy = {
      version: policy.version,
      inventory: mergedInventory,
      compliance: mergedCompliance,
      patch: mergedPatch,
      update: mergedUpdate,
      cdp: mergedCdp,
      rcp: mergedRcp,
      // Passed through verbatim; parseGatewayConfig() is the single validator
      // and it fails CLOSED — an absent or malformed block yields no connector
      // at all rather than a half-configured gateway.
      gateway: policy.gateway,
      plugins: mergedPlugins,
      modules: mergedModules,
      features: mergedFeatures,
      security: mergedSecurity
    };

    // validate inventory
    if (
      validated.inventory?.intervalSeconds &&
      (validated.inventory.intervalSeconds < 60 || validated.inventory.intervalSeconds > 86400)
    ) {
      this.logger?.warn?.("Invalid inventory interval in policy, reverting to default");
      validated.inventory!.intervalSeconds = DEFAULT_POLICY.inventory!.intervalSeconds;
    }

    if (
      validated.compliance?.intervalSeconds &&
      (validated.compliance.intervalSeconds < 300 || validated.compliance.intervalSeconds > 86400)
    ) {
      this.logger?.warn?.("Invalid compliance interval in policy, reverting to default");
      validated.compliance!.intervalSeconds = DEFAULT_POLICY.compliance!.intervalSeconds;
    }

    if (
      validated.patch?.intervalSeconds &&
      (validated.patch.intervalSeconds < 300 || validated.patch.intervalSeconds > 604800)
    ) {
      this.logger?.warn?.("Invalid patch interval in policy, reverting to default");
      validated.patch!.intervalSeconds = DEFAULT_POLICY.patch!.intervalSeconds;
    }

    // validate update — same shape as inventory: [60s, 24h]. Below 60s
    // would beat up the update-probe REST endpoint; above 24h defeats
    // the purpose of having an auto-update channel at all (operators
    // who want indefinite hold should flip `modules.update` off, not
    // crank the interval to a year).
    if (
      validated.update?.intervalSeconds &&
      (validated.update.intervalSeconds < 60 || validated.update.intervalSeconds > 86400)
    ) {
      this.logger?.warn?.("Invalid update interval in policy, reverting to default");
      validated.update!.intervalSeconds = DEFAULT_POLICY.update!.intervalSeconds;
    }

    // validate cdp — cert stores are near-static, so anything under
    // 5 min is abuse and anything over 7 days defeats the expiry-warn
    // window the alert rules assume.
    if (
      validated.cdp?.intervalSeconds &&
      (validated.cdp.intervalSeconds < 300 || validated.cdp.intervalSeconds > 604800)
    ) {
      this.logger?.warn?.("Invalid cdp interval in policy, reverting to default");
      validated.cdp!.intervalSeconds = DEFAULT_POLICY.cdp!.intervalSeconds;
    }

    // validate plugins
    if (!Array.isArray(validated.plugins?.enabled)) {
      validated.plugins = { enabled: DEFAULT_POLICY.plugins!.enabled };
    }

    return validated;
  }

  // ---------- plugin helpers ----------

  pluginEnabled(name: string): boolean {
    const enabled = this.getEnabledPlugins();
    return enabled.includes(name);
  }

  // ---------- Infrastructure Gateway ----------

  /**
   * Validated vCenter gateway configuration, or null when this device is not a
   * gateway. Deliberately NOT routed through `pluginEnabled`: the config's
   * presence IS the enablement (ADR-0001 (A)). Callers must treat null as
   * "reject any gateway job" — never as "use defaults".
   */
  /**
   * LAN base URLs of the distribution points serving this device's site.
   *
   * NOT operator-authored: the control plane injects this per device when it
   * delivers the policy (see modules/policies/policy-wire.ts), because it is a
   * fact about where the device sits, not a setting anyone typed.
   *
   * It exists so the agent's OWN periodic update check can prefer the LAN. That
   * check runs with no job behind it, so it had no way to learn about a DP and
   * always pulled the installer from the internet — even on a site whose DP
   * already held those exact bytes. Across a fleet that is the same file over
   * the WAN once per endpoint.
   *
   * Entries are validated here rather than trusted: only https URLs survive, so
   * a malformed or partially-written policy degrades to "no DP" (download from
   * the internet, as before) instead of handing a junk URL to the downloader.
   */
  dpBaseUrls(): string[] {
    const raw = (this.policy as any)?.sdp?.dpBaseUrls;
    if (!Array.isArray(raw)) return [];
    return raw
      .filter((u: unknown): u is string => typeof u === "string" && /^https:\/\//i.test(u))
      .slice(0, 8);
  }

  gatewayConfig(): GatewayConfig | null {
    return parseGatewayConfig(this.policy.gateway);
  }

  /** True when a valid gateway block is present on this device. */
  isGateway(): boolean {
    return this.gatewayConfig() !== null;
  }

  listEnabledModules(): string[] {
    const modules = this.policy.modules || {};

    return Object.keys(modules).filter(
      (m) => (modules as any)[m] === true
    );
  }

  // ---------- diagnostics ----------

  snapshot() {
    return {
      version: this.store.getVersion(),
      inventoryInterval: this.getInventoryInterval(),
      complianceInterval: this.getComplianceInterval(),
      patchInterval: this.getPatchInterval(),
      updateInterval: this.getUpdateInterval(),
      cdpInterval: this.getCdpInterval(),
      plugins: this.getEnabledPlugins(),
      modules: this.listEnabledModules(),
      features: this.policy.features
    };
  }
}
