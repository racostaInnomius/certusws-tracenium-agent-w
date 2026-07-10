// src/core/policy-runtime.ts
import { EventEmitter } from "events";
import { PolicyStore } from "./policy-store";

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
  };
  patch?: {
    intervalSeconds?: number;
  };
  update?: {
    intervalSeconds?: number;
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
    selfUpdate?: boolean;
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
      selfUpdate?: boolean;
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
    selfUpdate: true
  }
};

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

  getPatchInterval(): number {
    return this.policy.patch?.intervalSeconds || DEFAULT_POLICY.patch!.intervalSeconds!;
  }

  getUpdateInterval(): number {
    return this.policy.update?.intervalSeconds || DEFAULT_POLICY.update!.intervalSeconds!;
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
    this.emit("pluginsChanged", this.getEnabledPlugins());
    this.emit("modulesChanged", this.listEnabledModules());
    this.emit("featuresChanged", this.policy.features);
    this.emit("securityPolicyChanged", this.getSecurityPolicy());
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
        DEFAULT_POLICY.compliance!.intervalSeconds
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
      plugins: this.getEnabledPlugins(),
      modules: this.listEnabledModules(),
      features: this.policy.features
    };
  }
}
