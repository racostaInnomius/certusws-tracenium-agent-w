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
    // remoteShell stays as a placeholder for the future RCP (remote
    // control plugin) — once RCP ships, this flag becomes the
    // policy-level gate. Today it's accepted in the schema but
    // unused; the UI shows it as "coming soon".
    remoteShell?: boolean;
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
      selfUpdate?: boolean;
    };
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

    const validated: RuntimePolicy = {
      version: policy.version,
      inventory: mergedInventory,
      compliance: mergedCompliance,
      patch: mergedPatch,
      update: mergedUpdate,
      plugins: mergedPlugins,
      modules: mergedModules,
      features: mergedFeatures
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
