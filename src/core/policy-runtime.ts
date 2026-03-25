// src/core/policy-runtime.ts
import { EventEmitter } from "events";
import { PolicyStore } from "./policy-store";

export type RuntimePolicy = {
  version?: string;
  inventory?: {
    intervalSeconds?: number;
  };
  plugins?: {
    enabled?: string[];
  };
  modules?: {
    update?: boolean;
    patch?: boolean;
    compliance?: boolean;
  };
  features?: {
    realtimeInventory?: boolean;
    remoteShell?: boolean;
    selfUpdate?: boolean;
  };
};

const DEFAULT_POLICY: RuntimePolicy = {
  inventory: {
    intervalSeconds: 21600 // 6h
  },
  plugins: {
    enabled: ["amm"]
  },
  modules: {
    update: true,
    patch: false,
    compliance: false
  },
  features: {
    realtimeInventory: false,
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

  getEnabledPlugins(): string[] {
    return this.policy.plugins?.enabled || DEFAULT_POLICY.plugins!.enabled!;
  }

  isModuleEnabled(module: keyof RuntimePolicy["modules"]): boolean {
    return this.policy.modules?.[module] ?? false;
  }

  isFeatureEnabled(feature: keyof RuntimePolicy["features"]): boolean {
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
    this.emit("pluginsChanged", this.getEnabledPlugins());
    this.emit("modulesChanged", this.listEnabledModules());
    this.emit("featuresChanged", this.policy.features);
  }

  // ---------- validation ----------

  private validatePolicy(policy: any): RuntimePolicy {
    if (typeof policy !== "object" || policy === null) {
      return JSON.parse(JSON.stringify(DEFAULT_POLICY));
    }

    const validated: RuntimePolicy = {
      ...DEFAULT_POLICY,
      ...policy,
      inventory: {
        ...DEFAULT_POLICY.inventory,
        ...policy.inventory
      },
      plugins: {
        ...DEFAULT_POLICY.plugins,
        ...policy.plugins
      },
      modules: {
        ...DEFAULT_POLICY.modules,
        ...policy.modules
      },
      features: {
        ...DEFAULT_POLICY.features,
        ...policy.features
      }
    };

    // validate inventory
    if (
      validated.inventory?.intervalSeconds &&
      (validated.inventory.intervalSeconds < 60 || validated.inventory.intervalSeconds > 86400)
    ) {
      this.logger?.warn?.("Invalid inventory interval in policy, reverting to default");
      validated.inventory!.intervalSeconds = DEFAULT_POLICY.inventory!.intervalSeconds;
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
      plugins: this.getEnabledPlugins(),
      modules: this.listEnabledModules(),
      features: this.policy.features
    };
  }
}