// src/core/policy-runtime.ts
import { EventEmitter } from "events";
import { PolicyStore } from "./policy-store";
import { logger } from "../bootstrap/logger";

export type RuntimePolicy = {
  version?: string;
  inventory?: {
    intervalSeconds?: number;
  };
  plugins?: {
    enabled?: string[];
  };
  modules?: {
    amm?: boolean;
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
    amm: true,
    patch: false,
    compliance: false
  },
  features: {
    realtimeInventory: false,
    remoteShell: false,
    selfUpdate: false
  }
};

export class PolicyRuntime extends EventEmitter {

  private policy: RuntimePolicy = DEFAULT_POLICY;

  constructor(private store: PolicyStore) {
    super();
  }

  // ---------- initialization ----------

  async init() {
    const loaded = this.store.getPolicy();

    if (!loaded) {
      logger.info("PolicyRuntime: no stored policy, using defaults");
      this.policy = DEFAULT_POLICY;
      return;
    }

    const validated = this.validatePolicy(loaded);

    this.policy = validated;

    logger.info("PolicyRuntime initialized", {
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
      logger.warn("PolicyRuntime: update requested but no policy found in store");
      return;
    }

    const validated = this.validatePolicy(newPolicy);

    const previousVersion = this.store.getVersion();

    this.policy = validated;

    logger.info("PolicyRuntime updated", {
      version: previousVersion,
      inventoryInterval: validated.inventory?.intervalSeconds,
      plugins: validated.plugins?.enabled
    });

    // notify runtime components
    this.emit("policyChanged", this.policy);

    // notify specialized listeners
    this.emit("inventoryIntervalChanged", this.getInventoryInterval());
    this.emit("pluginsChanged", this.getEnabledPlugins());
  }

  // ---------- validation ----------

  private validatePolicy(policy: any): RuntimePolicy {
    const validated: RuntimePolicy = {
      ...DEFAULT_POLICY,
      ...policy
    };

    // validate inventory
    if (
      validated.inventory?.intervalSeconds &&
      (validated.inventory.intervalSeconds < 60 || validated.inventory.intervalSeconds > 86400)
    ) {
      logger.warn("Invalid inventory interval in policy, reverting to default");
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