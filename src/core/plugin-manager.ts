// src/core/plugin-manager.ts
import type { AgentContext } from "./agent-context";

export type PluginTask = (ctx: AgentContext, params?: any) => Promise<any>;

export type PluginDefinition = {
  name: string;
  tasks: Record<string, PluginTask>;
};

export class PluginManager {

  private plugins: Map<string, PluginDefinition> = new Map();
  private ctx: AgentContext | null = null;

  async init(ctx: AgentContext) {
    this.ctx = ctx;

    ctx.logger?.info?.("PluginManager initializing...");

    // register built‑in plugins
    await this.registerBuiltinPlugins();

    ctx.logger?.info?.("PluginManager ready", {
      plugins: Array.from(this.plugins.keys())
    });
  }

  // -----------------------------
  // registration
  // -----------------------------

  register(plugin: PluginDefinition) {

    if (this.plugins.has(plugin.name)) {
      this.ctx?.logger?.warn?.("Plugin already registered, overriding", { plugin: plugin.name });
    }

    this.plugins.set(plugin.name, plugin);

    this.ctx?.logger?.info?.("Plugin registered", {
      plugin: plugin.name,
      tasks: Object.keys(plugin.tasks)
    });
  }

  private async registerBuiltinPlugins() {

    try {
      const { collectAMM } = await import("../plugins/amm");

      this.register({
        name: "amm",
        tasks: {
          collect: async (ctx: AgentContext) => collectAMM(ctx)
        }
      });

    } catch (err: any) {
      this.ctx?.logger?.error?.("Failed to register AMM plugin", err?.message || err);
    }
  }

  // -----------------------------
  // execution
  // -----------------------------

  async run(taskPath: string, params?: any): Promise<any> {

    if (!this.ctx) {
      throw new Error("PluginManager not initialized");
    }

    const [pluginName, taskName] = taskPath.split(".");

    if (!pluginName || !taskName) {
      throw new Error(`Invalid taskPath: ${taskPath}`);
    }

    const plugin = this.plugins.get(pluginName);

    if (!plugin) {
      throw new Error(`Plugin not found: ${pluginName}`);
    }

    if (!plugin.tasks || typeof plugin.tasks !== "object") {
      throw new Error(`Invalid plugin definition: ${pluginName}`);
    }

    if (!this.ctx.policyRuntime.pluginEnabled(pluginName)) {
      this.ctx?.logger?.info?.("Plugin disabled by policy", { plugin: pluginName });
      return null;
    }

    const task = plugin.tasks[taskName];

    if (!task) {
      throw new Error(`Task not found: ${taskPath}`);
    }

    try {

      this.ctx?.logger?.info?.("Executing plugin task", {
        plugin: pluginName,
        task: taskName
      });

      return await task(this.ctx, params);

    } catch (err: any) {

      this.ctx?.logger?.error?.("Plugin task failed", {
        plugin: pluginName,
        task: taskName,
        error: err?.message || err
      });

      throw err;
    }
  }

  // -----------------------------
  // inspection
  // -----------------------------

  listPlugins(): string[] {
    return Array.from(this.plugins.keys());
  }

  listTasks(pluginName: string): string[] {

    const plugin = this.plugins.get(pluginName);

    if (!plugin) return [];

    return Object.keys(plugin.tasks);
  }

}
