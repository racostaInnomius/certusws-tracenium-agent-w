// src/plugins/amm/providers/macos.ts
export const macProvider = {
  async collect() {
    return { softwareInventory: { count: 0, apps: [] } };
  }
};