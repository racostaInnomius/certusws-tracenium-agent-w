// src/plugins/amm/providers/linux.ts
export const linuxProvider = {
  async collect() {
    return { softwareInventory: { count: 0, apps: [] } };
  }
};