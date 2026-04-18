// src/bootstrap/enrollment-store.ts
import fs from "fs";
import path from "path";
import os from "os";
import { agentDataDir, ensureAgentDataDir, getLegacyAgentDataDir } from "./paths";
import { EnrollmentState } from "./enrollment-state";

export class EnrollmentStore {
  private dir = ensureAgentDataDir();
  private statePath = path.join(this.dir, "enrollment.json");

  constructor() {
    this.migrateLegacyMacosState();
  }

  private writeSecureFile(filePath: string, content: string) {
    fs.writeFileSync(filePath, content, { encoding: "utf8", mode: 0o600 });
    try {
      fs.chmodSync(filePath, 0o600);
    } catch {}
  }

  private migrateLegacyMacosState() {
    if (os.platform() !== "darwin") {
      return;
    }

    const legacyDir = getLegacyAgentDataDir();
    if (!legacyDir || legacyDir === this.dir || !fs.existsSync(legacyDir)) {
      return;
    }

    const files = [
      "enrollment.json",
      "mtls-client.crt.pem",
      "mtls-client.key.pem",
      "mtls-ca.pem",
      "agent.db"
    ];

    let migrated = false;
    for (const name of files) {
      const source = path.join(legacyDir, name);
      const target = path.join(this.dir, name);
      if (!fs.existsSync(source) || fs.existsSync(target)) {
        continue;
      }
      fs.copyFileSync(source, target);
      if (name !== "agent.db") {
        try {
          fs.chmodSync(target, 0o600);
        } catch {}
      }
      migrated = true;
    }

    if (migrated) {
      console.log("[Enroll] migrated legacy macOS agent state", {
        from: legacyDir,
        to: this.dir
      });
    }
  }

  private normalizeCapabilities(state: EnrollmentState): boolean {
    const capabilities = Array.isArray(state.bootstrap?.capabilities)
      ? state.bootstrap.capabilities
      : [];

    const renamed: Record<string, string> = {
      amm: "amp",
      scm: "scp",
      pmm: "pmp"
    };

    const normalized = Array.from(
      new Set(
        capabilities.map((capability) => {
          const value = String(capability || "").trim();
          return renamed[value] || value;
        }).filter(Boolean)
      )
    );

    if (!state.bootstrap) {
      (state as any).bootstrap = {
        channel: "stable",
        capabilities: normalized.length > 0 ? normalized : ["amp"]
      };
      return true;
    }

    if (normalized.length === 0) {
      normalized.push("amp");
    }

    const changed =
      normalized.length !== capabilities.length ||
      normalized.some((value, index) => value !== capabilities[index]);

    if (changed) {
      state.bootstrap.capabilities = normalized;
    }

    return changed;
  }

  load(): EnrollmentState | null {
    if (!fs.existsSync(this.statePath)) return null;
    try {
      const raw = fs.readFileSync(this.statePath, "utf8");
      const parsed = JSON.parse(raw) as EnrollmentState;

      if (!parsed?.tenantId || !parsed?.deviceId) {
        return null;
      }

      if (this.normalizeCapabilities(parsed)) {
        this.save(parsed);
      }

      return parsed;
    } catch {
      return null;
    }
  }

  save(state: EnrollmentState) {
    this.writeSecureFile(this.statePath, JSON.stringify(state, null, 2));
  }

  clear() {
    if (fs.existsSync(this.statePath)) fs.unlinkSync(this.statePath);
  }

  getPaths() {
    const dir = agentDataDir();
    return {
      dir,
      enrollmentJson: this.statePath,
      clientCert: path.join(dir, "mtls-client.crt.pem"),
      clientKey: path.join(dir, "mtls-client.key.pem"),
      caBundle: path.join(dir, "mtls-ca.pem"),
    };
  }
}
