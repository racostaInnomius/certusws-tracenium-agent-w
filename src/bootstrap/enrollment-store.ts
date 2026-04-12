// src/bootstrap/enrollment-store.ts
import fs from "fs";
import path from "path";
import { ensureAgentDataDir } from "./paths";
import { EnrollmentState } from "./enrollment-state";

export class EnrollmentStore {
  private dir = ensureAgentDataDir();
  private statePath = path.join(this.dir, "enrollment.json");

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
    fs.writeFileSync(this.statePath, JSON.stringify(state, null, 2), { encoding: "utf8" });
  }

  clear() {
    if (fs.existsSync(this.statePath)) fs.unlinkSync(this.statePath);
  }

  getPaths() {
    const dir = this.dir;
    return {
      dir,
      enrollmentJson: this.statePath,
      clientCert: path.join(dir, "mtls-client.crt.pem"),
      clientKey: path.join(dir, "mtls-client.key.pem"),
      caBundle: path.join(dir, "mtls-ca.pem"),
    };
  }
}
