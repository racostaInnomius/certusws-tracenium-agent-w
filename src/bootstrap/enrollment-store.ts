// src/bootstrap/enrollment-store.ts
import fs from "fs";
import path from "path";
import { ensureAgentDataDir } from "./paths";
import { EnrollmentState } from "./enrollment-state";

export class EnrollmentStore {
  private dir = ensureAgentDataDir();
  private statePath = path.join(this.dir, "enrollment.json");

  load(): EnrollmentState | null {
    if (!fs.existsSync(this.statePath)) return null;
    const raw = fs.readFileSync(this.statePath, "utf8");
    return JSON.parse(raw) as EnrollmentState;
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