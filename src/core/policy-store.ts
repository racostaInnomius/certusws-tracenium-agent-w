// src/core/policy-store.ts

import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";

export type StoredPolicy = {
  policyVersion: string;
  policyHash: string;
  policy: any;
  appliedAtUtc: string;
};

function resolvePolicyPath(): string {
  // Windows production path
  if (process.platform === "win32") {
    const programData = process.env.ProgramData || "C:\\ProgramData";
    return path.join(programData, "Tracenium", "policy.json");
  }

  // dev / non‑windows fallback
  return path.join(os.homedir(), ".tracenium", "policy.json");
}

export class PolicyStore {
  private filePath: string;
  private current: StoredPolicy | null = null;

  constructor() {
    this.filePath = resolvePolicyPath();
  }

  async load(): Promise<void> {
    try {
      if (!fs.existsSync(this.filePath)) {
        this.current = null;
        return;
      }

      const raw = await fs.promises.readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw);

      this.current = parsed;
    } catch (err) {
      console.warn("PolicyStore load failed, ignoring corrupted policy", err);
      this.current = null;
    }
  }

  getVersion(): string {
    return this.current?.policyVersion || "none";
  }

  getHash(): string | null {
    return this.current?.policyHash || null;
  }

  getPolicy(): any | null {
    return this.current?.policy || null;
  }

  async save(policyVersion: string, policyHash: string, policyJson: any): Promise<void> {
    const dir = path.dirname(this.filePath);

    await fs.promises.mkdir(dir, { recursive: true });

    const record: StoredPolicy = {
      policyVersion,
      policyHash,
      policy: policyJson,
      appliedAtUtc: new Date().toISOString()
    };

    const tmp = this.filePath + ".tmp";

    await fs.promises.writeFile(tmp, JSON.stringify(record, null, 2), "utf8");
    await fs.promises.rename(tmp, this.filePath);

    this.current = record;
  }

  static computeHash(policyJson: any): string {
    const buf = Buffer.from(JSON.stringify(policyJson));

    return crypto
      .createHash("sha256")
      .update(buf)
      .digest("hex");
  }
}