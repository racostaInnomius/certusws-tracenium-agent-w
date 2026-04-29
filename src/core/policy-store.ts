// src/core/policy-store.ts

import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import { agentDataDir } from "../bootstrap/paths";

export type StoredPolicy = {
  policyVersion: string;
  policyHash: string;
  policy: any;
  appliedAtUtc: string;
};

function resolvePolicyPath(): string {
  // Producción: el policy.json vive junto a los otros archivos de
  // estado del agente (enrollment.json, agent.db, certs, .env). Eso
  // garantiza:
  //   * Backups y replicaciones (rsync, MDM agent state) capturan
  //     todo el estate atómicamente.
  //   * Los cleanups del postinstall (upgrades/uninstalls) tocan un
  //     único directorio.
  //   * Operadores pueden inspeccionar todo el state con un único
  //     `ls -la` sin saltar entre /var/root y /Library.
  //
  // Para macOS y Linux prod-like, agentDataDir() resuelve a:
  //   macOS:  /Library/Application Support/Tracenium/Agent
  //   Linux:  $HOME/.tracenium/agent  (dev)
  //   Win:    %ProgramData%\Tracenium\Agent
  //
  // El path histórico era $HOME/.tracenium/policy.json (= /var/root
  // cuando el agent corre como LaunchDaemon en macOS). Ese path
  // frágil + separado del resto del state causó un bug: agent
  // recibió new policy, save() falló silenciosamente o quedó stale,
  // y al restart cargó la old policy. El fallback de migración
  // abajo se queda por una release ciclo para devices que aún
  // tienen el archivo en el path viejo — la primera save() lo
  // mueve al nuevo path automáticamente.
  return path.join(agentDataDir(), "policy.json");
}

/**
 * Path legacy (~/.tracenium/policy.json en macOS = /var/root para
 * LaunchDaemons). Solo se usa para migration una vez en load() — se
 * lee y se elimina. Si el archivo no existe, no-op.
 */
function legacyPolicyPath(): string {
  if (process.platform === "win32") {
    const programData = process.env.ProgramData || "C:\\ProgramData";
    return path.join(programData, "Tracenium", "policy.json");
  }
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
      // Migración: si existe el archivo en el path legacy y no en el
      // nuevo, lo movemos. Esto es un one-time op para upgrades desde
      // 1.1.6 o anterior — el path viejo era $HOME/.tracenium que se
      // resolvía a /var/root cuando el daemon corría como root, fuera
      // del directorio principal de estate del agente.
      if (!fs.existsSync(this.filePath)) {
        const legacy = legacyPolicyPath();
        if (legacy !== this.filePath && fs.existsSync(legacy)) {
          try {
            const dir = path.dirname(this.filePath);
            await fs.promises.mkdir(dir, { recursive: true });
            await fs.promises.rename(legacy, this.filePath);
            console.warn(
              `PolicyStore: migrated policy.json from ${legacy} to ${this.filePath}`
            );
          } catch (err) {
            console.warn("PolicyStore migration failed (non-fatal)", err);
            // Si la migración falla, intentamos leer del path viejo.
            // Si esa lectura falla también, current queda null y el
            // siguiente HELLO disparará drift detection.
            try {
              const raw = await fs.promises.readFile(legacy, "utf8");
              const parsed = JSON.parse(raw);
              if (parsed?.policyVersion && parsed?.policy) {
                this.current = parsed;
                return;
              }
            } catch {}
          }
        }
      }

      if (!fs.existsSync(this.filePath)) {
        this.current = null;
        return;
      }

      const raw = await fs.promises.readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw);

      if (
        !parsed ||
        typeof parsed !== "object" ||
        !parsed.policyVersion ||
        !parsed.policy
      ) {
        throw new Error("invalid_policy_structure");
      }

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

    try {
      await fs.promises.writeFile(
        tmp,
        JSON.stringify(record, null, 2),
        { encoding: "utf8", mode: 0o600 }
      );

      await fs.promises.rename(tmp, this.filePath);

      this.current = record;

    } catch (err) {
      try { await fs.promises.unlink(tmp); } catch {}
      throw err;
    }
  }

  static computeHash(policyJson: any): string {
    // Canonical JSON serialization with recursive key sorting.
    //
    // The previous implementation used `JSON.stringify(value, replacer)`
    // with `Object.keys(value).sort()` as the replacer, intending it as
    // "sort keys for stable output". That's a misread of the spec: when
    // the replacer is an array, it acts as a recursive ALLOWLIST of key
    // names, not a sort directive. Since every policy's top-level keys
    // are `["modules","plugins"]`, the allowlist filters every nested
    // object down to `{}` because nested keys (`patch`, `compliance`,
    // `enabled`, …) aren't in the allowlist.
    //
    // Concretely:
    //   stringify({modules:{patch:true},plugins:{enabled:["amp"]}},
    //             ["modules","plugins"])
    //     → '{"modules":{},"plugins":{}}'
    //   stringify({modules:{patch:true,compliance:true},
    //              plugins:{enabled:["amp","scp","pmp"]}},
    //             ["modules","plugins"])
    //     → '{"modules":{},"plugins":{}}'   ← same string → same hash
    //
    // So EVERY policy with the same top-level shape collides, and the
    // "hash matched — runtime resync" branch in grpc-stream.ts swallowed
    // real policy updates as no-ops. Fleet impact: devices enrolled
    // before this fix kept reporting their old plugin set even after
    // tenant policy adopted PMP — the agent acked `policy_already_applied`
    // while the runtime was actually running the stale policy. The only
    // way out was deleting policy.json on disk so localHash became null.
    //
    // Correct fix: hand-rolled stable JSON that sorts keys at every
    // depth. Strings JSON-escape via JSON.stringify() so we don't
    // reinvent unicode escaping.
    const canonical = stableStringify(policyJson);
    return crypto
      .createHash("sha256")
      .update(Buffer.from(canonical, "utf8"))
      .digest("hex");
  }
}

function stableStringify(value: any): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    // Arrays preserve element order — order is semantically meaningful
    // (e.g. plugin install order). Only object keys get sorted.
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    const parts = keys.map(
      (k) => JSON.stringify(k) + ":" + stableStringify(value[k])
    );
    return "{" + parts.join(",") + "}";
  }
  // function, symbol, bigint — not expected in policy JSON. Fall back
  // to "null" rather than throw, to mirror JSON.stringify's behavior.
  return "null";
}