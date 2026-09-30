import { describe, expect, it } from "vitest";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";

/**
 * El agente de Linux corre como `tracenium` y, sin el grupo
 * `systemd-journal`, journald no le abre el journal del sistema: «No journal
 * files were opened due to insufficient permissions» (tracenium-grpc,
 * 29-sep-2026). De ahí salen los arranques anteriores y cómo terminó cada uno.
 *
 * El bloque del preinstall se EJECUTA aquí, con `getent`, `id` y `usermod`
 * de mentira: lo que importa es qué hace en cada equipo, no que el texto
 * contenga un `usermod`.
 */

const PREINSTALL = path.resolve(__dirname, "../../packaging/linux/scripts/preinstall.sh");
const text = readFileSync(PREINSTALL, "utf8");
const begin = text.indexOf("# ── BEGIN journal-access");
const end = text.indexOf("# ── END journal-access");
const block = text.slice(begin, end);

function run(env: { hasGroup: boolean; groups: string; usermodExit?: number }) {
  const dir = mkdtempSync(path.join(tmpdir(), "journal-access-"));
  const log = path.join(dir, "usermod.log");
  const stub = (name: string, body: string) => {
    const p = path.join(dir, name);
    writeFileSync(p, `#!/bin/sh\n${body}\n`);
    chmodSync(p, 0o755);
  };
  stub("getent", `[ "$1" = group ] && [ "$2" = systemd-journal ] && [ "$HAS_GROUP" = 1 ] && { echo "systemd-journal:x:101:"; exit 0; }; exit 2`);
  stub("id", `echo "$ID_GROUPS"`);
  stub("usermod", `echo "$@" >> "${log}"; exit \${USERMOD_EXIT:-0}`);
  const out = execFileSync("/bin/sh", ["-eu", "-c", block], {
    encoding: "utf8",
    env: {
      PATH: `${dir}:/usr/bin:/bin`,
      HAS_GROUP: env.hasGroup ? "1" : "0",
      ID_GROUPS: env.groups,
      USERMOD_EXIT: String(env.usermodExit ?? 0),
    },
  });
  let calls: string[] = [];
  try {
    calls = readFileSync(log, "utf8").trim().split("\n").filter(Boolean);
  } catch {
    /* no se llamó */
  }
  return { out, calls };
}

describe("preinstall de Linux: lectura del journal para el agente", () => {
  it("el bloque existe y va DESPUÉS de crear el usuario, fuera de su `if` (en una actualización también corre)", () => {
    expect(begin).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(begin);
    const useradd = text.indexOf('echo "  created user tracenium"\nfi\n');
    expect(useradd, "el bloque de useradd cambió de forma").toBeGreaterThan(-1);
    expect(begin).toBeGreaterThan(useradd);
  });

  it("⭐ con el grupo y sin estar dentro: lo añade", () => {
    const r = run({ hasGroup: true, groups: "tracenium" });
    expect(r.calls).toEqual(["-a -G systemd-journal tracenium"]);
    expect(r.out).toContain("added tracenium to systemd-journal");
  });

  it("ya dentro: no vuelve a tocarlo", () => {
    const r = run({ hasGroup: true, groups: "tracenium systemd-journal" });
    expect(r.calls).toEqual([]);
  });

  it("⚠️ sin el grupo en el equipo: no hace nada (por eso no va en SupplementaryGroups=, que impediría arrancar)", () => {
    const r = run({ hasGroup: false, groups: "tracenium" });
    expect(r.calls).toEqual([]);
    expect(r.out).toContain("skipping journal access");
  });

  it("🔴 si usermod falla (usuario de LDAP/AD), la instalación NO se aborta aunque el script corra con `set -e`", () => {
    const r = run({ hasGroup: true, groups: "tracenium", usermodExit: 6 });
    expect(r.calls).toHaveLength(1);
    expect(r.out).toContain("WARNING: could not add tracenium to systemd-journal");
  });

  it("y la unidad NO lo pide como SupplementaryGroups= (un grupo ausente = el agente no arranca)", () => {
    const unit = readFileSync(path.resolve(__dirname, "../../packaging/linux/systemd/tracenium-agent.service"), "utf8");
    expect(unit).not.toMatch(/^SupplementaryGroups=/m);
  });
});
