// test/packaging/linux-apparmor-stale-copies.test.ts
//
// 🔴 server.certusws.com (T1) se quedó en 1.1.80 desde el reboot del 24-sep.
// El perfil del paquete estaba bien, pero `/etc/apparmor.d/` tenía además
// `usr.lib.tracenium.privsvc.bak-20260815` —el perfil de la época 1.1.35,
// enforce y sin systemd-run—. apparmor.service carga todo el directorio en
// cada boot, y el viejo sustituía al bueno: el update moría con
// `spawn /usr/bin/systemd-run EACCES` cada 6 horas.
//
// Se ejecuta el bloque REAL del postinstall (entre sus marcadores) con /bin/sh
// contra un directorio temporal, no una réplica en TypeScript.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const POSTINSTALL = path.resolve(__dirname, "../../packaging/linux/scripts/postinstall.sh");

function sweepBlock(): string {
  const text = readFileSync(POSTINSTALL, "utf8");
  const m = text.match(/# >>> sweep-stale-apparmor-copies\n([\s\S]*?)# <<< sweep-stale-apparmor-copies/);
  if (!m) throw new Error("el postinstall ya no tiene el bloque sweep-stale-apparmor-copies");
  return m[1];
}

const OLD_PROFILE = "#include <tunables/global>\n\nprofile tracenium-privsvc /usr/lib/tracenium/node {\n}\n";
const NEW_PROFILE =
  "profile tracenium-privsvc /usr/lib/tracenium/node flags=(attach_disconnected,complain) {\n}\n";

let root: string;
let aa: string;
let backups: string;

function runSweep(): string {
  return execFileSync("/bin/sh", ["-c", sweepBlock()], {
    env: { ...process.env, TRACENIUM_APPARMOR_DIR: aa, TRACENIUM_APPARMOR_BACKUP_DIR: backups },
    encoding: "utf8"
  });
}

beforeEach(() => {
  root = mkdtempSync(path.join(os.tmpdir(), "aa-sweep-"));
  aa = path.join(root, "apparmor.d");
  backups = path.join(root, "backups");
  mkdirSync(aa);
  writeFileSync(path.join(aa, "usr.lib.tracenium.privsvc"), NEW_PROFILE);
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("postinstall de Linux: ninguna otra copia del perfil se queda en /etc/apparmor.d", () => {
  it("⭐ saca el .bak que dejó a server.certusws.com clavado en 1.1.80", () => {
    writeFileSync(path.join(aa, "usr.lib.tracenium.privsvc.bak-20260815"), OLD_PROFILE);

    const out = runSweep();

    expect(existsSync(path.join(aa, "usr.lib.tracenium.privsvc.bak-20260815"))).toBe(false);
    // Movido, no borrado: puede ser trabajo de un operador.
    expect(readFileSync(path.join(backups, "usr.lib.tracenium.privsvc.bak-20260815"), "utf8")).toBe(OLD_PROFILE);
    expect(out).toContain("copia vieja del perfil movida");
  });

  it("deja en su sitio el perfil del paquete", () => {
    writeFileSync(path.join(aa, "usr.lib.tracenium.privsvc.bak-20260815"), OLD_PROFILE);
    runSweep();
    expect(readFileSync(path.join(aa, "usr.lib.tracenium.privsvc"), "utf8")).toBe(NEW_PROFILE);
  });

  it("encuentra la copia por contenido, se llame como se llame", () => {
    writeFileSync(path.join(aa, "tracenium-old"), "  profile tracenium-privsvc {\n}\n");
    runSweep();
    expect(existsSync(path.join(aa, "tracenium-old"))).toBe(false);
  });

  it("no toca los perfiles de otros ni los que solo se parecen", () => {
    writeFileSync(path.join(aa, "usr.sbin.cupsd"), "profile /usr/sbin/cupsd {\n}\n");
    writeFileSync(path.join(aa, "other"), "profile tracenium-privsvc-extra {\n}\n");
    writeFileSync(path.join(aa, "notes"), "# profile tracenium-privsvc was here\n");

    runSweep();

    expect(existsSync(path.join(aa, "usr.sbin.cupsd"))).toBe(true);
    expect(existsSync(path.join(aa, "other"))).toBe(true);
    expect(existsSync(path.join(aa, "notes"))).toBe(true);
    expect(existsSync(backups)).toBe(false);
  });

  it("no mira dentro de subdirectorios (local/, abstractions/)", () => {
    mkdirSync(path.join(aa, "local"));
    writeFileSync(path.join(aa, "local", "usr.lib.tracenium.privsvc"), "# overrides locales\n");
    runSweep();
    expect(existsSync(path.join(aa, "local", "usr.lib.tracenium.privsvc"))).toBe(true);
  });

  it("sin /etc/apparmor.d (RHEL) no hace nada ni falla", () => {
    rmSync(aa, { recursive: true, force: true });
    expect(() => runSweep()).not.toThrow();
  });

  it("va ANTES de cargar el perfil y del opt-out", () => {
    const text = readFileSync(POSTINSTALL, "utf8");
    const sweep = text.indexOf("# >>> sweep-stale-apparmor-copies");
    expect(sweep).toBeGreaterThan(-1);
    expect(sweep).toBeLessThan(text.indexOf('if [ "${TRACENIUM_SKIP_APPARMOR:-0}" = "1" ]'));
    expect(sweep).toBeLessThan(text.indexOf("apparmor_parser -r /etc/apparmor.d/usr.lib.tracenium.privsvc"));
  });
});
