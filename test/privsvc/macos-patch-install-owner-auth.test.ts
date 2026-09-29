// test/privsvc/macos-patch-install-owner-auth.test.ts
//
// 🔴 28-sep, JPR-MacBookPro (M3 Pro, job e4689371): `softwareupdate --install
// "macOS 27.0.1-26A434"` escribió `Password:` y esperó UNA HORA en un stdin que
// `execFile` dejaba abierto, hasta que el tiempo límite lo mató. En Apple silicon
// una actualización de macOS pide la contraseña de un propietario del volumen
// aunque corra como root. Ahora el install corre sin stdin y se corta al primer
// `Password:`.
//
// Los procesos son de verdad (/bin/sh), no dobles: lo que se prueba es que el
// hijo no se quede colgado.

import { describe, it, expect } from "vitest";
import { asksForPassword, runInstall } from "../../privsvc/macos/src/patch-management";

describe("asksForPassword", () => {
  it("reconoce el prompt de softwareupdate", () => {
    expect(asksForPassword("Password:")).toBe(true);
    expect(asksForPassword("Software Update Tool\n\nPassword:")).toBe(true);
  });

  it("no confunde la salida normal", () => {
    expect(asksForPassword("Downloading macOS 27.0.1\nDone.")).toBe(false);
    expect(asksForPassword("")).toBe(false);
  });
});

describe.runIf(process.platform !== "win32")("runInstall", () => {
  it("🔴 corta en cuanto pide contraseña, sin esperar al tiempo límite", async () => {
    const started = Date.now();
    const r = await runInstall("/bin/sh", ["-c", "printf 'Password:'; sleep 30"], 60_000);
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(r.ownerAuthRequired).toBe(true);
    expect(r.ok).toBe(false);
  });

  it("stdin cerrado: quien lee la entrada ve EOF en vez de esperar", async () => {
    const started = Date.now();
    const r = await runInstall("/bin/sh", ["-c", "read x; echo \"got:[$x]\""], 60_000);
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(r.ownerAuthRequired).toBe(false);
    expect(r.stdout).toContain("got:[]");
  });

  it("una instalación normal sigue como antes", async () => {
    const r = await runInstall("/bin/sh", ["-c", "echo 'Installing Safari'; echo 'Done.' 1>&2"], 60_000);
    expect(r.ok).toBe(true);
    expect(r.ownerAuthRequired).toBe(false);
    expect(r.output).toBe("Installing Safari\nDone.");
  });

  it("el tiempo límite sigue matando lo que se cuelga sin pedir nada", async () => {
    const r = await runInstall("/bin/sh", ["-c", "sleep 30"], 300);
    expect(r.ok).toBe(false);
    expect(r.signal).toBe("SIGTERM");
    expect(r.ownerAuthRequired).toBe(false);
  });
});
