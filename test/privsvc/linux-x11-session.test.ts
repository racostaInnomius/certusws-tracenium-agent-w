// test/privsvc/linux-x11-session.test.ts
//
// La selección de sesión gráfica decide a QUÉ escritorio salta PrivSvc: de
// quién se captura la pantalla y a quién se le enseña el indicador de que le
// están mirando (ADR-0012). Elegir mal no da un error — da la pantalla de otra
// persona, o un aviso en el escritorio equivocado.
//
// Este código llevaba en campo desde M3.S1 sin un test. Se cubre ahora, al
// extraerlo, porque a partir de aquí depende de él un segundo llamador.

import { describe, it, expect } from "vitest";
import {
  parseLoginctlProps,
  parseSessionIds,
  selectGraphicalSession,
  buildRunuserArgs
} from "../../privsvc/linux/src/x11-session";

describe("parseLoginctlProps", () => {
  it("parsea las líneas Key=Value", () => {
    const props = parseLoginctlProps("Active=yes\nType=x11\nDisplay=:0\nName=javier\nUser=1000");
    expect(props).toEqual({
      Active: "yes", Type: "x11", Display: ":0", Name: "javier", User: "1000"
    });
  });

  it("conserva los '=' que vengan dentro del valor", () => {
    // Un GECOS o una ruta con '=' partiría el valor si se usara split("=").
    const props = parseLoginctlProps("Desktop=ubuntu:GNOME=classic");
    expect(props.Desktop).toBe("ubuntu:GNOME=classic");
  });

  it("ignora líneas sin '=' y no lanza con entrada vacía", () => {
    expect(parseLoginctlProps("")).toEqual({});
    expect(parseLoginctlProps("basura\n\nActive=yes")).toEqual({ Active: "yes" });
  });
});

describe("parseSessionIds", () => {
  it("saca la primera columna de list-sessions", () => {
    const list = "   2 1000 javier seat0 tty2\n   c1 1000 javier seat0 -\n";
    expect(parseSessionIds(list)).toEqual(["2", "c1"]);
  });

  it("no devuelve entradas vacías con líneas en blanco", () => {
    expect(parseSessionIds("\n\n  \n")).toEqual([]);
  });
});

describe("selectGraphicalSession", () => {
  const x11Active = {
    Active: "yes", Remote: "no", Type: "x11", Display: ":0", Name: "javier", User: "1000"
  };

  it("elige la sesión x11 activa", () => {
    const s = selectGraphicalSession([x11Active]);
    expect(s).toEqual({ uid: 1000, user: "javier", display: ":0", type: "x11" });
  });

  it("descarta las sesiones remotas", () => {
    // Una sesión SSH no tiene framebuffer local: capturarla no significa nada,
    // y enseñarle un indicador tampoco lo vería nadie.
    const ssh = { ...x11Active, Remote: "yes", Name: "deploy" };
    expect(selectGraphicalSession([ssh])).toBeNull();
  });

  it("prefiere la activa sobre una inactiva anterior en la lista", () => {
    // La inactiva sirve de último recurso, pero la activa es la que alguien
    // está mirando de verdad.
    const inactive = { ...x11Active, Active: "no", Name: "otro", User: "1001" };
    const s = selectGraphicalSession([inactive, x11Active]);
    expect(s?.user).toBe("javier");
  });

  it("usa la inactiva si no hay ninguna activa", () => {
    const inactive = { ...x11Active, Active: "no" };
    expect(selectGraphicalSession([inactive])?.user).toBe("javier");
  });

  it("DEVUELVE la sesión Wayland en vez de saltarla", () => {
    // Es deliberado: devolverla deja al llamador decir "wayland_unsupported".
    // Saltarla diría "no hay escritorio" en una máquina que sí lo tiene, y ese
    // mensaje manda a quien lo lea a investigar lo que no es.
    const wayland = { ...x11Active, Type: "wayland", Display: "" };
    const s = selectGraphicalSession([wayland]);
    expect(s?.type).toBe("wayland");
  });

  it("acepta una sesión con Display pero sin Type", () => {
    const noType = { Active: "yes", Remote: "no", Type: "", Display: ":1", Name: "javier", User: "1000" };
    expect(selectGraphicalSession([noType])).toEqual({
      uid: 1000, user: "javier", display: ":1", type: "x11"
    });
  });

  it("rellena :0 cuando el Display viene vacío en una sesión x11", () => {
    const noDisplay = { ...x11Active, Display: "" };
    expect(selectGraphicalSession([noDisplay])?.display).toBe(":0");
  });

  it("descarta sesiones sin uid o sin nombre utilizables", () => {
    const noUid = { ...x11Active, User: "no-es-un-numero" };
    const noName = { ...x11Active, Name: "" };
    expect(selectGraphicalSession([noUid, noName])).toBeNull();
  });

  it("ignora las sesiones tty puras", () => {
    // Sin Display y de tipo tty no hay nada que capturar ni dónde pintar.
    const tty = { Active: "yes", Remote: "no", Type: "tty", Display: "", Name: "javier", User: "1000" };
    expect(selectGraphicalSession([tty])).toBeNull();
  });

  it("devuelve null con la lista vacía", () => {
    expect(selectGraphicalSession([])).toBeNull();
  });
});

describe("buildRunuserArgs", () => {
  const session = { uid: 1000, user: "javier", display: ":0", type: "x11" };

  it("pone DISPLAY y XAUTHORITY antes del ejecutable", () => {
    const args = buildRunuserArgs(session, "/run/user/1000/gdm/Xauthority", ["/usr/lib/x", "--flag"]);
    expect(args).toEqual([
      "-u", "javier", "--", "env",
      "DISPLAY=:0", "XAUTHORITY=/run/user/1000/gdm/Xauthority",
      "/usr/lib/x", "--flag"
    ]);
  });

  it("omite XAUTHORITY cuando no se encontró cookie", () => {
    // No es lo mismo que pasarla vacía: XAUTHORITY="" hace que Xlib busque una
    // ruta vacía y falle, en vez de recurrir a $HOME/.Xauthority.
    const args = buildRunuserArgs(session, null, ["/usr/lib/x"]);
    expect(args).not.toContain("XAUTHORITY=");
    expect(args.filter((a) => a.startsWith("XAUTHORITY"))).toEqual([]);
    expect(args).toContain("DISPLAY=:0");
  });

  it("cae a :0 cuando la sesión no trae Display", () => {
    const args = buildRunuserArgs({ ...session, display: "" }, null, ["/usr/lib/x"]);
    expect(args).toContain("DISPLAY=:0");
  });
});
