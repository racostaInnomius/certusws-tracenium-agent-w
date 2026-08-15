// The gate and the output parsing are the parts that must not regress: every
// path that returns a coordinate is personal data leaving the endpoint. Both
// are pure, which is why they can be tested without a Windows box, a location
// permission, or a Wi-Fi radio.

import { describe, it, expect } from "vitest";
import {
  parseGeoOutput,
  supportsOsLocation,
  collectGeo,
  parseConsoleUser,
  isFixFresh,
  classifyGeoOutput,
  extractDetail,
} from "../../src/plugins/amp/providers/geo";

const at = () => new Date("2026-08-09T18:00:00.000Z");

describe("parseGeoOutput", () => {
  it("parses a well-formed reading", () => {
    expect(parseGeoOutput('{"lat":19.432608,"lon":-99.133209,"accuracyM":38}', at)).toEqual({
      lat: 19.432608,
      lon: -99.133209,
      accuracyM: 38,
      collectedAtUtc: "2026-08-09T18:00:00.000Z",
    });
  });

  it("treats the helper's own failure markers as 'no position'", () => {
    // The script prints these instead of throwing so a denied consent store
    // does not look the same as a crashed interpreter.
    expect(parseGeoOutput("TIMEOUT", at)).toBeNull();
    expect(parseGeoOutput("ERROR:Access is denied", at)).toBeNull();
  });

  it("returns null for anything that is not JSON", () => {
    expect(parseGeoOutput("", at)).toBeNull();
    expect(parseGeoOutput("   ", at)).toBeNull();
    expect(parseGeoOutput("not json", at)).toBeNull();
    expect(parseGeoOutput(undefined, at)).toBeNull();
    expect(parseGeoOutput(null, at)).toBeNull();
    expect(parseGeoOutput("[1,2,3]", at)).toBeNull();
  });

  it("rejects Null Island — a zeroed struct, not a place", () => {
    expect(parseGeoOutput('{"lat":0,"lon":0,"accuracyM":10}', at)).toBeNull();
  });

  it("keeps a legitimate zero on one axis", () => {
    // The equator and the Greenwich meridian are real places.
    expect(parseGeoOutput('{"lat":0,"lon":32.5}', at)?.lat).toBe(0);
    expect(parseGeoOutput('{"lat":51.48,"lon":0}', at)?.lon).toBe(0);
  });

  it("rejects out-of-range coordinates", () => {
    expect(parseGeoOutput('{"lat":91,"lon":0}', at)).toBeNull();
    expect(parseGeoOutput('{"lat":0,"lon":181}', at)).toBeNull();
    expect(parseGeoOutput('{"lat":"north","lon":"west"}', at)).toBeNull();
  });

  it("reports an unusable accuracy as unknown, not as perfect", () => {
    // A negative or missing accuracy must not render as "±0 m", which would
    // read as a pinpoint fix.
    expect(parseGeoOutput('{"lat":19.4,"lon":-99.1,"accuracyM":-1}', at)?.accuracyM).toBeNull();
    expect(parseGeoOutput('{"lat":19.4,"lon":-99.1}', at)?.accuracyM).toBeNull();
  });

  it("keeps a zero accuracy distinct from an absent one", () => {
    expect(parseGeoOutput('{"lat":19.4,"lon":-99.1,"accuracyM":0}', at)?.accuracyM).toBe(0);
  });
});

describe("supportsOsLocation", () => {
  it("covers the platforms with a real system location service", () => {
    expect(supportsOsLocation("win32")).toBe(true);
    expect(supportsOsLocation("darwin")).toBe(true);
  });

  it("excludes Linux, which has no equivalent", () => {
    // Those devices keep falling back to the operator's CIDR→site mapping,
    // which is exact anyway.
    expect(supportsOsLocation("linux")).toBe(false);
    expect(supportsOsLocation("freebsd")).toBe(false);
  });
});

describe("collectGeo — the gate", () => {
  it("collects nothing when the tenant has not enabled it, and says so", async () => {
    expect(await collectGeo(false, "win32")).toEqual({ geo: null, status: "disabled" });
  });

  it("fails closed on anything that is not exactly true", async () => {
    // A policy that failed to load, or one carrying a truthy string, must not
    // start reading positions.
    for (const value of [undefined, null, "true", 1]) {
      const result = await collectGeo(value as any, "win32");
      expect(result.geo).toBeNull();
      expect(result.status).toBe("disabled");
    }
  });

  it("distinguishes an unsupported platform from a disabled tenant", async () => {
    // Both produce no coordinate; only one of them is worth acting on.
    expect(await collectGeo(true, "linux")).toEqual({ geo: null, status: "unsupported" });
  });
});

describe("classifyGeoOutput — why there is no position", () => {
  it("reports a usable reading as ok", () => {
    expect(classifyGeoOutput('{"lat":19.4,"lon":-99.1}')).toBe("ok");
  });

  it("names WHICH of the two Windows gates is closed", () => {
    // Found in the field: HKLM=Allow (Settings shows location ON) but the
    // SYSTEM account's own consent = Deny, so every request from the agent was
    // refused while the machine looked correctly configured. The two cases have
    // different fixes, so they must not read the same.
    const machine = "ERROR:location_services_off machine-wide (HKLM=Deny)";
    const account = "ERROR:location_denied_for_service_account (HKLM=Allow, HKCU=Deny); the agent runs as SYSTEM and that account has no location consent";
    expect(classifyGeoOutput(machine)).toBe("denied");
    expect(classifyGeoOutput(account)).toBe("denied");
    // El detalle es lo que hace accionable a cada uno.
    expect(extractDetail(machine)).toMatch(/machine-wide/);
    expect(extractDetail(account)).toMatch(/service_account/);
    expect(extractDetail(account)).toMatch(/SYSTEM/);
  });

  it("separates a refusal from a miss", () => {
    // "denied" is a configuration problem an admin can fix; "unavailable" is
    // weather. Collapsing them would send an MSP chasing the wrong one.
    expect(classifyGeoOutput("ERROR:Access is denied")).toBe("denied");
    expect(classifyGeoOutput("TIMEOUT")).toBe("unavailable");
  });

  it("treats nothing-at-all as unavailable", () => {
    // On macOS this is the status app not running, no console user, or a fix
    // that aged out of the freshness window.
    expect(classifyGeoOutput("")).toBe("unavailable");
    expect(classifyGeoOutput("   ")).toBe("unavailable");
    expect(classifyGeoOutput(null)).toBe("unavailable");
  });

  it("treats a malformed or rejected reading as unavailable, not ok", () => {
    expect(classifyGeoOutput("not json")).toBe("unavailable");
    expect(classifyGeoOutput('{"lat":0,"lon":0}')).toBe("unavailable");
    expect(classifyGeoOutput('{"lat":91,"lon":0}')).toBe("unavailable");
  });
});

describe("classifyGeoOutput — the reason macOS publishes", () => {
  it("honours consent_required, which no amount of waiting fixes", () => {
    // The bug this exists for: a menubar (LSUIElement) app registers as a
    // location client but macOS never shows it the permission alert, so the
    // status sits at notDetermined forever. Reported as "unavailable" it read
    // as "no fix yet" and sent operators off to wait.
    expect(classifyGeoOutput('{"status":"consent_required","collectedAtUtc":"2026-08-13T02:00:00Z"}'))
      .toBe("consent_required");
  });

  it("honours a published denial", () => {
    expect(classifyGeoOutput('{"status":"denied","collectedAtUtc":"2026-08-13T02:00:00Z"}'))
      .toBe("denied");
  });

  it("refuses a published 'ok' that carries no usable coordinates", () => {
    // The reason is trusted; a claim of success is verified.
    expect(classifyGeoOutput('{"status":"ok"}')).toBe("unavailable");
    expect(classifyGeoOutput('{"status":"ok","lat":0,"lon":0}')).toBe("unavailable");
  });

  it("accepts a published ok WITH coordinates", () => {
    expect(classifyGeoOutput('{"status":"ok","lat":19.4,"lon":-99.1}')).toBe("ok");
  });

  it("ignores a status it does not recognise rather than propagating it", () => {
    // The app ships independently; an unknown value must not become a status
    // the backend and UI have no text for.
    expect(classifyGeoOutput('{"status":"banana","lat":19.4,"lon":-99.1}')).toBe("ok");
    expect(classifyGeoOutput('{"status":"banana"}')).toBe("unavailable");
  });
});

describe("classifyGeoOutput — las tres formas de no tener posición en macOS", () => {
  it("separa 'nadie ha iniciado sesión' de una falla", () => {
    // La posición la recolecta la app de sesión de usuario. Un Mac en la
    // pantalla de login no tiene NADA que pudiera recolectar — no es un fallo
    // que perseguir.
    expect(classifyGeoOutput("NO_USER")).toBe("no_user_session");
  });

  it("marca como falla que la app no esté publicando", () => {
    // Hay usuario en consola pero la app no dejó archivo, o el que dejó ya
    // caducó. Eso SÍ es algo que revisar.
    expect(classifyGeoOutput("NO_PUBLISHER")).toBe("agent_not_publishing");
  });

  it("reserva 'unavailable' para el caso legítimo: viva, con permiso, sin fix", () => {
    // Antes los tres casos producían este mismo valor, así que el mensaje
    // "aún no produce un fix" se mostraba también cuando la app estaba muerta.
    expect(classifyGeoOutput('{"status":"unavailable","collectedAtUtc":"2026-08-13T20:00:00Z"}'))
      .toBe("unavailable");
  });

  it("un fix real sigue ganando sobre cualquier motivo", () => {
    expect(classifyGeoOutput('{"status":"ok","lat":19.4,"lon":-99.1}')).toBe("ok");
  });
});

describe("parseConsoleUser (macOS)", () => {
  it("accepts the logged-in console user", () => {
    expect(parseConsoleUser("javierpacheco\n")).toBe("javierpacheco");
    expect(parseConsoleUser("  first.last  ")).toBe("first.last");
  });

  it("rejects the states where nobody is really logged in", () => {
    // At the login window the console is owned by root or loginwindow, and
    // there is no user session that could have collected a position.
    expect(parseConsoleUser("root")).toBeNull();
    expect(parseConsoleUser("loginwindow")).toBeNull();
    expect(parseConsoleUser("")).toBeNull();
    expect(parseConsoleUser("   ")).toBeNull();
    expect(parseConsoleUser(null)).toBeNull();
  });

  it("rejects a name that could escape the path it is interpolated into", () => {
    expect(parseConsoleUser("../../etc")).toBeNull();
    expect(parseConsoleUser("bad name")).toBeNull();
    expect(parseConsoleUser("a/b")).toBeNull();
    expect(parseConsoleUser("$(whoami)")).toBeNull();
  });
});

describe("isFixFresh (macOS staleness window)", () => {
  const now = Date.parse("2026-08-09T18:00:00.000Z");

  it("accepts a fix from the last refresh cycle", () => {
    expect(isFixFresh("2026-08-09T17:50:00.000Z", now)).toBe(true);
  });

  it("tolerates one missed cycle — asleep, no Wi-Fi, a failed request", () => {
    expect(isFixFresh("2026-08-09T17:10:00.000Z", now)).toBe(true);
  });

  it("expires a fix older than the window", () => {
    // The guard that stops a killed status app from pinning a laptop to an
    // office it left days ago.
    expect(isFixFresh("2026-08-09T16:30:00.000Z", now)).toBe(false);
    expect(isFixFresh("2026-08-01T18:00:00.000Z", now)).toBe(false);
  });

  it("rejects a timestamp from the future — clock skew or a forged file", () => {
    expect(isFixFresh("2026-08-09T19:00:00.000Z", now)).toBe(false);
  });

  it("tolerates a little skew rather than discarding a good fix", () => {
    expect(isFixFresh("2026-08-09T18:00:30.000Z", now)).toBe(true);
  });

  it("rejects anything that is not a parseable timestamp", () => {
    expect(isFixFresh(undefined, now)).toBe(false);
    expect(isFixFresh("", now)).toBe(false);
    expect(isFixFresh("yesterday", now)).toBe(false);
    expect(isFixFresh(12345, now)).toBe(false);
  });
});

describe("parseGeoOutput — the fix's own timestamp", () => {
  it("keeps the timestamp the source stamped on the reading", () => {
    // On macOS the status app takes the reading minutes before the daemon
    // reads the file; restamping it as "now" would report a stale position as
    // current.
    const geo = parseGeoOutput(
      '{"lat":19.4,"lon":-99.1,"collectedAtUtc":"2026-08-09T17:45:00.000Z"}',
      at
    );
    expect(geo?.collectedAtUtc).toBe("2026-08-09T17:45:00.000Z");
  });

  it("falls back to now when the source did not stamp one (Windows)", () => {
    expect(parseGeoOutput('{"lat":19.4,"lon":-99.1}', at)?.collectedAtUtc).toBe(
      "2026-08-09T18:00:00.000Z"
    );
  });

  it("falls back to now on an unparseable stamp", () => {
    expect(
      parseGeoOutput('{"lat":19.4,"lon":-99.1,"collectedAtUtc":"nope"}', at)?.collectedAtUtc
    ).toBe("2026-08-09T18:00:00.000Z");
  });
});

describe("extractDetail — las palabras del SO", () => {
  it("conserva el mensaje de la excepción", () => {
    // En Windows con ConsentStore=Allow a nivel máquina, ese texto es lo único
    // que separa "la cuenta SYSTEM no tiene consentimiento" de "este SKU no
    // trae proveedor de ubicación". Se estaba descartando.
    expect(extractDetail("ERROR:Access is denied. (0x80070005)")).toBe("Access is denied. (0x80070005)");
  });

  it("no inventa detalle cuando no hubo queja", () => {
    expect(extractDetail('{"lat":19.4,"lon":-99.1}')).toBeUndefined();
    expect(extractDetail("TIMEOUT")).toBeUndefined();
    expect(extractDetail("")).toBeUndefined();
    expect(extractDetail(null)).toBeUndefined();
  });

  it("acota el largo — es una línea de log, no un volcado", () => {
    expect(extractDetail("ERROR:" + "x".repeat(500))!.length).toBe(300);
  });

  it("trata un ERROR vacío como ausencia de detalle", () => {
    expect(extractDetail("ERROR:")).toBeUndefined();
    expect(extractDetail("ERROR:   ")).toBeUndefined();
  });
});

describe("Windows PositionSource — no aceptar una adivinanza por IP", () => {
  const wifi = '{"lat":19.4,"lon":-99.1,"accuracyM":38,"source":2}';
  const ip   = '{"lat":42.06975,"lon":-2.0098,"accuracyM":382,"source":3}';
  const def  = '{"lat":42.06975,"lon":-2.0098,"accuracyM":382,"source":5}';

  it("acepta una posición que el equipo observó (WiFi, celular, satélite)", () => {
    expect(parseGeoOutput(wifi)?.lat).toBe(19.4);
    expect(classifyGeoOutput(wifi)).toBe("ok");
    expect(parseGeoOutput('{"lat":19.4,"lon":-99.1,"source":0}')).not.toBeNull();
    expect(parseGeoOutput('{"lat":19.4,"lon":-99.1,"source":1}')).not.toBeNull();
  });

  it("RECHAZA la derivada de IP aunque traiga un radio creíble", () => {
    // Caso real: un equipo reportó 42.07,-2.01 (España) con acc=382. La misma
    // clase de mentira que nos hizo abandonar la geolocalización por IP; pasarla
    // por una API del sistema no la vuelve cierta.
    expect(parseGeoOutput(ip)).toBeNull();
    expect(classifyGeoOutput(ip)).toBe("ip_derived_rejected");
  });

  it("RECHAZA también la posición 'Default'", () => {
    expect(parseGeoOutput(def)).toBeNull();
    expect(classifyGeoOutput(def)).toBe("ip_derived_rejected");
  });

  it("no rompe con agentes que aún no mandan 'source'", () => {
    // El campo es nuevo; su ausencia no puede invalidar un fix bueno.
    expect(parseGeoOutput('{"lat":19.4,"lon":-99.1,"accuracyM":38}')).not.toBeNull();
  });
});
