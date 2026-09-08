// src/core/host-match.ts
//
// «¿Este equipo esta en la lista?» para los ajustes de policy que nombran
// equipos por hostname: los CA servers del lector AD CS y los equipos que
// ejecutan las sondas TLS remotas. Un ajuste asi a nivel de tenant sin
// nombres era la forma equivocada (repaso 2026-09-07): todo el parque
// hacia el trabajo de dos o tres equipos.
//
// Casa el nombre NetBIOS con el FQDN en las dos direcciones
// («msig-radius-ca» ≡ «msig-radius-ca.corp.example»), sin mayusculas.

import os from "os";

export function hostMatches(hosts: readonly string[], hostname: string): boolean {
  const me = String(hostname || "").trim().toLowerCase();
  if (!me) return false;
  const meShort = me.split(".")[0];
  return hosts.some((h) => {
    const x = String(h || "").trim().toLowerCase();
    if (!x) return false;
    return x === me || x === meShort || x.split(".")[0] === me || x.split(".")[0] === meShort;
  });
}

/** Lista de hostnames saneada: strings, sin espacios, minusculas, sin repetidos, acotada. */
export function sanitizeHostList(raw: unknown, max = 50): string[] {
  return Array.from(
    new Set(
      (Array.isArray(raw) ? raw : [])
        .filter((h): h is string => typeof h === "string")
        .map((h) => h.trim().toLowerCase())
        .filter((h) => h.length > 0 && h.length <= 253)
    )
  ).slice(0, max);
}

export function thisHostname(): string {
  return os.hostname();
}
