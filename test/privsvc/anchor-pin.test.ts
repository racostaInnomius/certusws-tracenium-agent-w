// test/privsvc/anchor-pin.test.ts
//
// Pin de anclas de confianza — ADR-0011 fase 0.
//
// Lo que esto protege: el agente instala como RAIZ DEL SISTEMA los
// certificados autofirmados que vengan en `caBundlePem`, y ese bundle
// sale de la respuesta del servidor. Al enrolar es legitimo; que la
// renovacion lo repita periodicamente sin recordar en que confio la
// primera vez es lo que convierte una decision puntual en recurrente, y
// lo que permite a un control plane comprometido plantar un ancla en
// cada endpoint por la ruta rutinaria.

import { describe, it, expect } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import {
  anchorStatePath,
  evaluateAnchorPins,
  describeAnchorVerdict,
  loadAnchorState,
  saveAnchorState
} from "../../privsvc/macos/src/anchor-pin";

const A = "aa11";
const B = "bb22";
const C = "cc33";

describe("evaluateAnchorPins — linea base", () => {
  it("la PRIMERA vez no acusa a nadie", () => {
    // Sin pines previos no hay contra que comparar. Tratar todo como
    // sospechoso convertiria cada enrolamiento en una alarma, y una
    // alarma que suena siempre se ignora siempre.
    const v = evaluateAnchorPins([], [A, B], "observe");
    expect(v.firstRun).toBe(true);
    expect(v.unpinned).toEqual([]);
    expect(v.rejected).toEqual([]);
  });

  it("un fichero de pines corrupto NO puede convertirse en alarma de flota", () => {
    // loadAnchorPins devuelve [] cuando no puede leer, asi que el caso
    // llega aqui como firstRun. Es deliberado: el fallo seguro es callar.
    expect(evaluateAnchorPins([], [A], "enforce").rejected).toEqual([]);
  });
});

describe("evaluateAnchorPins — deteccion", () => {
  it("un ancla nueva sobre una linea base existente se marca", () => {
    const v = evaluateAnchorPins([A], [A, B], "observe");
    expect(v.firstRun).toBe(false);
    expect(v.unpinned).toEqual([B]);
  });

  it("no marca nada cuando el bundle no trae nada nuevo", () => {
    expect(evaluateAnchorPins([A, B], [A], "observe").unpinned).toEqual([]);
  });

  it("compara sin distinguir mayusculas", () => {
    // Las huellas viajan en mayusculas o minusculas segun quien las
    // formatee; una diferencia de caja no es un ancla nueva.
    expect(evaluateAnchorPins(["AA11"], ["aa11"], "observe").unpinned).toEqual([]);
  });
});

describe("evaluateAnchorPins — observe vs enforce", () => {
  it("observe DETECTA pero no rechaza", () => {
    // El modo por defecto, y la razon esta en el modulo: hay una
    // rotacion de CA en curso, y un pin estricto en mitad de una
    // rotacion legitima deja equipos sin poder conectar — y sin conexion
    // no se les puede mandar el arreglo.
    const v = evaluateAnchorPins([A], [B], "observe");
    expect(v.unpinned).toEqual([B]);
    expect(v.rejected).toEqual([]);
  });

  it("enforce rechaza exactamente lo no fijado", () => {
    const v = evaluateAnchorPins([A], [A, B, C], "enforce");
    expect(v.rejected).toEqual([B, C]);
    // Y NO toca lo que ya estaba fijado: rechazar el ancla vigente
    // seria romper la confianza que el equipo ya tiene.
    expect(v.rejected).not.toContain(A);
  });

  it("enforce en el primer arranque sigue sin rechazar", () => {
    expect(evaluateAnchorPins([], [A, B], "enforce").rejected).toEqual([]);
  });
});

describe("describeAnchorVerdict — el veredicto tiene que poder leerse", () => {
  it("distingue linea base, todo conocido, y hallazgo", () => {
    expect(describeAnchorVerdict(evaluateAnchorPins([], [A], "observe"))).toMatch(/linea base/);
    expect(describeAnchorVerdict(evaluateAnchorPins([A], [A], "observe"))).toMatch(/ya fijadas/);
    expect(describeAnchorVerdict(evaluateAnchorPins([A], [B], "observe"))).toMatch(/ATENCION/);
  });

  it("dice si el ancla se instalo igual o se nego", () => {
    // La diferencia importa para quien lee el log a las 3 de la manana:
    // "lo vimos y lo dejamos entrar" y "lo vimos y lo paramos" son
    // situaciones distintas.
    expect(describeAnchorVerdict(evaluateAnchorPins([A], [B], "observe"))).toMatch(/observe/);
    expect(describeAnchorVerdict(evaluateAnchorPins([A], [B], "enforce"))).toMatch(/RECHAZADA/);
  });

  it("nombra las huellas concretas", () => {
    // Un aviso que no dice CUAL ancla obliga a ir a buscarla a mano.
    expect(describeAnchorVerdict(evaluateAnchorPins([A], [B], "observe"))).toContain(B);
  });
});

// ── La observacion tiene que SALIR del equipo (fase 0, paso 1) ───────
//
// Medido 2026-09-03: el modo `observe` observaba hacia un log local. El
// backend no tenia una sola referencia a esto y agent-core no leia el
// veredicto, asi que el modo cuyo UNICO proposito es generar la
// evidencia para decidir `enforce` no entregaba ninguna.

describe("estado persistido del pin", () => {
  const dir = () => fs.mkdtempSync(path.join(os.tmpdir(), "anchorstate-"));

  it("sin fichero devuelve null, que es «no ha evaluado» y no «no vio nada»", () => {
    expect(loadAnchorState(dir())).toBeNull();
  });

  it("guarda el veredicto con su origen", () => {
    const d = dir();
    saveAnchorState(d, evaluateAnchorPins([A], [B], "observe"), "observe", "renew");
    const s = loadAnchorState(d)!;
    expect(s.unpinned).toEqual([B]);
    expect(s.source).toBe("renew");
    expect(s.mode).toBe("observe");
  });

  it("⭐ el contador de hallazgos SOLO crece, aunque el detalle se pise", () => {
    // El resto del fichero es el ultimo veredicto y se sobrescribe. Si
    // ocurren dos eventos entre dos ciclos de facts, del primero solo
    // queda este numero — y el criterio de salida del paso 2 es «cero
    // anclas no fijadas», que sin esto seria indemostrable.
    const d = dir();
    saveAnchorState(d, evaluateAnchorPins([A], [B], "observe"), "observe", "renew");
    saveAnchorState(d, evaluateAnchorPins([A, B], [C], "observe"), "observe", "renew");
    expect(loadAnchorState(d)!.unpinnedSeenTotal).toBe(2);

    // Un veredicto limpio NO lo incrementa ni lo reinicia: el historico
    // de que paso algo tiene que sobrevivir a que despues fuera bien.
    saveAnchorState(d, evaluateAnchorPins([A], [A], "observe"), "observe", "renew");
    const s = loadAnchorState(d)!;
    expect(s.unpinnedSeenTotal).toBe(2);
    expect(s.unpinned).toEqual([]);
  });

  it("un fichero corrupto no es una alarma", () => {
    // Mismo fallo seguro que los pines: un JSON roto no puede
    // convertirse en un hallazgo para toda la flota.
    const d = dir();
    fs.writeFileSync(anchorStatePath(d), "{ esto no es json");
    expect(loadAnchorState(d)).toBeNull();
  });
});
