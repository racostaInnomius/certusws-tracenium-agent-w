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
import {
  evaluateAnchorPins,
  describeAnchorVerdict
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
