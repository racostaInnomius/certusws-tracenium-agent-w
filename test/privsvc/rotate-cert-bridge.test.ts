// test/privsvc/rotate-cert-bridge.test.ts
//
// Todo campo de `RotateCert` tiene que CRUZAR el puente del privsvc.
//
// ⚠️ `altKeyAlgorithm` SE PERDÍA EN EL ESLABÓN DEL MEDIO, EN LAS TRES
// PLATAFORMAS (2026-09-11).
//
// El backend lo mandaba, el proto instalado lo conocía y el agente lo leía
// — pero el canal gRPC lo sostiene el PRIVSVC, que traduce cada mensaje
// del servidor a un push IPC, y los tres puentes reenviaban sólo
// `reason`. El agente recibía siempre `""` y renovaba clásico aunque la CA
// pudiera firmar híbrido: poner ISSUING_CA_ALT_KEY_PEM no habría producido
// ni un certificado catalyst, todo en verde. «Las 3 listas» por 5ª vez.
//
// Los campos se DERIVAN del proto: un campo nuevo en RotateCert hace
// fallar este test hasta que los tres puentes y el agente lo recojan.

import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";

const raiz = path.join(__dirname, "..", "..");
const leer = (...p: string[]) => fs.readFileSync(path.join(raiz, ...p), "utf8");

const cuerpo = (leer("proto", "controlplane.proto").match(/message RotateCert\s*\{([\s\S]*?)\n\}/) || [])[1] || "";
const campos = [...cuerpo.matchAll(/^\s*(?:string|bool|int32|int64|uint32|bytes)\s+(\w+)\s*=\s*\d+\s*;/gm)].map((m) => m[1]);

/** El bloque que traduce RotateCert a push, en cada puente. */
const bloqueTs = (src: string) => {
  const i = src.indexOf("if (msg.rotateCert)");
  return i === -1 ? "" : src.slice(i, src.indexOf("return;", i));
};
const bloqueCs = (src: string) => {
  const i = src.indexOf("if (msg.RotateCert is not null)");
  return i === -1 ? "" : src.slice(i, src.indexOf("});", i));
};

const puentes = [
  { nombre: "macOS", bloque: bloqueTs(leer("privsvc", "macos", "src", "grpc-bridge.ts")), lleva: (b: string, c: string) => b.includes(`${c}:`) },
  { nombre: "Linux", bloque: bloqueTs(leer("privsvc", "linux", "src", "grpc-bridge.ts")), lleva: (b: string, c: string) => b.includes(`${c}:`) },
  {
    nombre: "Windows",
    bloque: bloqueCs(leer("privsvc", "windows", "Tracenium.PrivSvc.Windows", "Ipc", "GrpcBridge.cs")),
    lleva: (b: string, c: string) => new RegExp(`\\b${c}\\s*=`).test(b)
  }
];

describe("RotateCert cruza el puente del privsvc entero", () => {
  it("el proto declara reason y altKeyAlgorithm (si no, el censo no mediría nada)", () => {
    expect(campos).toEqual(expect.arrayContaining(["reason", "altKeyAlgorithm"]));
  });

  for (const p of puentes) {
    it(`⚠️ el puente de ${p.nombre} reenvía todos los campos de RotateCert`, () => {
      expect(p.bloque, `no se encontró el bloque de RotateCert en ${p.nombre}`).not.toBe("");
      const faltan = campos.filter((c) => !p.lleva(p.bloque, c));
      expect(faltan, `${p.nombre} se come: ${faltan.join(", ")}`).toEqual([]);
    });
  }

  it("el agente lee cada campo de lo que el puente le entrega", () => {
    const stream = leer("src", "transport", "grpc-stream.ts");
    const noLeidos = campos.filter((c) => !stream.includes(`msg.rotateCert?.${c}`));
    expect(noLeidos).toEqual([]);
  });
});
