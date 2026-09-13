// test/plugins/asp/predicate.test.ts
//
// ADR-0022 — el mismo corpus que ejecuta el backend
// (certusws-tracenium/modules/asp/__tests__/predicate-conformance.json) contra
// la copia del agente. Si la semántica cambia en un lado y el corpus no se
// copia, falla uno de los dos.

import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import corpus from "./predicate-conformance.json";
import { compilePredicate, evaluatePredicate, type Predicate } from "../../../src/plugins/asp/predicate";

describe("asp predicate (agente) — corpus de conformidad", () => {
  for (const c of corpus.compile) {
    it(`compile: ${c.name}`, () => {
      expect(compilePredicate(c.predicate).length === 0).toBe(c.valid);
    });
  }
  for (const c of corpus.evaluate) {
    it(`evaluate: ${c.name}`, () => {
      const out = evaluatePredicate(c.predicate as Predicate, c.evidence);
      expect(out.outcome).toBe(c.outcome);
      if (c.outcome === "missing") expect((out as any).path).toBe((c as any).path);
    });
  }
});

describe("asp predicate — la copia del backend es la misma", () => {
  // Cuando los dos repos están lado a lado (el workspace de desarrollo), el
  // cuerpo tiene que ser idéntico salvo la primera línea (la ruta). En CI el
  // repo hermano no existe y se omite: el corpus de arriba sigue siendo la
  // guarda.
  const sibling = path.resolve(__dirname, "../../../../certusws-tracenium/modules/asp/predicate.ts");
  it.skipIf(!fs.existsSync(sibling))("predicate.ts idéntico al del backend", () => {
    const mine = fs.readFileSync(path.resolve(__dirname, "../../../src/plugins/asp/predicate.ts"), "utf8").split("\n").slice(1).join("\n");
    const theirs = fs.readFileSync(sibling, "utf8").split("\n").slice(1).join("\n");
    expect(mine).toBe(theirs);
  });
});
