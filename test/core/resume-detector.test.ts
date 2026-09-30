// test/core/resume-detector.test.ts
import { describe, it, expect } from "vitest";
import { createResumeDetector, RESUME_GAP_FACTOR } from "../../src/core/resume-detector";

describe("createResumeDetector", () => {
  const clock = (start = 0) => {
    let t = start;
    return { now: () => t, advance: (ms: number) => (t += ms) };
  };

  it("un tick a su hora (o algo tarde) no es una suspensión", () => {
    const c = clock();
    const d = createResumeDetector(60_000, c.now);
    c.advance(60_000);
    expect(d.check()).toBeNull();
    c.advance(60_000 * RESUME_GAP_FACTOR); // justo en el límite
    expect(d.check()).toBeNull();
  });

  it("⭐ las 3 h 57 min de AquilesF entre dos ticks sí lo son, y devuelve el hueco", () => {
    const c = clock();
    const d = createResumeDetector(60_000, c.now);
    c.advance(14_245_000);
    expect(d.check()).toBe(14_245_000);
  });

  it("mide desde el tick anterior, no desde el arranque", () => {
    const c = clock();
    const d = createResumeDetector(60_000, c.now);
    c.advance(10 * 60_000);
    expect(d.check()).toBe(600_000);
    c.advance(60_000);
    expect(d.check()).toBeNull();
  });
});
