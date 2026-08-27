// Qué hace el agente mientras no hay token.
//
// El comportamiento anterior —throw, morir, que el gestor de servicios lo
// levante— produjo 3722 arranques en cinco días en un equipo de campo. Ninguno
// podía tener éxito: la causa no estaba en el proceso. Lo que se fija aquí es
// que el agente espere en vez de morir, que hable poco, y que continúe solo en
// cuanto el token exista.

import { describe, it, expect, vi } from "vitest";
import {
  MAX_RETRY_MS,
  nextTokenWaitDelayMs,
  shouldLogAttempt,
  waitForEnrollmentToken,
} from "../../src/bootstrap/token-wait";
import type { TokenLookup } from "../../src/bootstrap/token-source";

const sinToken: TokenLookup = {
  token: null,
  attempts: [{ source: "env", location: "ENROLLMENT_TOKEN", found: false, detail: "not set" }],
};
const conToken: TokenLookup = {
  token: "tok_abc",
  attempts: [{ source: "file", location: "/x/enrollment.token", found: true }],
};

const mudo = () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() });

describe("nextTokenWaitDelayMs", () => {
  it("crece y se detiene en el tope", () => {
    expect(nextTokenWaitDelayMs(1)).toBe(15_000);
    expect(nextTokenWaitDelayMs(2)).toBe(30_000);
    expect(nextTokenWaitDelayMs(3)).toBe(60_000);
    expect(nextTokenWaitDelayMs(20)).toBe(MAX_RETRY_MS);
  });

  it("no se desborda ni devuelve valores absurdos con intentos grandes", () => {
    // 2^1000 es Infinity en coma flotante. Sin el tope, un agente que lleva
    // meses esperando dejaría de reintentar del todo.
    const d = nextTokenWaitDelayMs(1000);
    expect(Number.isFinite(d)).toBe(true);
    expect(d).toBe(MAX_RETRY_MS);
  });

  it("trata cualquier intento inválido como el primero", () => {
    expect(nextTokenWaitDelayMs(0)).toBe(15_000);
    expect(nextTokenWaitDelayMs(-5)).toBe(15_000);
  });
});

describe("shouldLogAttempt", () => {
  it("habla al principio, que es cuando alguien mira", () => {
    expect(shouldLogAttempt(1)).toBe(true);
    expect(shouldLogAttempt(2)).toBe(true);
    expect(shouldLogAttempt(3)).toBe(true);
  });

  it("⚠️ luego calla: 3722 renglones idénticos no son información", () => {
    expect(shouldLogAttempt(4)).toBe(false);
    expect(shouldLogAttempt(7)).toBe(false);
    expect(shouldLogAttempt(8)).toBe(true); // ~2 h en el tope
    expect(shouldLogAttempt(9)).toBe(false);
  });

  it("cinco días caídos caben en decenas de renglones, no en decenas de miles", () => {
    const vueltas = 500;
    const hablo = Array.from({ length: vueltas }, (_, i) => shouldLogAttempt(i + 1)).filter(
      Boolean
    ).length;
    expect(hablo).toBeLessThan(100);
  });
});

describe("waitForEnrollmentToken", () => {
  it("devuelve el token sin esperar cuando ya está", async () => {
    const sleep = vi.fn(async () => {});
    const token = await waitForEnrollmentToken({
      read: () => conToken,
      sleep,
      logger: mudo(),
      onBlocked: vi.fn(),
      onRecovered: vi.fn(),
    });

    expect(token).toBe("tok_abc");
    expect(sleep).not.toHaveBeenCalled();
  });

  it("⚠️ se recupera solo cuando el token aparece, sin reiniciar nada", async () => {
    // Éste es el caso de campo. En DANIELA-PC el token terminó estando
    // presente; con el comportamiento anterior eso no servía de nada porque el
    // proceso ya había muerto y vuelto a nacer con la misma pregunta. Aquí el
    // mismo proceso lo ve en la siguiente vuelta y continúa.
    const lecturas = [sinToken, sinToken, conToken];
    let i = 0;
    const log = mudo();
    const onRecovered = vi.fn();

    const token = await waitForEnrollmentToken({
      read: () => lecturas[i++],
      sleep: async () => {},
      logger: log,
      onBlocked: vi.fn(),
      onRecovered,
    });

    expect(token).toBe("tok_abc");
    expect(onRecovered).toHaveBeenCalledTimes(1);
    expect(log.info).toHaveBeenCalledWith(expect.stringMatching(/appeared after 3 checks/));
  });

  it("el primer fallo explica el motivo completo y deja rastro en la máquina", async () => {
    const log = mudo();
    const onBlocked = vi.fn();

    await waitForEnrollmentToken({
      read: () => sinToken,
      sleep: async () => {},
      logger: log,
      onBlocked,
      onRecovered: vi.fn(),
      maxAttempts: 1,
    });

    expect(onBlocked).toHaveBeenCalledTimes(1);
    const [[diagnostico]] = onBlocked.mock.calls;
    expect(diagnostico).toMatch(/ENROLLMENT_TOKEN/);

    const [[mensaje]] = log.error.mock.calls;
    // Sin esta frase, la reacción natural —reiniciar el servicio— es
    // exactamente lo que la persona ya intentó y lo que no puede funcionar.
    expect(mensaje).toMatch(/restarting the service will NOT help/i);
  });

  it("no repite el diagnóstico completo en cada vuelta", async () => {
    const log = mudo();
    const onBlocked = vi.fn();

    await waitForEnrollmentToken({
      read: () => sinToken,
      sleep: async () => {},
      logger: log,
      onBlocked,
      onRecovered: vi.fn(),
      maxAttempts: 12,
    });

    expect(onBlocked).toHaveBeenCalledTimes(1);
    expect(log.error).toHaveBeenCalledTimes(1);
    // 12 vueltas → los avisos cortos de las vueltas 2, 3 y 8.
    expect(log.warn).toHaveBeenCalledTimes(3);
  });

  it("espera con la cadencia creciente entre vueltas", async () => {
    const esperas: number[] = [];
    await waitForEnrollmentToken({
      read: () => sinToken,
      sleep: async (ms) => {
        esperas.push(ms);
      },
      logger: mudo(),
      onBlocked: vi.fn(),
      onRecovered: vi.fn(),
      maxAttempts: 4,
    });

    expect(esperas).toEqual([15_000, 30_000, 60_000]);
  });

  it("no avisa 'recuperado' si nunca estuvo bloqueado", async () => {
    const onRecovered = vi.fn();
    await waitForEnrollmentToken({
      read: () => conToken,
      sleep: async () => {},
      logger: mudo(),
      onBlocked: vi.fn(),
      onRecovered,
    });
    expect(onRecovered).not.toHaveBeenCalled();
  });
});
