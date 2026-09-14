// test/core/policy-runtime-passthrough.test.ts
//
// `validatePolicy()` RECONSTRUYE la policy como un literal con claves
// nombradas: todo bloque que no se nombre ahí desaparece sin rastro, aunque
// un getter lo lea. Así murieron dos cosas a la vez:
//
//   * `sdp.dpBaseUrls` — el control plane lo inyecta por equipo
//     (modules/policies/policy-wire.ts) y el auto-update periódico nunca
//     prefería el DP de la LAN.
//   * `remoteControl.maxUploadBytes` — el tope de subida que fija el tenant
//     nunca se aplicaba; el agente usaba siempre su techo de 2 GiB.
//
// policy-dp-base-urls.test.ts no lo podía ver: construye el runtime con
// `Object.create` y asigna `rt.policy` a mano, saltándose el validador. Estos
// tests entran por donde entra la policy de verdad: el store → init() /
// applyUpdate().

import { describe, expect, it } from "vitest";
import { PolicyRuntime } from "../../src/core/policy-runtime";
import type { PolicyStore } from "../../src/core/policy-store";

// Doble con la forma que usa el llamador real: sólo getPolicy/getVersion.
function storeWith(doc: any): { store: PolicyStore; set(next: any): void } {
  let current = doc;
  const store = {
    getPolicy: () => current,
    getVersion: () => "test"
  } as unknown as PolicyStore;
  return { store, set: (next) => { current = next; } };
}

const DOC = {
  version: "7",
  plugins: { enabled: ["amp", "rcp", "sdp"] },
  sdp: { dpBaseUrls: ["https://10.1.2.3:47821"] },
  remoteControl: { maxUploadBytes: 50 * 1024 * 1024 }
};

describe("PolicyRuntime keeps the blocks its getters read", () => {
  it("init(): sdp.dpBaseUrls survives validation", async () => {
    const rt = new PolicyRuntime(storeWith(DOC).store, null);
    await rt.init();
    expect(rt.dpBaseUrls()).toEqual(["https://10.1.2.3:47821"]);
  });

  it("init(): remoteControl.maxUploadBytes survives validation", async () => {
    const rt = new PolicyRuntime(storeWith(DOC).store, null);
    await rt.init();
    expect(rt.remoteFileMaxUploadBytes()).toBe(50 * 1024 * 1024);
  });

  it("applyUpdate(): both blocks arrive with a policy pushed later", async () => {
    const s = storeWith({ version: "1" });
    const rt = new PolicyRuntime(s.store, null);
    await rt.init();
    expect(rt.dpBaseUrls()).toEqual([]);
    expect(rt.remoteFileMaxUploadBytes()).toBeNull();

    s.set(DOC);
    await rt.applyUpdate();
    expect(rt.dpBaseUrls()).toEqual(["https://10.1.2.3:47821"]);
    expect(rt.remoteFileMaxUploadBytes()).toBe(50 * 1024 * 1024);
  });

  it("applyUpdate(): a policy that stops carrying them clears them", async () => {
    // El DP puede desaparecer (equipo movido de sede) y el tenant puede
    // quitar el tope: lo que ya no viene no debe quedarse pegado.
    const s = storeWith(DOC);
    const rt = new PolicyRuntime(s.store, null);
    await rt.init();

    s.set({ version: "8" });
    await rt.applyUpdate();
    expect(rt.dpBaseUrls()).toEqual([]);
    expect(rt.remoteFileMaxUploadBytes()).toBeNull();
  });

  it("the getters still fail closed on junk that made it through", async () => {
    const rt = new PolicyRuntime(
      storeWith({
        sdp: { dpBaseUrls: ["http://10.1.2.4:47821", "file:///etc/passwd", 42] },
        remoteControl: { maxUploadBytes: "lots" }
      }).store,
      null
    );
    await rt.init();
    expect(rt.dpBaseUrls()).toEqual([]);
    expect(rt.remoteFileMaxUploadBytes()).toBeNull();
  });
});

describe("PolicyRuntime — browserExtensions", () => {
  const ID = "cjpalhdlnbpafiamejdnhcphjbkeiagm";
  it("sobrevive a la validación entrando por el store, y el getter descarta lo que no es un id", async () => {
    const s = storeWith({ version: "1" });
    const rt = new PolicyRuntime(s.store, null);
    await rt.init();
    expect(rt.browserExtensionPolicy().chrome.blocklist).toEqual([]);

    s.set({ version: "2", browserExtensions: { chrome: { blocklist: [ID, "*", "calc.exe"], allowlist: ["*", ID] }, edge: { allowlist: [ID] } } });
    await rt.applyUpdate();
    const p = rt.browserExtensionPolicy();
    expect(p.chrome.blocklist).toEqual([ID, "*"]);
    // `*` no vale en la allowlist, y un id bloqueado no puede estar permitido.
    expect(p.chrome.allowlist).toEqual([]);
    expect(p.edge).toEqual({ blocklist: [], allowlist: [ID] });
  });
});
