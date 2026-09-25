// test/plugins/cdp-key-algorithm.test.ts
//
// ADR-0033 F1 — la tabla de algoritmos de `cdp.csr.generate`.
//
// Dos cosas, y la segunda es la que de verdad duele si falta:
//
//   · Lo DESCONOCIDO se rechaza y no cae a nada. Caer a RSA-2048
//     convertiría un «ECDSA P-384» mal escrito en una clave de 2048 bits
//     que nadie pidió, con un CSR que el inventario declararía como lo
//     pedido: sólo se vería auditando la CA meses después.
//
//   · Las CUATRO implementaciones admiten lo mismo. Son cuatro ficheros
//     en tres lenguajes (TS compartido, C# de Windows, Swift del helper
//     de macOS) y nada los ata salvo esto. La misma petición no puede
//     producir certificados distintos según el sistema operativo del
//     endpoint — que es justo lo que ADR-0011 dice que no puede pasar.

import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import {
  CDP_DEFAULT_KEY_ALGORITHM,
  CDP_KEY_ALGORITHMS,
  cdpKeyAlgorithmError,
  resolveCdpKeyAlgorithm
} from "../../privsvc/shared/cdp-key-algorithm";
import { buildGenPkeyArgs } from "../../privsvc/linux/src/cdp-keys";

describe("tabla de algoritmos (compartida macOS/Linux)", () => {
  it.each([
    ["RSA_2048", "rsa", 2048, "sha256"],
    ["RSA_3072", "rsa", 3072, "sha256"],
    ["RSA_4096", "rsa", 4096, "sha256"],
    ["ECDSA_P256", "ecdsa", 256, "sha256"],
    // El hash acompaña a la curva: P-384 con SHA-256 es legal y
    // desperdicia la curva que alguien eligió a propósito.
    ["ECDSA_P384", "ecdsa", 384, "sha384"]
  ])("resuelve %s", (raw, kind, bits, digest) => {
    const spec = resolveCdpKeyAlgorithm(raw)!;
    expect(spec).toBeTruthy();
    expect(spec.name).toBe(raw);
    expect(spec.kind).toBe(kind);
    expect(spec.bits).toBe(bits);
    expect(spec.digest).toBe(digest);
  });

  it("sin campo sigue siendo RSA_2048", () => {
    // Un control plane que todavía no manda `keyAlgorithm` tiene que
    // seguir emitiendo lo mismo que antes de ADR-0033.
    for (const vacio of [undefined, null, "", "   "]) {
      expect(resolveCdpKeyAlgorithm(vacio)?.name).toBe(CDP_DEFAULT_KEY_ALGORITHM);
    }
    expect(CDP_DEFAULT_KEY_ALGORITHM).toBe("RSA_2048");
  });

  it("la caja no importa, pero nada más", () => {
    expect(resolveCdpKeyAlgorithm("ecdsa_p384")?.name).toBe("ECDSA_P384");
    expect(resolveCdpKeyAlgorithm(" rsa_3072 ")?.name).toBe("RSA_3072");
  });

  it("⭐ lo desconocido se rechaza y NO cae a otra cosa", () => {
    for (const malo of [
      "RSA_1024", // más débil: jamás
      "RSA_2047",
      "ECDSA_P521", // no está en F1
      "ECDSA-P384", // guion en vez de subrayado
      "ED25519",
      "P384",
      "RSA",
      "rsa_3072 ; DROP",
      42,
      {},
      []
    ]) {
      expect(resolveCdpKeyAlgorithm(malo as any), `${String(malo)} debería rechazarse`).toBeNull();
    }
  });

  it("el mensaje de rechazo dice qué SÍ se admite", () => {
    const msg = cdpKeyAlgorithmError("ED25519");
    expect(msg).toContain("ED25519");
    expect(msg).toContain("no soportado");
    // Sin la lista hay que leer el código del PrivSvc desde el otro lado
    // del mundo para saber qué escribir.
    for (const n of CDP_KEY_ALGORITHMS) expect(msg).toContain(n);
  });
});

describe("openssl: los argumentos de generación (Linux)", () => {
  it("RSA pide los bits pedidos, no otros", () => {
    expect(buildGenPkeyArgs(resolveCdpKeyAlgorithm("RSA_4096")!, "/k.pem")).toEqual([
      "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", "/k.pem"
    ]);
  });

  it("⭐ EC pide la curva POR NOMBRE", () => {
    // Sin `ec_param_enc:named_curve` openssl mete los parámetros
    // explícitos de la curva en la clave y en el CSR. Verifica igual, y
    // una CA seria lo rechaza: los perfiles públicos exigen curva con
    // nombre. Es un fallo que no se ve hasta que la CA contesta.
    const args = buildGenPkeyArgs(resolveCdpKeyAlgorithm("ECDSA_P384")!, "/k.pem");
    expect(args).toContain("EC");
    expect(args).toContain("ec_paramgen_curve:P-384");
    expect(args).toContain("ec_param_enc:named_curve");
    expect(args).not.toContain("RSA");
  });
});

describe("⭐ las cuatro implementaciones admiten lo MISMO", () => {
  const leer = (rel: string) => fs.readFileSync(path.join(__dirname, "../..", rel), "utf8");

  it("la tabla de C# (Windows) coincide", () => {
    const cs = leer("privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CdpKeyAlgorithm.cs");
    const nombres = [...cs.matchAll(/\["([A-Z0-9_]+)"\] = new CdpKeyAlgorithmSpec/g)].map((m) => m[1]);
    expect(nombres).toEqual(CDP_KEY_ALGORITHMS);
    // Y el hash por algoritmo, que es donde es fácil divergir.
    expect(cs).toMatch(/"ECDSA_P384", CdpKeyKind\.Ecdsa, 384, "SHA384"/);
    expect(cs).toMatch(/"ECDSA_P256", CdpKeyKind\.Ecdsa, 256, "SHA256"/);
  });

  it("la tabla del helper Swift (macOS) coincide", () => {
    const swift = leer("privsvc/macos/helpers/keystore/main.swift");
    const bloque = swift.slice(swift.indexOf("let SUPPORTED_ALGS"));
    const nombres = [...bloque.slice(0, bloque.indexOf("]\n")).matchAll(/"([A-Z0-9_]+)": KeyAlg/g)].map((m) => m[1]);
    expect(nombres).toEqual(CDP_KEY_ALGORITHMS);
  });
});
