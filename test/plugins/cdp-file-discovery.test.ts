// test/plugins/cdp-file-discovery.test.ts
//
// Ola 1.1 — descubrimiento de ficheros por defecto.
//
// Lo que se fija aquí:
//   1. Presupuesto de TIEMPO y de ficheros: el recorrido se corta y lo
//      DICE (truncated + incompleteRoots), en vez de parar en silencio.
//   2. Incremental: un fichero sin cambios sale de la caché pero se vuelve
//      a EMITIR (el control plane retira lo que no se reporta).
//   3. Keystores por bytes mágicos (JKS/JCEKS/PKCS#12, da igual el nombre);
//      el que no abre es un almacén ilegible, no un vacío.
//   4. Claves sueltas: presencia (y la ilegible también se dice).
//   5. Bajo una raíz POR DEFECTO: copias de bundles públicos, directorios
//      de paquetes y rutas excluidas no se inventarían; lo denegado se
//      cuenta aparte.
//
// Ficheros de verdad en un directorio temporal: lo que se prueba es el
// manejo de bytes y de directorios reales.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "child_process";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import {
  collectCertFiles,
  defaultFileDiscoveryRoots,
  dirPrefix,
  type FileScanCache,
  type FileScanRecord
} from "../../src/plugins/cdp/providers/cert-files";
import { matchLooseKeys } from "../../src/plugins/cdp";
import { FIXTURE_CERT, FIXTURE_KEY } from "./tls-fixture";
import { OPENSSL } from "../privsvc/openssl-compat";

let root: string;
const w = (rel: string, content: string | Buffer) => {
  fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  fs.writeFileSync(path.join(root, rel), content);
};
const derOf = (pem: string) => Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");

const u4 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const utf = (s: string) => { const d = Buffer.from(s, "utf8"); const b = Buffer.alloc(2); b.writeUInt16BE(d.length); return Buffer.concat([b, d]); };
const u8 = (n: number) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
function keystore(magic: number, entries: Array<{ tag: 1 | 2 | 3; der?: Buffer }>): Buffer {
  const parts: Buffer[] = [u4(magic), u4(2), u4(entries.length)];
  for (const e of entries) {
    if (e.tag === 2) parts.push(u4(2), utf("t"), u8(1), utf("X.509"), u4(e.der!.length), e.der!);
    else if (e.tag === 1) parts.push(u4(1), utf("k"), u8(1), u4(8), Buffer.alloc(8, 0xab), u4(1), utf("X.509"), u4(e.der!.length), e.der!);
    else parts.push(u4(3), utf("s"), u8(1), Buffer.from([0xac, 0xed, 0x00, 0x05]));
  }
  parts.push(Buffer.alloc(20));
  return Buffer.concat(parts);
}

function memoryCache(): FileScanCache & { rows: Map<string, { size: number; mtimeMs: number; record: FileScanRecord }>; gets: number } {
  const rows = new Map<string, { size: number; mtimeMs: number; record: FileScanRecord }>();
  const c = {
    rows,
    gets: 0,
    get(p: string, size: number, mtimeMs: number) {
      c.gets += 1;
      const r = rows.get(p);
      return r && r.size === size && r.mtimeMs === mtimeMs ? r.record : undefined;
    },
    put(p: string, size: number, mtimeMs: number, record: FileScanRecord) {
      rows.set(p, { size, mtimeMs, record: JSON.parse(JSON.stringify(record)) });
    },
    prune(seen: Set<string>, keep: string[]) {
      for (const p of [...rows.keys()]) if (!seen.has(p) && !keep.some((k) => p.startsWith(k))) rows.delete(p);
    }
  };
  return c;
}

let bundle = "";
beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-disc-"));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-disc-gen-"));
  const ossl = (...a: string[]) => execFileSync(OPENSSL, a, { cwd: tmp, stdio: "pipe" });
  // 41 CAs autofirmadas en un solo fichero: la forma de una copia de certifi.
  const cas: string[] = [];
  for (let i = 0; i < 41; i++) {
    ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", `k${i}.pem`,
      "-out", `c${i}.pem`, "-subj", `/CN=bundle-ca-${i}`, "-days", "30", "-addext", "basicConstraints=critical,CA:TRUE");
    cas.push(fs.readFileSync(path.join(tmp, `c${i}.pem`), "utf8"));
  }
  bundle = cas.join("\n");
  ossl("pkcs12", "-export", "-in", "c0.pem", "-inkey", "k0.pem", "-passout", "pass:", "-out", "empty.p12");
  ossl("pkcs12", "-export", "-in", "c1.pem", "-inkey", "k1.pem", "-passout", "pass:secreta", "-out", "locked.p12");

  const certDer = derOf(FIXTURE_CERT);
  w("etc/nginx/ssl/server.crt", FIXTURE_CERT);
  w("etc/nginx/ssl/server.key", FIXTURE_KEY);
  w("etc/app/tomcat.keystore", keystore(0xfeedfeed, [{ tag: 1, der: certDer }]));
  w("etc/app/store.jceks", keystore(0xcececece, [{ tag: 2, der: certDer }]));
  w("etc/app/secret.jceks", keystore(0xcececece, [{ tag: 2, der: certDer }, { tag: 3 }]));
  // PKCS#12 con un nombre que no lo delata: se reconoce por estructura.
  w("etc/app/keystore", fs.readFileSync(path.join(tmp, "empty.p12")));
  w("etc/app/locked.pfx", fs.readFileSync(path.join(tmp, "locked.p12")));
  w("opt/venv/lib/site-packages/certifi/cacert.pem", bundle);
  w("opt/tool/ca-bundle.crt", bundle);
  w("excluded/dir/x.crt", FIXTURE_CERT);
  fs.rmSync(tmp, { recursive: true, force: true });
});

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe("collectCertFiles — raíces por defecto", () => {
  it("⭐ keystores por bytes mágicos: JKS con clave, JCEKS legible, PKCS#12 sin nombre", async () => {
    const r = await collectCertFiles([{ path: path.join(root, "etc"), origin: "default" }]);
    const byStore = (suffix: string) => r.items.filter((i) => i.store.name.endsWith(suffix));
    const jks = byStore("tomcat.keystore");
    expect(jks).toHaveLength(1);
    expect(jks[0]).toMatchObject({ source: "java-store", hasPrivateKey: true, keyStorage: "software", keyExportable: true });
    expect(byStore("store.jceks")).toHaveLength(1);
    const p12 = byStore(`${path.sep}keystore`);
    expect(p12).toHaveLength(1);
    expect(p12[0]).toMatchObject({ source: "file", hasPrivateKey: true });
    expect(r.keystores).toBe(5);
  });

  it("⭐ un keystore que no abre es ILEGIBLE con su razón — nunca un vacío", async () => {
    const r = await collectCertFiles([{ path: path.join(root, "etc"), origin: "default" }]);
    const locked = r.unreadableFiles.find((f) => f.endsWith("locked.pfx"))!;
    expect(r.unreadableReasons[locked]).toMatch(/^pkcs12: password required/);
    const secret = r.unreadableFiles.find((f) => f.endsWith("secret.jceks"))!;
    expect(r.unreadableReasons[secret]).toMatch(/^jceks: .*secret-key/);
    expect(r.items.some((i) => i.store.name.endsWith("secret.jceks"))).toBe(false);
  });

  it("⭐ clave suelta: presencia, casa con su certificado del mismo directorio y lo marca con clave", async () => {
    const r = await collectCertFiles([{ path: path.join(root, "etc"), origin: "default" }]);
    expect(r.keys).toHaveLength(1);
    expect(r.keys[0]).toMatchObject({ format: "pkcs8", keyAlgorithm: "RSA", keySizeBits: 2048, encrypted: false });
    const crt = r.items.find((i) => i.store.name.endsWith("server.crt"))!;
    expect(crt.hasPrivateKey).toBe(false); // el colector no lo afirma...
    const [matched] = matchLooseKeys(r.keys, r.items);
    expect(matched).toMatchObject({ certMatch: "same-dir", matchedFingerprint256: crt.fingerprint256 });
    expect(crt).toMatchObject({ hasPrivateKey: true, keyStorage: "software" }); // ...el cruce sí, con evidencia
    expect(JSON.stringify(r.keys)).not.toContain("MII"); // ni un trozo de la clave en base64
  });

  it("copias de un bundle público y árboles de paquetes no se inventarían bajo una raíz por defecto", async () => {
    const r = await collectCertFiles([{ path: path.join(root, "opt"), origin: "default" }]);
    expect(r.items).toEqual([]);
    expect(r.trustBundlesSkipped).toBe(1); // ca-bundle.crt; site-packages ni se recorre
  });

  it("…pero el operador que configura esa ruta la obtiene entera", async () => {
    const r = await collectCertFiles([{ path: path.join(root, "opt", "tool"), origin: "configured" }]);
    expect(r.items).toHaveLength(41);
  });

  it("una ruta excluida no se recorre", async () => {
    const r = await collectCertFiles([{ path: root, origin: "default" }], { excludePaths: [path.join(root, "excluded")] });
    expect(r.items.some((i) => i.store.name.includes(`${path.sep}excluded${path.sep}`))).toBe(false);
  });
});

describe("presupuestos", () => {
  it("⭐ tiempo: se corta, lo dice y nombra las raíces a medias", async () => {
    let t = 0;
    const clock = () => (t += 1000); // cada consulta avanza 1 s
    const r = await collectCertFiles(
      [{ path: path.join(root, "etc"), origin: "default" }, { path: path.join(root, "opt"), origin: "default" }],
      { timeBudgetMs: 3500, clock }
    );
    expect(r.truncated).toBe("time");
    expect(r.incompleteRoots).toEqual([path.join(root, "etc"), path.join(root, "opt")]);
  });

  it("ficheros: se corta por número y lo dice", async () => {
    const r = await collectCertFiles([{ path: path.join(root, "etc"), origin: "default" }], { maxFiles: 2 });
    expect(r.truncated).toBe("files");
    expect(r.capped).toBe(true);
    expect(r.filesScanned).toBe(2);
    expect(r.incompleteRoots).toEqual([path.join(root, "etc")]);
  });

  it("sin corte, truncated es null", async () => {
    const r = await collectCertFiles([{ path: path.join(root, "etc"), origin: "default" }]);
    expect(r.truncated).toBeNull();
    expect(r.incompleteRoots).toEqual([]);
  });
});

describe("incremental", () => {
  it("⭐ lo que no cambió sale de la caché y se EMITE igual", async () => {
    const cache = memoryCache();
    const rootsEtc = [{ path: path.join(root, "etc"), origin: "default" as const }];
    const first = await collectCertFiles(rootsEtc, { cache });
    expect(first.cacheHits).toBe(0);
    const second = await collectCertFiles(rootsEtc, { cache });
    expect(second.cacheHits).toBe(first.filesScanned);
    expect(second.items.map((i) => i.id).sort()).toEqual(first.items.map((i) => i.id).sort());
    expect(second.keys).toEqual(first.keys);
    expect(second.unreadableFiles.sort()).toEqual(first.unreadableFiles.sort());
    // La caché no guarda material de clave: solo metadatos.
    const keyRow = [...cache.rows.entries()].find(([p]) => p.endsWith("server.key"))![1];
    expect(JSON.stringify(keyRow)).not.toContain("PRIVATE KEY");
    expect(keyRow.record.certs).toEqual([]);
  });

  it("un fichero modificado se relee", async () => {
    const cache = memoryCache();
    const rootsEtc = [{ path: path.join(root, "etc"), origin: "default" as const }];
    await collectCertFiles(rootsEtc, { cache });
    const crt = path.join(root, "etc/nginx/ssl/server.crt");
    const later = new Date(Date.now() + 5000);
    fs.utimesSync(crt, later, later);
    const again = await collectCertFiles(rootsEtc, { cache });
    expect(again.cacheHits).toBe(again.filesScanned - 1);
  });

  it("lo que ya no existe se poda; lo de una raíz a medias se conserva", async () => {
    const cache = memoryCache();
    cache.put(path.join(root, "gone.crt"), 1, 1, { origin: "default", kind: "none", certs: [], keys: [] });
    cache.put(path.join(root, "opt", "later.crt"), 1, 1, { origin: "default", kind: "none", certs: [], keys: [] });
    let t = 0;
    await collectCertFiles(
      [{ path: path.join(root, "etc"), origin: "default" }, { path: path.join(root, "opt"), origin: "default" }],
      { cache, maxFiles: 50, timeBudgetMs: 1e9, clock: () => t }
    );
    expect(cache.rows.has(path.join(root, "gone.crt"))).toBe(false);
    // `opt` se terminó aquí, así que su fantasma también se va:
    expect(cache.rows.has(path.join(root, "opt", "later.crt"))).toBe(false);

    cache.put(path.join(root, "opt", "later.crt"), 1, 1, { origin: "default", kind: "none", certs: [], keys: [] });
    await collectCertFiles(
      [{ path: path.join(root, "etc"), origin: "default" }, { path: path.join(root, "opt"), origin: "default" }],
      { cache, maxFiles: 3 }
    );
    expect(cache.rows.has(path.join(root, "opt", "later.crt"))).toBe(true);
  });
});

describe("permisos", () => {
  const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
  it.skipIf(isRoot || process.platform === "win32")("una clave ilegible se dice; un directorio denegado bajo raíz por defecto va a deniedPaths", async () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-deny-"));
    try {
      fs.writeFileSync(path.join(d, "srv.key"), FIXTURE_KEY);
      fs.chmodSync(path.join(d, "srv.key"), 0o000);
      fs.mkdirSync(path.join(d, "private"));
      fs.writeFileSync(path.join(d, "private", "x.crt"), FIXTURE_CERT);
      fs.chmodSync(path.join(d, "private"), 0o000);
      const r = await collectCertFiles([{ path: d, origin: "default" }]);
      expect(r.keys).toEqual([{ path: path.join(d, "srv.key"), format: "unknown", encrypted: null, readable: false }]);
      expect(r.deniedPaths).toEqual([path.join(d, "private")]);
      expect(r.unreadableDirs).toEqual([]);
      // Bajo una raíz del operador, el mismo directorio es ilegible nombrado.
      const c = await collectCertFiles([{ path: d, origin: "configured" }]);
      expect(c.unreadableDirs).toEqual([path.join(d, "private")]);
    } finally {
      fs.chmodSync(path.join(d, "private"), 0o755);
      fs.rmSync(d, { recursive: true, force: true });
    }
  });
});

describe("defaultFileDiscoveryRoots", () => {
  it("Linux: config y datos de servicios, nunca /home; excluye lo que ya leen los almacenes", () => {
    const { roots, exclude } = defaultFileDiscoveryRoots("linux");
    expect(roots).toContain("/etc");
    expect(roots).toContain("/opt");
    expect(roots.some((r) => r.startsWith("/home") || r === "/root")).toBe(false);
    expect(exclude).toEqual(expect.arrayContaining(["/etc/ssl/certs", "/etc/pki/ca-trust", "/var/lib/docker"]));
  });

  it("Windows: ProgramData y Program Files desde el entorno, con su exclusión de Microsoft", () => {
    const { roots, exclude } = defaultFileDiscoveryRoots("win32", {
      ProgramData: "D:\\PD", ProgramFiles: "D:\\PF", "ProgramFiles(x86)": "D:\\PF86", SystemDrive: "D:"
    });
    expect(roots).toEqual(["D:\\PD", "D:\\PF", "D:\\PF86", "D:\\inetpub"]);
    expect(exclude).toContain("D:\\PD\\Microsoft");
  });

  it("macOS: sin /Users, excluyendo keychains y JVMs (tienen proveedor propio)", () => {
    const { roots, exclude } = defaultFileDiscoveryRoots("darwin");
    expect(roots).toContain("/Library");
    expect(roots.some((r) => r.startsWith("/Users"))).toBe(false);
    expect(exclude).toEqual(expect.arrayContaining(["/Library/Keychains", "/Library/Java"]));
  });

  it("dirPrefix no confunde /opt con /optx", () => {
    expect(dirPrefix("/opt")).toBe("/opt/");
    expect(dirPrefix("/opt/")).toBe("/opt/");
    expect(dirPrefix("C:\\ProgramData")).toBe("C:\\ProgramData\\");
  });
});

describe("matchLooseKeys", () => {
  it("sin hash público → unknown; con hash que no casa → none", () => {
    const k = [{ path: "/a/x.key", format: "pkcs8-encrypted" as const, encrypted: true, readable: true }];
    expect(matchLooseKeys(k, [])[0].certMatch).toBe("unknown");
    const h = [{ path: "/a/y.key", format: "pkcs8" as const, encrypted: false, readable: true, publicKeyHash: "ff".repeat(32) }];
    expect(matchLooseKeys(h, [])[0].certMatch).toBe("none");
  });

  it("no toca hasPrivateKey de un certificado de ALMACÉN", () => {
    const hash = crypto.randomBytes(32).toString("hex");
    const storeItem: any = { id: "s", fingerprint256: "aa", publicKeyHash: hash, hasPrivateKey: false, store: { id: "lm/my", name: "LocalMachine\\My", scope: "machine" }, source: "store" };
    const [m] = matchLooseKeys([{ path: "/x/k.key", format: "pkcs8", encrypted: false, readable: true, publicKeyHash: hash }], [storeItem]);
    expect(m.certMatch).toBe("inventory");
    expect(storeItem.hasPrivateKey).toBe(false);
  });
});
