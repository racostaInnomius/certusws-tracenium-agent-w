// test/domain/file-integrity.test.ts
//
// ADR-0027 F3 — la vigilancia de ficheros en el agente, con un sistema de
// ficheros falso: qué se recorre, qué se hashea, qué se cuenta y cuándo sale
// un mensaje. Cada caso es una manera de mentir que hay que evitar.

import { describe, it, expect, vi } from "vitest";
import { sanitizeFileIntegrityPolicy, appliesTo } from "../../src/domain/file-integrity-policy";
import { scanFileIntegrity, type FsLike } from "../../src/domain/file-integrity-scan";
import { computeFileIntegrityDelta, runFileIntegrityPass, setsFingerprint, type FimDeps } from "../../src/plugins/scp/file-integrity-pipeline";

type Node = { kind: "file"; size: number; mtimeMs: number; content: string } | { kind: "dir" } | { kind: "link" } | { kind: "denied" };

function fakeFs(tree: Record<string, Node>) {
  const sha256 = vi.fn(async (p: string) => {
    const n = tree[p];
    if (!n || n.kind !== "file") throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    return n.content.padEnd(64, "0").slice(0, 64);
  });
  const fs: FsLike = {
    lstat: async (p) => {
      const n = tree[p];
      if (!n) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      if (n.kind === "denied") throw Object.assign(new Error("EACCES"), { code: "EACCES" });
      return {
        isFile: () => n.kind === "file",
        isDirectory: () => n.kind === "dir",
        isSymbolicLink: () => n.kind === "link",
        size: n.kind === "file" ? n.size : 0,
        mtimeMs: n.kind === "file" ? n.mtimeMs : 0,
      };
    },
    readdir: async (dir) => {
      const n = tree[dir];
      if (n?.kind === "denied") throw Object.assign(new Error("EACCES"), { code: "EACCES" });
      const prefix = dir.endsWith("/") ? dir : `${dir}/`;
      return Object.keys(tree)
        .filter((k) => k.startsWith(prefix) && !k.slice(prefix.length).includes("/"))
        .map((k) => k.slice(prefix.length));
    },
    sha256,
  };
  return { fs, sha256 };
}

const file = (content: string, over: Partial<{ size: number; mtimeMs: number }> = {}): Node => ({ kind: "file", size: 100, mtimeMs: 1_700_000_000_000, content, ...over });

const policy = (over: Record<string, unknown> = {}) =>
  sanitizeFileIntegrityPolicy({ enabled: true, sets: [{ id: "etc", platform: "linux", path: "/etc/app", recursive: true }], ...over })!;

describe("sanitizeFileIntegrityPolicy", () => {
  it("descarta el conjunto imposible sin tirar el resto, y aplica los topes", () => {
    const p = sanitizeFileIntegrityPolicy({
      sets: [
        { id: "bueno", path: "/etc/hosts" },
        { id: "malo", path: "/etc/*" },
        { id: "bueno", path: "/etc/otro" }, // id repetido
      ],
      maxFilesPerDevice: 999999,
    })!;
    expect(p.sets.map((s) => s.id)).toEqual(["bueno"]);
    expect(p.enabled).toBe(true);
    expect(p.maxFilesPerDevice).toBe(20_000);
    expect(p.sets[0]).toMatchObject({ platform: "any", purpose: "system", recursive: false, maxDepth: 4 });
    expect(sanitizeFileIntegrityPolicy(null)).toBeNull();
  });

  it("un conjunto se vigila sólo en su plataforma", () => {
    const s = policy().sets[0];
    expect(appliesTo(s, "linux")).toBe(true);
    expect(appliesTo(s, "win32")).toBe(false);
    expect(appliesTo({ ...s, platform: "any" }, "darwin")).toBe(true);
  });
});

describe("scanFileIntegrity", () => {
  const base = { platform: "linux" as NodeJS.Platform, previous: new Map(), fullRehash: true };

  it("⭐ recorre, hashea y no sigue enlaces simbólicos (un enlace puede sacarte del conjunto)", async () => {
    const { fs } = fakeFs({
      "/etc/app": { kind: "dir" },
      "/etc/app/a.conf": file("aa"),
      "/etc/app/sub": { kind: "dir" },
      "/etc/app/sub/b.conf": file("bb"),
      "/etc/app/fuera": { kind: "link" },
    });
    const r = await scanFileIntegrity({ ...base, policy: policy(), fs });
    expect(r.scope).toBe("collected");
    expect(r.files.map((f) => f.path)).toEqual(["/etc/app/a.conf", "/etc/app/sub/b.conf"]);
    expect(r.files[0]).toMatchObject({ setId: "etc", hashed: true, sizeBytes: 100 });
  });

  it("⚠️ para en el tope de ficheros y lo DICE", async () => {
    const tree: Record<string, Node> = { "/etc/app": { kind: "dir" } };
    for (let i = 0; i < 5; i++) tree[`/etc/app/f${i}`] = file(`c${i}`);
    const r = await scanFileIntegrity({ ...base, policy: policy({ maxFilesPerDevice: 3 }), fs: fakeFs(tree).fs });
    expect(r.files).toHaveLength(3);
    expect(r.truncated).toBe(true);
  });

  it("un fichero demasiado grande se cuenta sin hash: es un hecho, no un hueco", async () => {
    const { fs, sha256 } = fakeFs({ "/etc/app": { kind: "dir" }, "/etc/app/big.bin": file("zz", { size: 50 * 1024 * 1024 }) });
    const r = await scanFileIntegrity({ ...base, policy: policy(), fs });
    expect(r.files[0]).toMatchObject({ hashed: false, sha256: null, sizeBytes: 50 * 1024 * 1024 });
    expect(sha256).not.toHaveBeenCalled();
  });

  it("⚠️ sin permiso cuenta como ilegible; una ruta que no existe en ESTE equipo no es un error", async () => {
    const { fs } = fakeFs({ "/etc/app": { kind: "dir" }, "/etc/app/secreto": { kind: "denied" }, "/etc/app/ok": file("ok") });
    const r = await scanFileIntegrity({
      ...base,
      policy: sanitizeFileIntegrityPolicy({ sets: [{ id: "etc", path: "/etc/app", recursive: true }, { id: "otro", path: "/opt/no-existe" }] })!,
      fs,
    });
    expect(r.scope).toBe("collected");
    expect(r.unreadable).toBe(1);
    expect(r.files.map((f) => f.path)).toEqual(["/etc/app/ok"]);
  });

  it("⭐ reutiliza el hash de un fichero con el mismo tamaño y fecha, salvo en el rehasheo diario", async () => {
    const { fs, sha256 } = fakeFs({ "/etc/app": { kind: "dir" }, "/etc/app/a.conf": file("aa") });
    const previous = new Map([["etc|/etc/app/a.conf", { sha256: "x".repeat(64), sizeBytes: 100, mtimeMs: 1_700_000_000_000 }]]);
    const r = await scanFileIntegrity({ ...base, policy: policy(), fs, previous, fullRehash: false });
    expect(r.files[0].sha256).toBe("x".repeat(64));
    expect(sha256).not.toHaveBeenCalled();

    // Una vez al día se rehashea todo: cambiar un fichero conservando fecha y
    // tamaño es posible para quien lo intenta.
    const again = await scanFileIntegrity({ ...base, policy: policy(), fs, previous, fullRehash: true });
    expect(again.files[0].sha256).toBe("aa".padEnd(64, "0"));
    expect(sha256).toHaveBeenCalledTimes(1);
  });

  it("sin política, sin conjuntos para esta plataforma o en una plataforma sin soporte, lo dice", async () => {
    const { fs } = fakeFs({});
    expect((await scanFileIntegrity({ ...base, policy: null, fs })).scope).toBe("not_configured");
    expect((await scanFileIntegrity({ ...base, platform: "win32", policy: policy(), fs })).scope).toBe("not_configured");
    expect((await scanFileIntegrity({ ...base, platform: "aix" as NodeJS.Platform, policy: policy(), fs })).scope).toBe("unsupported");
  });
});

describe("computeFileIntegrityDelta", () => {
  const f = (p: string, sha: string | null, over: Record<string, unknown> = {}) =>
    ({ setId: "etc", path: p, sha256: sha, hashed: sha !== null, sizeBytes: 100, modifiedAtUtc: "2026-09-21T00:00:00.000Z", mtimeMs: 1, ...over }) as any;

  it("añadido, borrado y cambiado; un fichero sin hash se compara por tamaño", () => {
    const d = computeFileIntegrityDelta(
      [f("/a", "11"), f("/c", "33"), f("/big", null, { sizeBytes: 999 })],
      [f("/a", "10"), f("/b", "22"), f("/big", null, { sizeBytes: 998 })]
    );
    expect(d.added.map((x) => x.path)).toEqual(["/c"]);
    expect(d.removed.map((x) => x.path)).toEqual(["/b"]);
    expect(d.changed.map((x) => x.path).sort()).toEqual(["/a", "/big"]);
    // Nada interno del agente viaja: sólo ruta, hash, tamaño y fecha.
    expect(Object.keys(d.added[0]).sort()).toEqual(["hashed", "modifiedAtUtc", "path", "setId", "sha256", "sizeBytes"]);
  });
});

describe("runFileIntegrityPass", () => {
  function deps(tree: Record<string, Node>, over: Partial<FimDeps> = {}) {
    const state = new Map<string, string>();
    let baseline: any[] = [];
    const sent: any[] = [];
    const d: FimDeps = {
      platform: "linux",
      policy: policy(),
      fs: fakeFs(tree).fs,
      now: 1_800_000_000_000,
      getState: (k) => state.get(k) ?? null,
      setState: (k, v) => void state.set(k, v),
      enqueue: (p) => void sent.push(p),
      loadBaseline: () => baseline,
      replaceBaseline: (files) => { baseline = files; },
      schemaVersion: "1.0",
      ...over,
    };
    return { d, sent, state, get baseline() { return baseline; } };
  }
  const TREE = { "/etc/app": { kind: "dir" } as Node, "/etc/app/a.conf": file("aa") };

  it("⭐ la primera pasada manda la FOTO completa, sola en su mensaje", async () => {
    const h = deps(TREE);
    const r = await runFileIntegrityPass(h.d);
    expect(r).toMatchObject({ sent: true, kind: "photo" });
    expect(Object.keys(h.sent[0].namespaces)).toEqual(["fim"]);
    expect(h.sent[0].namespaces.fim).toMatchObject({ scope: "collected", hasChanges: true, setIds: ["etc"], counts: { files: 1, unreadable: 0 } });
    expect(h.sent[0].namespaces.fim.files).toHaveLength(1);
  });

  it("sin cambios no manda nada hasta el latido diario, y entonces sólo los recuentos", async () => {
    const h = deps(TREE);
    await runFileIntegrityPass(h.d);
    expect((await runFileIntegrityPass({ ...h.d, now: h.d.now + 3_600_000 })).sent).toBe(false);
    const hb = await runFileIntegrityPass({ ...h.d, now: h.d.now + 86_400_000 });
    expect(hb).toMatchObject({ sent: true, kind: "heartbeat" });
    expect(h.sent[1].namespaces.fim.files).toBeUndefined();
    expect(h.sent[1].namespaces.fim.delta).toBeUndefined();
  });

  it("⭐ un cambio sale como delta", async () => {
    const tree = { ...TREE };
    const h = deps(tree);
    await runFileIntegrityPass(h.d);
    tree["/etc/app/a.conf"] = file("bb", { mtimeMs: 1_700_000_999_000 });
    const r = await runFileIntegrityPass({ ...h.d, fs: fakeFs(tree).fs, now: h.d.now + 60_000 });
    expect(r.kind).toBe("delta");
    expect(h.sent[1].namespaces.fim.delta.changed.map((x: any) => x.path)).toEqual(["/etc/app/a.conf"]);
  });

  it("⭐ cambiar los conjuntos declarados manda FOTO, no un delta con todos los ficheros «añadidos»", async () => {
    const tree = { ...TREE, "/opt/log": { kind: "dir" } as Node, "/opt/log/audit.log": file("ll") };
    const h = deps(tree);
    await runFileIntegrityPass(h.d);
    const withLogs = sanitizeFileIntegrityPolicy({
      sets: [
        { id: "etc", platform: "linux", path: "/etc/app", recursive: true },
        { id: "logs", platform: "linux", purpose: "audit_logs", path: "/opt/log" },
      ],
    })!;
    expect(setsFingerprint(withLogs, "linux")).not.toBe(setsFingerprint(h.d.policy, "linux"));
    const r = await runFileIntegrityPass({ ...h.d, policy: withLogs, now: h.d.now + 60_000 });
    expect(r.kind).toBe("photo");
    expect(h.sent[1].namespaces.fim.files.map((x: any) => x.path).sort()).toEqual(["/etc/app/a.conf", "/opt/log/audit.log"]);
  });

  it("⚠️ si no se pudo mirar, se dice y la línea base NO se toca", async () => {
    const h = deps(TREE);
    await runFileIntegrityPass(h.d);
    const before = h.baseline;
    const broken: FsLike = { lstat: async () => { throw new Error("EIO"); }, readdir: async () => [], sha256: async () => "" };
    const r = await runFileIntegrityPass({ ...h.d, fs: broken, now: h.d.now + 60_000 });
    expect(r).toMatchObject({ sent: true, scope: "unavailable" });
    expect(h.sent[1].namespaces.fim).toMatchObject({ scope: "unavailable", hasChanges: false });
    expect(h.baseline).toBe(before);
  });
});
