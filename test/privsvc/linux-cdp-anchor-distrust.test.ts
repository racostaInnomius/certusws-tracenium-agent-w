// test/privsvc/linux-cdp-anchor-distrust.test.ts
//
// `cdp.anchor.distrust` en Linux (ADR-0011, decision 10).
//
// Hasta ahora el router de Linux no tenía la ruta: el job llegaba y
// moría en «Unsupported method». Aquí se prueba el handler contra un
// sistema de ficheros y un exec FALSOS que imitan lo que hacen
// `update-ca-trust extract` y `update-ca-certificates --fresh` —
// reconstruir lo extraído a partir de las fuentes—, porque lo que importa
// no es que se escriba un fichero sino que, después, el sistema deje de
// confiar. Los certificados sí son reales (openssl), para que las huellas
// se calculen de verdad.

import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from "vitest";
import { execFileSync } from "child_process";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";

vi.mock("../../privsvc/linux/src/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }
}));

import {
  distrustAnchor,
  handleCdpAnchorDistrust,
  detectMechanism,
  DISTRUSTED_SUFFIX,
  type DistrustDeps
} from "../../privsvc/linux/src/cdp-anchor-distrust";
import { OPENSSL } from "./openssl-compat";

let tmp: string;
let TARGET: string;
let OTHER: string;
let AGENT_CA: string;

const sha1 = (pem: string) =>
  crypto.createHash("sha1").update(new crypto.X509Certificate(pem).raw).digest("hex").toUpperCase();
const sha256 = (pem: string) =>
  crypto.createHash("sha256").update(new crypto.X509Certificate(pem).raw).digest("hex").toUpperCase();

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "linux-distrust-"));
  const mk = (cn: string) => {
    execFileSync(OPENSSL, ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
      "-keyout", path.join(tmp, `${cn}.key`), "-out", path.join(tmp, `${cn}.pem`), "-subj", `/CN=${cn}`, "-days", "30"],
      { stdio: "pipe" });
    return fs.readFileSync(path.join(tmp, `${cn}.pem`), "utf8").trim();
  };
  TARGET = mk("rogue-inspection-ca");
  OTHER = mk("good-root");
  AGENT_CA = mk("tracenium-agent-ca");
});

afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

// ── Sistema falso ────────────────────────────────────────────────────

type Fake = DistrustDeps & {
  files: Map<string, string>;
  dirs: Set<string>;
  calls: string[];
  writes: string[];
};

function fakeSystem(opts: {
  files: Record<string, string>;
  dirs?: string[];
  bins?: string[];
  /** Lo que hace el comando de regeneración sobre el FS falso. */
  rebuild?: (f: Fake) => void;
  execFails?: boolean;
  own?: string[];
}): Fake {
  const files = new Map(Object.entries(opts.files));
  const dirs = new Set(opts.dirs ?? []);
  const bins = new Set(opts.bins ?? []);
  const f: Fake = {
    files,
    dirs,
    calls: [],
    writes: [],
    exists: (p) =>
      files.has(p) || bins.has(p) || dirs.has(p) || [...files.keys()].some((k) => k.startsWith(p + "/")),
    readFile: (p) => {
      const v = files.get(p);
      if (v === undefined) throw Object.assign(new Error(`ENOENT ${p}`), { code: "ENOENT" });
      return v;
    },
    readDir: (p) => {
      const out = new Map<string, boolean>();
      for (const k of [...files.keys(), ...dirs]) {
        if (!k.startsWith(p + "/")) continue;
        const rest = k.slice(p.length + 1);
        const [head, ...tail] = rest.split("/");
        out.set(head, tail.length > 0 || (dirs.has(k) && tail.length === 0 && !files.has(k)));
      }
      return [...out].map(([name, dir]) => ({ name, dir }));
    },
    writeFile: (p, data) => {
      files.set(p, data);
      f.writes.push(p);
    },
    rename: (a, b) => {
      const v = files.get(a);
      if (v === undefined) throw new Error(`ENOENT ${a}`);
      files.delete(a);
      files.set(b, v);
      f.writes.push(`${a} -> ${b}`);
    },
    exec: async (bin, args) => {
      f.calls.push([bin, ...args].join(" "));
      if (opts.execFails) throw Object.assign(new Error("exit 1"), { stderr: "p11-kit: boom\n" });
      opts.rebuild?.(f);
      return { stdout: "", stderr: "" };
    },
    ownAnchorFiles: () => opts.own ?? []
  };
  return f;
}

// ── RHEL: p11-kit ────────────────────────────────────────────────────

const RHEL_BUNDLE = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem";
const RHEL_BLOCK = "/etc/pki/ca-trust/source/blocklist";
const RHEL_PKG_ANCHORS = "/usr/share/pki/ca-trust-source/anchors";

/** `update-ca-trust extract`: anclas del paquete + locales, menos lo bloqueado. */
function rhelRebuild(f: Fake) {
  const blocked = new Set<string>();
  const anchors: string[] = [];
  for (const [p, v] of f.files) {
    if (p.startsWith(RHEL_BLOCK + "/") || p.startsWith("/etc/pki/ca-trust/source/blacklist/")) blocked.add(sha1(v));
    if (p.startsWith(RHEL_PKG_ANCHORS + "/") || p.startsWith("/etc/pki/ca-trust/source/anchors/")) anchors.push(v);
  }
  f.files.set(RHEL_BUNDLE, anchors.filter((a) => !blocked.has(sha1(a))).join("\n"));
}

function rhel(extra: Partial<Parameters<typeof fakeSystem>[0]> = {}) {
  const f = fakeSystem({
    files: {
      [`${RHEL_PKG_ANCHORS}/good.pem`]: OTHER,
      "/etc/pki/ca-trust/source/anchors/rogue.pem": TARGET
    },
    dirs: ["/etc/pki/ca-trust/source", RHEL_BLOCK],
    bins: ["/usr/bin/update-ca-trust"],
    rebuild: rhelRebuild,
    ...extra
  });
  rhelRebuild(f);
  return f;
}

describe("Linux distrust — RHEL/Fedora (p11-kit)", () => {
  it("escribe el PEM LOCAL en la lista de bloqueo, regenera y verifica", async () => {
    const f = rhel();
    const out = await distrustAnchor(sha1(TARGET), f);

    expect(out).toMatchObject({ ok: true, mechanism: "p11-kit-blocklist", family: "rhel", alreadyDistrusted: false });
    const target = `${RHEL_BLOCK}/tracenium-distrust-${sha256(TARGET).toLowerCase()}.pem`;
    expect(f.files.get(target)?.trim()).toBe(TARGET);
    // argv, sin shell.
    expect(f.calls).toEqual(["/usr/bin/update-ca-trust extract"]);
    expect(f.files.get(RHEL_BUNDLE)).not.toContain(TARGET);
    expect(f.files.get(RHEL_BUNDLE)).toContain(OTHER);
  });

  it("⭐ acepta el SHA-256 con dos puntos que manda la UI (`fingerprint256`)", async () => {
    // La UI de CDP identifica las anclas por fingerprint256 y el backend
    // lo reenvía tal cual; con solo SHA-1 el job sería inservible aquí.
    const f = rhel();
    const colons = sha256(TARGET).match(/../g)!.join(":");
    const out = await distrustAnchor(colons, f);
    expect(out).toMatchObject({ ok: true, sha1: sha1(TARGET), sha256: sha256(TARGET) });
    expect(f.files.get(RHEL_BUNDLE)).not.toContain(TARGET);

    // Y la repetición por la otra huella también es idempotente.
    expect(await distrustAnchor(sha1(TARGET), f)).toMatchObject({ ok: true, alreadyDistrusted: true });
  });

  it("idempotente: la segunda vez es éxito `alreadyDistrusted`, sin reescribir ni regenerar", async () => {
    const f = rhel();
    await distrustAnchor(sha1(TARGET), f);
    const writes = f.writes.length;
    const calls = f.calls.length;

    const again = await distrustAnchor(sha1(TARGET), f);
    expect(again).toMatchObject({ ok: true, alreadyDistrusted: true });
    expect(f.writes.length).toBe(writes);
    expect(f.calls.length).toBe(calls);
  });

  it("usa `blacklist/` en versiones viejas que no tienen `blocklist/`", () => {
    const f = rhel({ dirs: ["/etc/pki/ca-trust/source", "/etc/pki/ca-trust/source/blacklist"] });
    expect(detectMechanism(f)).toMatchObject({ blocklistDir: "/etc/pki/ca-trust/source/blacklist" });
  });

  it("⚠️ si tras regenerar la huella SIGUE en lo extraído, falla — no hay falso verde", async () => {
    const f = rhel({ rebuild: () => {} });
    const out = await distrustAnchor(sha1(TARGET), f);
    expect(out).toMatchObject({ ok: false, code: "distrust_not_effective" });
  });

  it("si la regeneración falla, lo dice y cuenta qué quedó cambiado", async () => {
    const f = rhel({ execFails: true });
    const out = await distrustAnchor(sha1(TARGET), f);
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.code).toBe("distrust_failed");
      expect(out.message).toContain("p11-kit: boom");
      expect(out.message).toContain(RHEL_BLOCK);
    }
  });

  it("⚠️ un ancla ausente se niega y no toca nada", async () => {
    const f = rhel();
    const out = await distrustAnchor("AB".repeat(20), f);
    expect(out).toMatchObject({ ok: false, code: "anchor_not_present" });
    expect(f.writes).toEqual([]);
    expect(f.calls).toEqual([]);
  });

  it("⚠️ jamás la cadena propia del agente", async () => {
    const f = rhel({
      files: {
        [`${RHEL_PKG_ANCHORS}/good.pem`]: OTHER,
        [`${RHEL_PKG_ANCHORS}/agent.pem`]: AGENT_CA,
        "/etc/tracenium/certs/ca-bundle.crt.pem": AGENT_CA
      },
      own: ["/etc/tracenium/certs/ca-bundle.crt.pem"]
    });
    const out = await distrustAnchor(sha1(AGENT_CA), f);
    expect(out).toMatchObject({ ok: false, code: "anchor_is_own_chain" });
    expect(f.writes).toEqual([]);
    expect(f.calls).toEqual([]);
  });

  it.each([
    ["vacía", ""],
    ["corta", "ABCDEF"],
    ["intento de ruta", "../../../../etc/shadow"],
    ["de longitud rara (48 hex)", "AB".repeat(24)]
  ])("rechaza una huella %s sin tocar nada", async (_n, value) => {
    const f = rhel();
    const out = await distrustAnchor(value, f);
    expect(out).toMatchObject({ ok: false, code: "invalid_params" });
    expect(f.writes).toEqual([]);
    expect(f.calls).toEqual([]);
  });
});

// ── SUSE ─────────────────────────────────────────────────────────────

describe("Linux distrust — SUSE (p11-kit, /etc/pki/trust)", () => {
  it("lista de bloqueo de SUSE + update-ca-certificates", async () => {
    const BUNDLE = "/var/lib/ca-certificates/ca-bundle.pem";
    const rebuild = (f: Fake) => {
      const blocked = [...f.files].filter(([p]) => p.startsWith("/etc/pki/trust/blocklist/")).map(([, v]) => sha1(v));
      const anchors = [...f.files].filter(([p]) => p.startsWith("/usr/share/pki/trust/anchors/")).map(([, v]) => v);
      f.files.set(BUNDLE, anchors.filter((a) => !blocked.includes(sha1(a))).join("\n"));
    };
    const f = fakeSystem({
      files: { "/usr/share/pki/trust/anchors/rogue.pem": TARGET, "/usr/share/pki/trust/anchors/good.pem": OTHER },
      dirs: ["/etc/pki/trust", "/etc/pki/trust/blocklist"],
      bins: ["/usr/sbin/update-ca-certificates"],
      rebuild
    });
    rebuild(f);

    const out = await distrustAnchor(sha1(TARGET), f);
    expect(out).toMatchObject({ ok: true, family: "suse", mechanism: "p11-kit-blocklist" });
    expect(f.calls).toEqual(["/usr/sbin/update-ca-certificates"]);
    expect(f.files.get(BUNDLE)).not.toContain(TARGET);
  });
});

// ── Debian/Ubuntu ────────────────────────────────────────────────────

const DEB_CONF = "/etc/ca-certificates.conf";
const DEB_BUNDLE = "/etc/ssl/certs/ca-certificates.crt";

/** `update-ca-certificates --fresh`: líneas activas del .conf + todo *.crt local. */
function debianRebuild(f: Fake) {
  for (const k of [...f.files.keys()]) if (k.startsWith("/etc/ssl/certs/")) f.files.delete(k);
  const selected: [string, string][] = [];
  for (const raw of (f.files.get(DEB_CONF) ?? "").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;
    const v = f.files.get(`/usr/share/ca-certificates/${line}`);
    if (v) selected.push([path.basename(line), v]);
  }
  for (const [p, v] of f.files) {
    if (p.startsWith("/usr/local/share/ca-certificates/") && p.endsWith(".crt")) selected.push([path.basename(p), v]);
  }
  for (const [name, v] of selected) f.files.set(`/etc/ssl/certs/${name.replace(/\.crt$/, ".pem")}`, v);
  f.files.set(DEB_BUNDLE, selected.map(([, v]) => v).join("\n"));
}

function debian(files: Record<string, string>, extra: Partial<Parameters<typeof fakeSystem>[0]> = {}) {
  const f = fakeSystem({ files, bins: ["/usr/sbin/update-ca-certificates"], rebuild: debianRebuild, ...extra });
  debianRebuild(f);
  return f;
}

describe("Linux distrust — Debian/Ubuntu (ca-certificates)", () => {
  it("antepone `!` a la línea del .conf, conserva el resto y regenera con --fresh", async () => {
    const conf = "# comentario\nmozilla/Good_Root.crt\nmozilla/Rogue.crt\n";
    const f = debian({
      [DEB_CONF]: conf,
      "/usr/share/ca-certificates/mozilla/Good_Root.crt": OTHER,
      "/usr/share/ca-certificates/mozilla/Rogue.crt": TARGET
    });

    const out = await distrustAnchor(sha1(TARGET), f);
    expect(out).toMatchObject({ ok: true, family: "debian", mechanism: "ca-certificates.conf" });
    expect(f.files.get(DEB_CONF)).toBe("# comentario\nmozilla/Good_Root.crt\n!mozilla/Rogue.crt\n");
    expect(f.calls).toEqual(["/usr/sbin/update-ca-certificates --fresh"]);
    // Ni en el bundle ni en el directorio de hashes que OpenSSL también lee.
    for (const [p, v] of f.files) if (p.startsWith("/etc/ssl/certs/")) expect(v).not.toContain(TARGET);
    // El certificado sigue en disco: se desconfía, no se borra.
    expect(f.files.get("/usr/share/ca-certificates/mozilla/Rogue.crt")).toBe(TARGET);
  });

  it("una CA plantada en /usr/local/share/ca-certificates se renombra (reversible), no se borra", async () => {
    const f = debian({
      [DEB_CONF]: "mozilla/Good_Root.crt\n",
      "/usr/share/ca-certificates/mozilla/Good_Root.crt": OTHER,
      "/usr/local/share/ca-certificates/corp/proxy.crt": TARGET
    });

    const out = await distrustAnchor(sha1(TARGET), f);
    expect(out.ok).toBe(true);
    expect(f.files.has("/usr/local/share/ca-certificates/corp/proxy.crt")).toBe(false);
    expect(f.files.get(`/usr/local/share/ca-certificates/corp/proxy.crt${DISTRUSTED_SUFFIX}`)).toBe(TARGET);
    expect(f.files.get(DEB_BUNDLE)).not.toContain(TARGET);

    // Y repetirlo es éxito idempotente.
    const again = await distrustAnchor(sha1(TARGET), f);
    expect(again).toMatchObject({ ok: true, alreadyDistrusted: true });
  });

  it("confiada pero sin fuente conocida: se niega en vez de borrar del bundle", async () => {
    const f = debian({ [DEB_CONF]: "mozilla/Good_Root.crt\n", "/usr/share/ca-certificates/mozilla/Good_Root.crt": OTHER });
    // Pegada a mano en el bundle, fuera de update-ca-certificates.
    f.files.set(DEB_BUNDLE, `${f.files.get(DEB_BUNDLE)}\n${TARGET}`);

    const out = await distrustAnchor(sha1(TARGET), f);
    expect(out).toMatchObject({ ok: false, code: "anchor_source_unknown" });
    expect(f.writes).toEqual([]);
    expect(f.calls).toEqual([]);
  });

  it("una línea del .conf que escapa de /usr/share/ca-certificates se ignora", async () => {
    const f = debian({
      [DEB_CONF]: "../../../etc/tracenium/certs/ca-bundle.crt.pem\n",
      "/etc/tracenium/certs/ca-bundle.crt.pem": TARGET
    });
    f.files.set(DEB_BUNDLE, TARGET);
    const out = await distrustAnchor(sha1(TARGET), f);
    expect(out).toMatchObject({ ok: false, code: "anchor_source_unknown" });
  });
});

// ── Sin mecanismo ────────────────────────────────────────────────────

describe("Linux distrust — distro no soportada", () => {
  it("devuelve `trust_store_unsupported`, nunca éxito, y no ejecuta nada", async () => {
    const f = fakeSystem({ files: { "/etc/ssl/cert.pem": TARGET } });
    const out = await distrustAnchor(sha1(TARGET), f);
    expect(out).toMatchObject({ ok: false, code: "trust_store_unsupported" });
    expect(f.calls).toEqual([]);
  });
});

// ── Contrato IPC ─────────────────────────────────────────────────────

describe("handleCdpAnchorDistrust — mismo contrato que Windows/macOS", () => {
  it("lee `sha1` o `thumbprint` y responde { distrusted, sha1, subject }", async () => {
    const f = rhel();
    const res = await handleCdpAnchorDistrust(
      { v: 1, id: "x1", method: "cdp.anchor.distrust", params: { thumbprint: sha1(TARGET).toLowerCase() } },
      f
    );
    expect(res.ok).toBe(true);
    expect(res.result).toMatchObject({ distrusted: true, sha1: sha1(TARGET), thumbprint: sha1(TARGET) });
    expect(res.result.subject).toContain("rogue-inspection-ca");
  });

  it("un fallo viaja como error con código", async () => {
    const res = await handleCdpAnchorDistrust({ v: 1, id: "x2", method: "cdp.anchor.distrust", params: {} }, rhel());
    expect(res).toMatchObject({ ok: false, error: { code: "invalid_params" } });
  });
});

describe("router de Linux", () => {
  let uidSpy: any;
  afterEach(() => {
    uidSpy?.mockRestore();
    vi.doUnmock("../../privsvc/linux/src/cdp-anchor-distrust");
    vi.resetModules();
  });

  it("⭐ `cdp.anchor.distrust` está enrutado (antes: Unsupported method)", async () => {
    vi.resetModules();
    uidSpy = vi.spyOn(process, "getuid" as any).mockReturnValue(0 as any);
    const handler = vi.fn(async (req: any) => ({ v: 1, id: req.id, ok: true, result: { distrusted: true }, error: null }));
    vi.doMock("../../privsvc/linux/src/cdp-anchor-distrust", () => ({ handleCdpAnchorDistrust: handler }));
    vi.doMock("../../privsvc/linux/src/grpc-bridge", () => ({}));
    const { routeRequest } = await import("../../privsvc/linux/src/router");

    const res = await routeRequest({ v: 1, id: "r1", method: "cdp.anchor.distrust", params: { sha1: "AB".repeat(20) } }, vi.fn());
    expect(handler).toHaveBeenCalledTimes(1);
    expect(res.ok).toBe(true);
  });
});
