// test/plugins/cdp-ssh-user-keys.test.ts
//
// Ola 1.4 — claves SSH por usuario. Lo que se defiende:
//   · un `authorized_keys` es una CONCESION y se distingue de un `.pub`;
//   · las opciones viajan tal cual, incluidas las que llevan comas
//     dentro de comillas (`command="a,b"`), que es donde un split
//     ingenuo parte la linea por la mitad;
//   · de una clave PRIVADA solo sale presencia, y ni un byte del secreto.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";
import {
  collectSshUserKeys,
  describeOpensshPrivateKey,
  parseAuthorizedKeyLine,
  splitAuthorizedOptions
} from "../../src/plugins/cdp/providers/ssh-user-keys";
import { parseSshPublicKey } from "../../src/plugins/cdp/providers/ssh-host-keys";

// Claves reales, generadas una vez: hace falta un blob SSH valido para
// que la huella signifique algo.
let dir: string;
let ed25519Pub: string;
let rsaPub: string;

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-sshuser-"));
  const keygen = (name: string, args: string[]) =>
    execFileSync("ssh-keygen", ["-q", "-f", path.join(dir, name), "-N", "", ...args], { stdio: "pipe" });
  keygen("id_ed25519", ["-t", "ed25519", "-C", "javier@laptop"]);
  keygen("id_rsa", ["-t", "rsa", "-b", "2048", "-C", "build@ci"]);
  ed25519Pub = fs.readFileSync(path.join(dir, "id_ed25519.pub"), "utf8").trim();
  rsaPub = fs.readFileSync(path.join(dir, "id_rsa.pub"), "utf8").trim();
});

afterAll(() => {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    /* tmp */
  }
});

describe("splitAuthorizedOptions", () => {
  it("una linea normal no tiene opciones", () => {
    expect(splitAuthorizedOptions("ssh-ed25519 AAAA javier@laptop")).toEqual({
      options: [],
      rest: "ssh-ed25519 AAAA javier@laptop"
    });
  });

  it("⭐ una coma DENTRO de comillas no separa opciones", () => {
    const out = splitAuthorizedOptions('command="/bin/backup a,b c",no-pty,from="10.0.0.0/8,192.168.1.1" ssh-rsa AAAA x');
    expect(out.options).toEqual(['command="/bin/backup a,b c"', "no-pty", 'from="10.0.0.0/8,192.168.1.1"']);
    expect(out.rest).toBe("ssh-rsa AAAA x");
  });

  it("una comilla escapada no cierra la cadena", () => {
    const out = splitAuthorizedOptions('command="echo \\"hola\\", ya",no-agent-forwarding ssh-ed25519 AAAA');
    expect(out.options).toEqual(['command="echo \\"hola\\", ya"', "no-agent-forwarding"]);
  });

  it("una linea con solo opciones no da clave", () => {
    expect(splitAuthorizedOptions("no-pty,restrict").rest).toBe("");
  });
});

describe("parseAuthorizedKeyLine", () => {
  it("⭐ tipo, tamaño, huella, comentario y restricciones", () => {
    const k = parseAuthorizedKeyLine(`no-pty,from="10.0.0.0/8" ${rsaPub}`, "deploy", "/home/deploy/.ssh/authorized_keys")!;
    expect(k.kind).toBe("authorized");
    expect(k.user).toBe("deploy");
    expect(k.keyType).toBe("ssh-rsa");
    expect(k.algorithm).toBe("RSA");
    expect(k.bits).toBe(2048);
    expect(k.comment).toBe("build@ci");
    expect(k.options).toEqual(["no-pty", 'from="10.0.0.0/8"']);
    expect(k.fingerprintSha256).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  });

  it("la huella es la de `ssh-keygen -lf`", () => {
    const k = parseAuthorizedKeyLine(ed25519Pub, "javier", "/x")!;
    const out = execFileSync("ssh-keygen", ["-lf", path.join(dir, "id_ed25519.pub")], { encoding: "utf8" });
    expect(out).toContain(k.fingerprintSha256);
  });

  it("comentarios, lineas vacias y basura no son concesiones", () => {
    expect(parseAuthorizedKeyLine("# una nota", "u", "/x")).toBeNull();
    expect(parseAuthorizedKeyLine("   ", "u", "/x")).toBeNull();
    expect(parseAuthorizedKeyLine("ssh-ed25519 no-es-base64-valida", "u", "/x")).toBeNull();
    expect(parseAuthorizedKeyLine("no-pty,restrict", "u", "/x")).toBeNull();
  });

  it("⭐ una clave FIDO SI cuenta en authorized_keys (aunque no sea de host)", () => {
    const line = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIB3GVQ0nQ8Pk5w0aQ0u8p9Dh4mQzQ2cE1sSx0xQx0xQxAAAABHNzaDo= yubikey";
    const k = parseAuthorizedKeyLine(line, "u", "/x");
    expect(k?.keyType).toBe("sk-ssh-ed25519@openssh.com");
    expect(k?.algorithm).toBe("Ed25519");
    // Y sigue SIN contar como clave de host: el colector de sshd la tira.
    expect(parseSshPublicKey(line.split(" ").slice(0, 2).join(" "))).toBeNull();
  });
});

describe("describeOpensshPrivateKey", () => {
  it("⭐ dice el tipo y si esta cifrada leyendo SOLO la cabecera publica", () => {
    const text = fs.readFileSync(path.join(dir, "id_ed25519"), "utf8");
    const out = describeOpensshPrivateKey(text)!;
    expect(out.encrypted).toBe(false);
    const parsed = parseSshPublicKey(out.publicLine!, "", { allowSk: true })!;
    expect(parsed.keyType).toBe("ssh-ed25519");
    // La huella de la cabecera es la MISMA que la del `.pub`: es la misma
    // clave publica, que es lo unico que se ha leido.
    expect(parsed.fingerprintSha256).toBe(parseSshPublicKey(ed25519Pub)!.fingerprintSha256);
  });

  it("una clave con contraseña se reporta como cifrada, sin abrirla", () => {
    execFileSync("ssh-keygen", ["-q", "-f", path.join(dir, "locked"), "-t", "ed25519", "-N", "secreto"], { stdio: "pipe" });
    const out = describeOpensshPrivateKey(fs.readFileSync(path.join(dir, "locked"), "utf8"))!;
    expect(out.encrypted).toBe(true);
  });

  it("lo que no es openssh-key-v1 devuelve null", () => {
    expect(describeOpensshPrivateKey("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----")).toBeNull();
    expect(describeOpensshPrivateKey("cualquier cosa")).toBeNull();
  });
});

describe("collectSshUserKeys", () => {
  let home: string;
  let sysFile: string;

  beforeAll(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-home-"));
    const ssh = path.join(home, ".ssh");
    fs.mkdirSync(ssh);
    fs.writeFileSync(path.join(ssh, "authorized_keys"), `# claves del equipo\nno-pty ${rsaPub}\n${ed25519Pub}\n`);
    fs.writeFileSync(path.join(ssh, "authorized_keys2"), `${rsaPub}\n`);
    fs.copyFileSync(path.join(dir, "id_ed25519"), path.join(ssh, "id_ed25519"));
    fs.copyFileSync(path.join(dir, "id_ed25519.pub"), path.join(ssh, "id_ed25519.pub"));
    fs.writeFileSync(path.join(ssh, "known_hosts"), "github.com ssh-ed25519 AAAA\n");
    fs.writeFileSync(path.join(ssh, "config"), "Host *\n  User javier\n");
    sysFile = path.join(home, "etc-authorized_keys");
    fs.writeFileSync(sysFile, `${ed25519Pub}\n`);
  });

  it("⭐ separa lo que CONCEDE acceso de lo que el usuario tiene", async () => {
    const r = await collectSshUserKeys({ users: [{ user: "javier", home }], systemFiles: [] });
    const authorized = r.keys.filter((k) => k.kind === "authorized");
    const pub = r.keys.filter((k) => k.kind === "public");
    // 2 en authorized_keys + 1 en authorized_keys2
    expect(authorized).toHaveLength(3);
    expect(pub).toHaveLength(1);
    expect(authorized.every((k) => k.user === "javier")).toBe(true);
    expect(authorized.find((k) => k.keyType === "ssh-rsa")!.options).toEqual(["no-pty"]);
    expect(r.users).toBe(1);
    expect(r.truncated).toBe(false);
  });

  it("⭐ de la clave privada solo sale presencia: ruta, cifrado, tipo y el .pub hermano", async () => {
    const r = await collectSshUserKeys({ users: [{ user: "javier", home }], systemFiles: [] });
    expect(r.privateKeys).toHaveLength(1);
    const k = r.privateKeys[0];
    expect(k.path.endsWith("id_ed25519")).toBe(true);
    expect(k.format).toBe("openssh");
    expect(k.encrypted).toBe(false);
    expect(k.keyType).toBe("ssh-ed25519");
    expect(k.publicHalfPath!.endsWith("id_ed25519.pub")).toBe(true);
    // Y NADA que se parezca a material de clave.
    const dump = JSON.stringify(r);
    expect(dump).not.toContain("PRIVATE KEY");
    expect(dump).not.toContain("BEGIN");
  });

  it("known_hosts y config no son claves", async () => {
    const r = await collectSshUserKeys({ users: [{ user: "javier", home }], systemFiles: [] });
    expect(r.keys.some((k) => k.path.endsWith("known_hosts"))).toBe(false);
    expect(r.privateKeys.some((k) => k.path.endsWith("config"))).toBe(false);
  });

  it("un authorized_keys de sistema se atribuye al fichero, no a una persona", async () => {
    const r = await collectSshUserKeys({ users: [], systemFiles: [sysFile], platform: "linux" });
    expect(r.keys).toHaveLength(1);
    expect(r.keys[0].user).toBe("(system)");
    expect(r.keys[0].kind).toBe("authorized");
  });

  it("un home sin .ssh no es un fallo", async () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-empty-"));
    const r = await collectSshUserKeys({ users: [{ user: "nadie", home: empty }], systemFiles: [] });
    expect(r.keys).toEqual([]);
    expect(r.users).toBe(0);
    expect(r.unreadable).toBe(0);
  });

  it("⭐ un equipo sin nada manda el bloque vacio, que es una afirmacion", async () => {
    const r = await collectSshUserKeys({ users: [], systemFiles: [] });
    expect(r).toMatchObject({ users: 0, keys: [], privateKeys: [], unreadable: 0, truncated: false });
  });
});
