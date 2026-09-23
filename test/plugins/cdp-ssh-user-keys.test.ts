// test/plugins/cdp-ssh-user-keys.test.ts
//
// Ola 1.4 — claves SSH por usuario. Lo que se defiende:
//   · un `authorized_keys` es una CONCESION y se distingue de un `.pub`;
//   · las opciones viajan tal cual, incluidas las que llevan comas
//     dentro de comillas (`command="a,b"`), que es donde un split
//     ingenuo parte la linea por la mitad;
//   · ⭐ por DEFECTO no se abre ningun fichero de clave privada.
//
// ⚠️ ESTE FICHERO NO ESCRIBE CLAVES PRIVADAS EN DISCO, ni siquiera de
// usar y tirar. La primera version si lo hacia (ssh-keygen -t ed25519 en
// un temporal) y ejecutarla disparo una deteccion **High** de CrowdStrike
// en la Mac de desarrollo: `id_ed25519` en un directorio `.ssh` es el
// patron que los EDR vigilan, y nada de lo que se prueba aqui lo
// necesita. Las claves PUBLICAS se generan de verdad (hacen falta blobs
// validos para que la huella signifique algo); la presencia de una
// privada se prueba con un fichero VACIO con ese nombre, que es
// exactamente lo que el modo por defecto mira.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";
import {
  collectSshUserKeys,
  describeOpensshPrivateKey,
  isPrivateKeyName,
  localUsers,
  parseAuthorizedKeyLine,
  splitAuthorizedOptions
} from "../../src/plugins/cdp/providers/ssh-user-keys";
import { parseSshPublicKey } from "../../src/plugins/cdp/providers/ssh-host-keys";

let dir: string;
let ed25519Pub: string;
let rsaPub: string;
let ed25519Fingerprint: string;

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-sshuser-"));
  // Se generan pares reales para quedarse SOLO con la mitad publica: la
  // privada se borra en el acto y nunca vive en un `.ssh`.
  const gen = (name: string, args: string[]) => {
    const keyPath = path.join(dir, `gen-${name}`);
    execFileSync("ssh-keygen", ["-q", "-f", keyPath, "-N", "", ...args], { stdio: "pipe" });
    const pub = fs.readFileSync(`${keyPath}.pub`, "utf8").trim();
    const fp = execFileSync("ssh-keygen", ["-lf", `${keyPath}.pub`], { encoding: "utf8" });
    fs.rmSync(keyPath, { force: true });
    fs.rmSync(`${keyPath}.pub`, { force: true });
    return { pub, fingerprint: (/SHA256:[A-Za-z0-9+/]+/.exec(fp) ?? [""])[0] };
  };
  const ed = gen("a", ["-t", "ed25519", "-C", "javier@laptop"]);
  ed25519Pub = ed.pub;
  ed25519Fingerprint = ed.fingerprint;
  rsaPub = gen("b", ["-t", "rsa", "-b", "2048", "-C", "build@ci"]).pub;
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
  });

  it("la huella es la de `ssh-keygen -lf`", () => {
    const k = parseAuthorizedKeyLine(ed25519Pub, "javier", "/x")!;
    expect(k.fingerprintSha256).toBe(ed25519Fingerprint);
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

describe("localUsers", () => {
  // ⚠️ El disco se simula, no se mira el de esta maquina.
  //
  // La primera version de estas pruebas leia el `/Users` REAL y comparaba
  // contra el, asi que afirmaba algo del Mac de quien la corria en vez de
  // algo del codigo: en el runner de CI (Linux) `/Users` no existe y el
  // test moria con ENOENT antes de comprobar nada. Y al reves, en un Mac
  // habria pasado igual aunque la rama de darwin estuviera vacia, porque
  // `/etc/passwd` tambien trae homes.
  //
  // Con el disco puesto a mano las dos direcciones se prueban de verdad, y
  // se prueban igual en cualquier sistema operativo.
  function conDisco<T>(
    dirs: Record<string, string[]>,
    ficheros: Record<string, string>,
    fn: () => T
  ): T {
    const realDir = fs.readdirSync;
    const realRead = fs.readFileSync;
    (fs as any).readdirSync = (p: any, ...rest: any[]) => {
      const key = String(p);
      if (key in dirs) return dirs[key] as any;
      if (key === "/Users" || key.startsWith("/Users/")) {
        const e: any = new Error(`ENOENT: no such file or directory, scandir '${key}'`);
        e.code = "ENOENT";
        throw e;
      }
      return (realDir as any)(p, ...rest);
    };
    (fs as any).readFileSync = (p: any, ...rest: any[]) => {
      const key = String(p);
      if (key in ficheros) return ficheros[key] as any;
      return (realRead as any)(p, ...rest);
    };
    try {
      return fn();
    } finally {
      (fs as any).readdirSync = realDir;
      (fs as any).readFileSync = realRead;
    }
  }

  const PASSWD_MACOS =
    "root:*:0:0:System Administrator:/var/root:/bin/sh\n" +
    "daemon:*:1:1:System Services:/var/root:/usr/bin/false\n" +
    "nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false\n";

  it("⭐ en macOS los homes de persona salen de /Users, que /etc/passwd no trae", () => {
    // Es el fallo que motivo la rama: en macOS las cuentas de PERSONA viven
    // en OpenDirectory. `/etc/passwd` existe y se lee sin error, asi que el
    // `catch` nunca salta — simplemente no habria ni un home real que mirar.
    const r = conDisco(
      { "/Users": ["javier", "invitado", ".localized", "Shared", "Guest"] },
      { "/etc/passwd": PASSWD_MACOS },
      () => localUsers("darwin")
    );
    const homes = r.map((u) => u.home);

    expect(homes).toContain("/Users/javier");
    expect(homes).toContain("/Users/invitado");
    // Y lo del passwd sigue ahi: es «ademas de», no «en vez de».
    expect(homes).toContain("/var/root");
  });

  it("se saltan los ocultos, Shared y Guest", () => {
    const homes = conDisco(
      { "/Users": ["javier", ".localized", ".DS_Store", "Shared", "Guest"] },
      { "/etc/passwd": PASSWD_MACOS },
      () => localUsers("darwin")
    ).map((u) => u.home);

    expect(homes).toContain("/Users/javier");
    for (const n of [".localized", ".DS_Store", "Shared", "Guest"]) {
      expect(homes).not.toContain(path.join("/Users", n));
    }
  });

  it("⭐ sin /Users no revienta: sigue con lo que diga /etc/passwd", () => {
    // Exactamente el caso del runner de CI, y tambien el de un macOS con el
    // volumen de datos sin montar. La rama tiene su `catch` por esto.
    const r = conDisco({}, { "/etc/passwd": PASSWD_MACOS }, () => localUsers("darwin"));
    expect(r.map((u) => u.home)).toContain("/var/root");
  });

  it("en Linux NO se inventa /Users: solo /etc/passwd", () => {
    const homes = conDisco(
      { "/Users": ["javier"] },
      { "/etc/passwd": "git:x:1001:1001::/var/lib/git:/usr/bin/git-shell\n" },
      () => localUsers("linux")
    ).map((u) => u.home);

    expect(homes).toContain("/var/lib/git");
    expect(homes).not.toContain("/Users/javier");
  });

  it("los homes falsos de las cuentas del sistema no cuentan", () => {
    const homes = conDisco(
      {},
      {
        "/etc/passwd":
          "a:x:1:1::/:/bin/sh\n" +
          "b:x:2:2::/nonexistent:/usr/sbin/nologin\n" +
          "c:x:3:3::/dev/null:/usr/sbin/nologin\n" +
          "d:x:4:4::/var/lib/gitolite:/usr/bin/git-shell\n",
      },
      () => localUsers("linux")
    ).map((u) => u.home);

    expect(homes).toEqual(["/var/lib/gitolite"]);
  });
});

describe("isPrivateKeyName", () => {
  it("⭐ se decide por el NOMBRE y por el `.pub` hermano, sin abrir nada", () => {
    expect(isPrivateKeyName("id_ed25519", ["id_ed25519", "id_ed25519.pub"])).toBe(true);
    expect(isPrivateKeyName("id_rsa", ["id_rsa"])).toBe(true);
    // Sin nombre de clave, el `.pub` hermano lo delata igual.
    expect(isPrivateKeyName("deploy-2026", ["deploy-2026", "deploy-2026.pub"])).toBe(true);
    expect(isPrivateKeyName("server.pem", ["server.pem"])).toBe(true);
  });

  it("lo que NO es una clave no se toca", () => {
    for (const n of ["known_hosts", "config", "authorized_keys", "authorized_keys2", "id_rsa.pub", "id_rsa.old", "environment"]) {
      expect(isPrivateKeyName(n, [n])).toBe(false);
    }
  });
});

describe("describeOpensshPrivateKey", () => {
  // Cabecera `openssh-key-v1` armada a mano: los dos campos que se leen
  // (nombre del cifrado y blob publico) van en claro y son publicos, asi
  // que no hace falta —ni se quiere— una clave de verdad en disco.
  const header = (cipher: string, publicBlob: Buffer) => {
    const field = (b: Buffer) => {
      const len = Buffer.alloc(4);
      len.writeUInt32BE(b.length);
      return Buffer.concat([len, b]);
    };
    const count = Buffer.alloc(4);
    count.writeUInt32BE(1);
    const blob = Buffer.concat([
      Buffer.from("openssh-key-v1\0", "latin1"),
      field(Buffer.from(cipher)),
      field(Buffer.from(cipher === "none" ? "none" : "bcrypt")),
      field(Buffer.alloc(0)),
      count,
      field(publicBlob),
      field(Buffer.from("cifrado-o-no, aqui no se mira"))
    ]);
    return `-----BEGIN OPENSSH PRIVATE KEY-----\n${blob.toString("base64")}\n-----END OPENSSH PRIVATE KEY-----`;
  };
  const publicBlob = () => Buffer.from(ed25519Pub.split(/\s+/)[1], "base64");

  it("⭐ dice el tipo y si esta cifrada leyendo SOLO la cabecera publica", () => {
    const out = describeOpensshPrivateKey(header("none", publicBlob()))!;
    expect(out.encrypted).toBe(false);
    const parsed = parseSshPublicKey(out.publicLine!, "", { allowSk: true })!;
    expect(parsed.keyType).toBe("ssh-ed25519");
    // La huella de la cabecera es la MISMA que la del `.pub`: es la misma
    // clave publica, que es lo unico que se ha leido.
    expect(parsed.fingerprintSha256).toBe(ed25519Fingerprint);
  });

  it("un cifrado distinto de `none` es una clave con contraseña", () => {
    expect(describeOpensshPrivateKey(header("aes256-ctr", publicBlob()))!.encrypted).toBe(true);
  });

  it("lo que no es openssh-key-v1 devuelve null", () => {
    expect(describeOpensshPrivateKey("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----")).toBeNull();
    expect(describeOpensshPrivateKey("cualquier cosa")).toBeNull();
  });
});

describe("collectSshUserKeys", () => {
  let home: string;
  let sshDir: string;
  let sysFile: string;

  beforeAll(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-home-"));
    sshDir = path.join(home, ".ssh");
    fs.mkdirSync(sshDir);
    fs.writeFileSync(path.join(sshDir, "authorized_keys"), `# claves del equipo\nno-pty ${rsaPub}\n${ed25519Pub}\n`);
    fs.writeFileSync(path.join(sshDir, "authorized_keys2"), `${rsaPub}\n`);
    // Presencia: fichero VACIO con nombre de clave. No hay material
    // privado en disco en ningun momento de esta suite.
    fs.writeFileSync(path.join(sshDir, "id_ed25519"), "");
    fs.chmodSync(path.join(sshDir, "id_ed25519"), 0o600);
    fs.writeFileSync(path.join(sshDir, "id_ed25519.pub"), `${ed25519Pub}\n`);
    fs.writeFileSync(path.join(sshDir, "known_hosts"), "github.com ssh-ed25519 AAAA\n");
    fs.writeFileSync(path.join(sshDir, "config"), "Host *\n  User javier\n");
    sysFile = path.join(home, "etc-authorized_keys");
    fs.writeFileSync(sysFile, `${ed25519Pub}\n`);
  });

  // Funcion y no constante: `home` se crea en el beforeAll.
  const only = () => ({ users: [{ user: "javier", home }], systemFiles: [] as string[] });

  it("⭐ separa lo que CONCEDE acceso de lo que el usuario tiene", async () => {
    const r = await collectSshUserKeys(only());
    const authorized = r.keys.filter((k) => k.kind === "authorized");
    const pub = r.keys.filter((k) => k.kind === "public");
    // 2 en authorized_keys + 1 en authorized_keys2
    expect(authorized).toHaveLength(3);
    expect(pub).toHaveLength(1);
    expect(authorized.every((k) => k.user === "javier")).toBe(true);
    expect(authorized.find((k) => k.keyType === "ssh-rsa")!.options).toEqual(["no-pty"]);
    expect(r.users).toBe(1);
    expect(r.truncated).toBe(false);
    expect(r.mode).toBe("public-only");
  });

  it("⭐ POR DEFECTO no se abre el fichero de la clave privada: solo `stat` y el `.pub` hermano", async () => {
    // Es la regla que evita la deteccion de acceso a credenciales del
    // EDR. Si alguien la quita, este test cae.
    const opened: string[] = [];
    const realRead = fs.readFileSync;
    const spy = (f: any, ...rest: any[]) => {
      if (typeof f === "string") opened.push(f);
      return (realRead as any)(f, ...rest);
    };
    (fs as any).readFileSync = spy;
    try {
      const r = await collectSshUserKeys(only());
      expect(opened.some((f) => f.endsWith(`${path.sep}id_ed25519`))).toBe(false);
      // Y los publicos SI se leen: no disparan nada.
      expect(opened.some((f) => f.endsWith("id_ed25519.pub"))).toBe(true);
      expect(opened.some((f) => f.endsWith("authorized_keys"))).toBe(true);

      const k = r.privateKeys[0];
      expect(k.path.endsWith("id_ed25519")).toBe(true);
      // «No se sabe», que no es «no cifrada».
      expect(k.encrypted).toBeNull();
      expect(k.format).toBe("unknown");
      // Lo que `stat` si da, y que es lo que pide un auditor.
      expect(k.filePermissions).toBe("600");
      expect(k.sizeBytes).toBe(0);
      expect(typeof k.modifiedAt).toBe("string");
      // El tipo y la huella salen del `.pub`, que es publico.
      expect(k.keyType).toBe("ssh-ed25519");
      expect(k.fingerprintSha256).toBe(ed25519Fingerprint);
      expect(k.publicHalfPath!.endsWith("id_ed25519.pub")).toBe(true);
    } finally {
      (fs as any).readFileSync = realRead;
    }
  });

  it("⭐ en modo `full` SI se abre (y por eso no es el defecto)", async () => {
    const opened: string[] = [];
    const realRead = fs.readFileSync;
    (fs as any).readFileSync = (f: any, ...rest: any[]) => {
      if (typeof f === "string") opened.push(f);
      return (realRead as any)(f, ...rest);
    };
    try {
      const r = await collectSshUserKeys({ ...only(), mode: "full" });
      expect(opened.some((f) => f.endsWith(`${path.sep}id_ed25519`))).toBe(true);
      expect(r.mode).toBe("full");
      // El fichero esta vacio a proposito: no es una clave, asi que el
      // formato sigue siendo desconocido y nada se inventa.
      expect(r.privateKeys[0].format).toBe("unknown");
    } finally {
      (fs as any).readFileSync = realRead;
    }
  });

  it("⭐ en modo `off` no se mira nada en absoluto", async () => {
    const r = await collectSshUserKeys({ ...only(), mode: "off" });
    expect(r).toEqual({ users: 0, keys: [], privateKeys: [], unreadable: 0, truncated: false, mode: "off" });
  });

  it("nunca sale material de clave en el payload", async () => {
    const dump = JSON.stringify(await collectSshUserKeys({ ...only(), mode: "full" }));
    expect(dump).not.toContain("PRIVATE KEY");
    expect(dump).not.toContain("BEGIN");
  });

  it("known_hosts y config no son claves", async () => {
    const r = await collectSshUserKeys(only());
    expect(r.keys.some((k) => k.path.endsWith("known_hosts"))).toBe(false);
    expect(r.privateKeys.some((k) => k.path.endsWith("config"))).toBe(false);
    expect(r.privateKeys).toHaveLength(1);
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
