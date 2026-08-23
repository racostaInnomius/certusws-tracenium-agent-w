// test/plugins/rcp-path-jail.test.ts
//
// Confinement tests for the rcp.file path jail.
//
// The fake filesystem below lets a single test run exercise BOTH Windows and
// POSIX semantics from any host: the jail takes `platform` as a dependency
// and selects path.win32 / path.posix accordingly, so nothing here depends on
// the separator of the machine running the suite.

import { describe, it, expect } from "vitest";
import { PathJail, sanitizeAbsolutePaths, JAIL_PATHS_MAX } from "../../src/plugins/rcp/path-jail";

/**
 * Minimal fs double. `existing` is the set of paths that exist; `links` maps
 * a path to what it really points at (applied to the deepest existing
 * ancestor, exactly like fs.realpathSync would).
 */
function fakeFs(existing: string[], links: Record<string, string> = {}) {
  const set = new Set(existing);
  return {
    existsSync: (p: string) => set.has(p),
    realpathSync: (p: string) => {
      if (links[p]) return links[p];
      // Resolve a symlinked ancestor: longest matching prefix wins.
      for (const [from, to] of Object.entries(links)) {
        if (p === from) return to;
        if (p.startsWith(from + "/") || p.startsWith(from + "\\")) {
          return to + p.slice(from.length);
        }
      }
      return p;
    }
  };
}

const POSIX_ENV = { SystemDrive: "C:", ProgramData: "C:\\ProgramData" };

function posixJail(config = {}, existing: string[] = [], links = {}) {
  return new PathJail(config, {
    platform: "linux",
    env: POSIX_ENV,
    ...fakeFs(existing, links)
  });
}

function winJail(config = {}, existing: string[] = [], links = {}) {
  return new PathJail(config, {
    platform: "win32",
    env: {
      SystemDrive: "C:",
      SystemRoot: "C:\\Windows",
      ProgramData: "C:\\ProgramData",
      TEMP: "C:\\Windows\\Temp"
    },
    ...fakeFs(existing, links)
  });
}

describe("PathJail — allowed traffic", () => {
  it("permits a file inside a default root", () => {
    const jail = posixJail({}, ["/home", "/home/ana", "/home/ana/report.txt"]);
    const d = jail.check("/home/ana/report.txt");
    expect(d.allowed).toBe(true);
    expect(d.allowed && d.realPath).toBe("/home/ana/report.txt");
  });

  it("permits the root itself so the browser can list it", () => {
    const jail = posixJail({}, ["/home"]);
    expect(jail.check("/home").allowed).toBe(true);
  });

  it("permits a path that does not exist yet (upload target)", () => {
    const jail = posixJail({}, ["/home", "/home/ana"]);
    const d = jail.check("/home/ana/new-file.txt");
    expect(d.allowed).toBe(true);
    expect(d.allowed && d.realPath).toBe("/home/ana/new-file.txt");
  });

  it("honours policy-configured roots instead of the defaults", () => {
    const jail = posixJail({ roots: ["/srv/shared"] }, ["/srv", "/srv/shared", "/home"]);
    expect(jail.check("/srv/shared/a.log").allowed).toBe(true);
    // /home is a DEFAULT root, but policy replaced the list.
    const d = jail.check("/home/ana/report.txt");
    expect(d.allowed).toBe(false);
    expect(!d.allowed && d.code).toBe("PATH_OUTSIDE_ROOTS");
  });
});

describe("PathJail — traversal and prefix bypasses", () => {
  it("refuses ../ escapes out of a root", () => {
    const jail = posixJail({}, ["/home", "/etc", "/etc/shadow"]);
    const d = jail.check("/home/../etc/shadow");
    expect(d.allowed).toBe(false);
  });

  it("refuses a sibling directory sharing the root's name prefix", () => {
    // The classic startsWith() bug: "/home-evil" must not match root "/home".
    const jail = posixJail({}, ["/home", "/home-evil", "/home-evil/loot.txt"]);
    const d = jail.check("/home-evil/loot.txt");
    expect(d.allowed).toBe(false);
    expect(!d.allowed && d.code).toBe("PATH_OUTSIDE_ROOTS");
  });

  it("refuses a NUL byte", () => {
    const jail = posixJail({}, ["/home"]);
    const d = jail.check("/home/ana/safe.txt\0/etc/shadow");
    expect(d.allowed).toBe(false);
    expect(!d.allowed && d.code).toBe("PATH_INVALID");
  });

  it("refuses non-string and empty input", () => {
    const jail = posixJail({}, ["/home"]);
    expect(jail.check(undefined).allowed).toBe(false);
    expect(jail.check("").allowed).toBe(false);
    expect(jail.check("   ").allowed).toBe(false);
  });
});

describe("PathJail — symlink escapes", () => {
  it("refuses a symlink inside a root pointing outside it", () => {
    const jail = posixJail(
      {},
      ["/home", "/home/ana", "/home/ana/escape", "/etc", "/etc/shadow"],
      { "/home/ana/escape": "/etc/shadow" }
    );
    const d = jail.check("/home/ana/escape");
    expect(d.allowed).toBe(false);
  });

  it("refuses a write whose ANCESTOR is a symlink out of the jail", () => {
    // The upload attack: /tmp is world-writable, a local user plants
    // /tmp/drop -> /etc, and the agent (root) is asked to write
    // /tmp/drop/cron.d/pwn — a file that does not exist yet.
    const jail = posixJail({}, ["/tmp", "/tmp/drop", "/etc"], {
      "/tmp/drop": "/etc"
    });
    const d = jail.check("/tmp/drop/cron.d/pwn");
    expect(d.allowed).toBe(false);
    expect(!d.allowed && d.code).toBe("PATH_OUTSIDE_ROOTS");
  });

  it("follows a symlink that stays inside the jail", () => {
    const jail = posixJail({}, ["/home", "/home/ana", "/home/ana/link", "/home/shared"], {
      "/home/ana/link": "/home/shared"
    });
    const d = jail.check("/home/ana/link/notes.txt");
    expect(d.allowed).toBe(true);
    expect(d.allowed && d.realPath).toBe("/home/shared/notes.txt");
  });
});

describe("PathJail — deny wins inside an allowed root", () => {
  it("seals the agent credential directory under an allowed ProgramData root", () => {
    const jail = winJail({}, [
      "C:\\ProgramData",
      "C:\\ProgramData\\Tracenium",
      "C:\\ProgramData\\Tracenium\\Agent",
      "C:\\ProgramData\\Tracenium\\Agent\\client.key"
    ]);
    // ProgramData IS a default root…
    expect(jail.check("C:\\ProgramData").allowed).toBe(true);
    // …but the agent's own directory underneath it is not reachable.
    const d = jail.check("C:\\ProgramData\\Tracenium\\Agent\\client.key");
    expect(d.allowed).toBe(false);
    expect(!d.allowed && d.code).toBe("PATH_DENIED");
  });

  it("seals the registry hives even if policy opens the whole drive", () => {
    const jail = winJail({ roots: ["C:\\"] }, [
      "C:\\",
      "C:\\Windows",
      "C:\\Windows\\System32",
      "C:\\Windows\\System32\\config",
      "C:\\Windows\\System32\\config\\SAM"
    ]);
    const d = jail.check("C:\\Windows\\System32\\config\\SAM");
    expect(d.allowed).toBe(false);
    expect(!d.allowed && d.code).toBe("PATH_DENIED");
  });

  it("seals /etc/shadow even if policy opens /", () => {
    const jail = posixJail({ roots: ["/"] }, ["/", "/etc", "/etc/shadow"]);
    expect(jail.check("/etc/shadow").allowed).toBe(false);
  });

  it("seals per-user credential directories anywhere they appear", () => {
    const jail = posixJail({}, [
      "/home",
      "/home/ana",
      "/home/ana/.ssh",
      "/home/ana/.ssh/id_rsa"
    ]);
    const d = jail.check("/home/ana/.ssh/id_rsa");
    expect(d.allowed).toBe(false);
    expect(!d.allowed && d.code).toBe("PATH_DENIED");
  });

  it("seals private-key file extensions", () => {
    const jail = posixJail({}, ["/home", "/home/ana", "/home/ana/server.pem"]);
    const d = jail.check("/home/ana/server.pem");
    expect(d.allowed).toBe(false);
    expect(!d.allowed && d.code).toBe("PATH_DENIED");
  });

  it("accepts extra deny paths from policy", () => {
    const jail = posixJail({ denyPaths: ["/home/ana/private"] }, [
      "/home",
      "/home/ana",
      "/home/ana/private",
      "/home/ana/private/x.txt"
    ]);
    expect(jail.check("/home/ana/private/x.txt").allowed).toBe(false);
    expect(jail.check("/home/ana").allowed).toBe(true);
  });
});

describe("PathJail — Windows specifics", () => {
  it("compares case-insensitively", () => {
    const jail = winJail({}, ["C:\\Users", "C:\\Users\\ana", "C:\\Users\\ana\\a.txt"]);
    expect(jail.check("c:\\users\\ANA\\a.txt").allowed).toBe(true);
  });

  it("seals the agent directory regardless of case", () => {
    const jail = winJail({}, [
      "C:\\ProgramData",
      "C:\\ProgramData\\Tracenium",
      "C:\\ProgramData\\Tracenium\\Agent"
    ]);
    expect(jail.check("c:\\programdata\\TRACENIUM\\agent").allowed).toBe(false);
  });

  it("refuses a drive outside the roots", () => {
    const jail = winJail({}, ["C:\\Users", "D:\\", "D:\\loot.txt"]);
    const d = jail.check("D:\\loot.txt");
    expect(d.allowed).toBe(false);
    expect(!d.allowed && d.code).toBe("PATH_OUTSIDE_ROOTS");
  });
});

describe("PathJail — roots listing", () => {
  it("exposes the configured roots for the browser's starting points", () => {
    const jail = posixJail({ roots: ["/srv/a", "/srv/b"] }, ["/srv", "/srv/a", "/srv/b"]);
    expect(jail.listRoots()).toEqual(["/srv/a", "/srv/b"]);
  });

  it("resolves a symlinked root so paths under it match", () => {
    // macOS: /tmp is a symlink to /private/tmp. A lexical root of "/tmp"
    // would never match the real path of anything inside it.
    const jail = new PathJail(
      { roots: ["/tmp"] },
      {
        platform: "darwin",
        env: {},
        ...fakeFs(["/tmp", "/private/tmp", "/private/tmp/f.txt"], { "/tmp": "/private/tmp" })
      }
    );
    expect(jail.listRoots()).toEqual(["/private/tmp"]);
    expect(jail.check("/tmp/f.txt").allowed).toBe(true);
  });
});

describe("sanitizeAbsolutePaths", () => {
  it("drops relative, empty, oversized and duplicate entries", () => {
    const out = sanitizeAbsolutePaths(
      ["/a", "relative/path", "", "   ", "/a", "/b", "x".repeat(600)],
      "linux"
    );
    expect(out).toEqual(["/a", "/b"]);
  });

  it("accepts Windows drive paths", () => {
    expect(sanitizeAbsolutePaths(["C:\\Users", "D:/data"], "win32")).toEqual([
      "C:\\Users",
      "D:/data"
    ]);
  });

  it("de-duplicates case-insensitively on Windows only", () => {
    expect(sanitizeAbsolutePaths(["C:\\Users", "c:\\users"], "win32")).toHaveLength(1);
    expect(sanitizeAbsolutePaths(["/Data", "/data"], "linux")).toHaveLength(2);
  });

  it("caps the number of entries", () => {
    const many = Array.from({ length: JAIL_PATHS_MAX + 10 }, (_, i) => `/root${i}`);
    expect(sanitizeAbsolutePaths(many, "linux")).toHaveLength(JAIL_PATHS_MAX);
  });

  it("ignores non-arrays and non-strings", () => {
    expect(sanitizeAbsolutePaths(undefined, "linux")).toEqual([]);
    expect(sanitizeAbsolutePaths("/a", "linux")).toEqual([]);
    expect(sanitizeAbsolutePaths([1, null, {}], "linux")).toEqual([]);
  });
});

describe("PathJail — raíces duplicadas", () => {
  // Los duplicados no están en la lista literal: aparecen al resolver symlinks.
  // En macOS /tmp → /private/tmp, y os.tmpdir() suele coincidir con una raíz ya
  // presente. El operador veía chips repetidos que llevaban al mismo sitio.
  it("colapsa las raíces que resuelven al mismo sitio real", () => {
    const jail = new PathJail(
      { roots: ["/Users", "/tmp", "/private/tmp", "/opt"] },
      {
        platform: "darwin",
        realpathSync: (p: string) => (p === "/tmp" ? "/private/tmp" : p),
        existsSync: () => true
      }
    );
    const roots = (jail as any).rootsForDisplay as string[];
    expect(roots).toEqual(["/Users", "/private/tmp", "/opt"]);
  });

  it("no colapsa raíces distintas que comparten prefijo", () => {
    const jail = new PathJail(
      { roots: ["/opt", "/opt2"] },
      { platform: "linux", realpathSync: (p: string) => p, existsSync: () => true }
    );
    expect((jail as any).rootsForDisplay).toEqual(["/opt", "/opt2"]);
  });
});

describe("PathJail — excepciones a la denylist (logs)", () => {
  const winDeps = {
    platform: "win32" as NodeJS.Platform,
    env: { ProgramData: "C:\\ProgramData", SystemDrive: "C:", SystemRoot: "C:\\Windows" },
    realpathSync: (p: string) => p,
    existsSync: () => true,
    tmpdir: "C:\\Windows\\Temp"
  };

  it("los logs del agente son alcanzables aunque su carpeta padre esté denegada", () => {
    const jail = new PathJail({}, winDeps);
    const d = jail.check("C:\\ProgramData\\Tracenium\\logs\\privsvc-20260820.log");
    expect(d.allowed).toBe(true);
  });

  it("el resto del directorio de datos sigue sellado", () => {
    const jail = new PathJail({}, winDeps);
    for (const p of [
      "C:\\ProgramData\\Tracenium\\mtls-client.crt.pem",
      "C:\\ProgramData\\Tracenium\\outbox.db",
      "C:\\ProgramData\\Tracenium\\Agent\\debug.flag"
    ]) {
      const d: any = jail.check(p);
      expect(d.allowed, `debería seguir denegado: ${p}`).toBe(false);
      expect(d.code).toBe("PATH_DENIED");
    }
  });

  it("una excepción no anula los segmentos prohibidos", () => {
    const jail = new PathJail({}, winDeps);
    const d: any = jail.check("C:\\ProgramData\\Tracenium\\logs\\.ssh\\id_rsa");
    expect(d.allowed).toBe(false);
    expect(d.code).toBe("PATH_DENIED");
  });

  it("Program Files es alcanzable en Windows", () => {
    const jail = new PathJail({}, winDeps);
    expect(jail.check("C:\\Program Files\\Tracenium\\AgentCore").allowed).toBe(true);
  });
});

describe("PathJail — los logs son navegables, no solo permitidos", () => {
  // Una excepción a la denylist no basta por sí sola: para ENTRAR en
  // ProgramData\Tracenium\logs hay que poder listar ProgramData\Tracenium,
  // que está denegado. El operador veía el rescate y no podía llegar a él.
  it("el directorio de logs es una raíz propia en Windows", () => {
    const jail = new PathJail({}, {
      platform: "win32",
      env: { ProgramData: "C:\\ProgramData", SystemDrive: "C:", SystemRoot: "C:\\Windows" },
      realpathSync: (p) => p,
      existsSync: () => true,
      tmpdir: "C:\\Windows\\Temp"
    });
    const roots = (jail).rootsForDisplay;
    expect(roots).toContain("C:\\ProgramData\\Tracenium\\logs");
    // Y el padre sigue sellado: la raíz no lo abre.
    const d = jail.check("C:\\ProgramData\\Tracenium\\mtls-client.crt.pem");
    expect(d.allowed).toBe(false);
  });
});
