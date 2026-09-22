// test/plugins/cdp-process-libraries.test.ts
//
// Ola 1.5 — libreria criptografica por proceso. Lo que se defiende:
//   · el alcance son los procesos QUE ESCUCHAN, no un `ps` de la maquina;
//   · la version viene de la soname, de la ruta o del fichero leido como
//     DATOS, nunca ejecutando lo que se acaba de encontrar;
//   · la soname no basta (3.0.2 y 3.6.2 son los dos `libssl.so.3`, y el
//     umbral de ML-KEM esta en medio), asi que se dice de donde sale.

import { describe, it, expect } from "vitest";
import {
  classifyLibraryPath,
  collectProcessLibraries,
  parseLsofLibraries,
  parseProcMaps,
  parseWindowsModules,
  serviceFromCgroup,
  versionFromBinary,
  versionFromPath,
  MAX_LIBS_PER_PROCESS
} from "../../src/plugins/cdp/providers/process-libraries";

describe("classifyLibraryPath", () => {
  it("reconoce las pilas que deciden si un servicio puede hacer ML-KEM", () => {
    expect(classifyLibraryPath("/usr/lib/x86_64-linux-gnu/libssl.so.3")).toBe("openssl");
    expect(classifyLibraryPath("/usr/lib/libcrypto.so.1.1")).toBe("openssl");
    expect(classifyLibraryPath("/usr/lib/libgnutls.so.30")).toBe("gnutls");
    expect(classifyLibraryPath("/usr/lib/libnss3.so")).toBe("nss");
    expect(classifyLibraryPath("/usr/lib/libgcrypt.so.20")).toBe("gcrypt");
    expect(classifyLibraryPath("C:\\Windows\\System32\\bcrypt.dll")).toBe("schannel");
    expect(classifyLibraryPath("/usr/lib/libssl.48.dylib")).toBe("openssl");
  });

  it("lo que no es una libreria criptografica no cuenta", () => {
    expect(classifyLibraryPath("/usr/lib/libc.so.6")).toBeNull();
    expect(classifyLibraryPath("/usr/sbin/nginx")).toBeNull();
    // ⚠️ `libsslfoo.so` NO es libssl: el patron exige el separador.
    expect(classifyLibraryPath("/usr/lib/libsslfoo.so")).toBeNull();
  });
});

describe("versionFromPath", () => {
  it("soname, dylib y ruta de instalacion", () => {
    expect(versionFromPath("/usr/lib/libssl.so.3")).toEqual({ version: "3", source: "soname" });
    expect(versionFromPath("/usr/lib/libssl.so.1.1")).toEqual({ version: "1.1", source: "soname" });
    expect(versionFromPath("/usr/lib/libssl.3.dylib")).toEqual({ version: "3", source: "soname" });
    expect(versionFromPath("/opt/homebrew/Cellar/openssl@3/3.5.0/lib/libssl.dylib")).toEqual({
      version: "3.5.0",
      source: "path"
    });
  });

  it("sin nada que leer, null (y no un cero inventado)", () => {
    expect(versionFromPath("/usr/lib/libssl.so")).toBeNull();
  });
});

describe("versionFromBinary", () => {
  it("⭐ la cadena que la libreria lleva dentro: lo unico que distingue 3.0.2 de 3.6.2", () => {
    expect(versionFromBinary(Buffer.from("....OpenSSL 3.0.2 15 Mar 2022...."))).toBe("3.0.2");
    expect(versionFromBinary(Buffer.from("xxOpenSSL 3.6.2 1 Jan 2026yy"))).toBe("3.6.2");
    expect(versionFromBinary(Buffer.from("LibreSSL 3.3.6"))).toBe("3.3.6");
    expect(versionFromBinary(Buffer.from("GnuTLS/3.8.9"))).toBe("3.8.9");
    expect(versionFromBinary(Buffer.from("no hay version aqui"))).toBeNull();
  });
});

describe("parseProcMaps", () => {
  const maps = [
    "7f8c00000000-7f8c00021000 r--p 00000000 fd:00 1234 /usr/lib/x86_64-linux-gnu/libssl.so.3",
    "7f8c00021000-7f8c00080000 r-xp 00021000 fd:00 1234 /usr/lib/x86_64-linux-gnu/libssl.so.3",
    "7f8c00090000-7f8c00100000 r-xp 00000000 fd:00 1235 /usr/lib/x86_64-linux-gnu/libc.so.6",
    "7f8c00200000-7f8c00300000 rw-p 00000000 00:00 0 [heap]",
    "7f8c00400000-7f8c00500000 r--p 00000000 fd:00 9 /var/lib/nginx/cache/data.bin"
  ].join("\n");

  it("⭐ solo lo mapeado como libreria, deduplicado (un .so aparece en varias lineas)", () => {
    expect(parseProcMaps(maps)).toEqual([
      "/usr/lib/x86_64-linux-gnu/libssl.so.3",
      "/usr/lib/x86_64-linux-gnu/libc.so.6"
    ]);
  });

  it("un mapa vacio o sin rutas no revienta", () => {
    expect(parseProcMaps("")).toEqual([]);
    expect(parseProcMaps("7f8c-7f8d rw-p 0 00:00 0")).toEqual([]);
  });
});

describe("serviceFromCgroup", () => {
  it("la unidad de systemd es la identidad que sobrevive a un reinicio", () => {
    expect(serviceFromCgroup("0::/system.slice/nginx.service")).toBe("nginx.service");
    expect(serviceFromCgroup("0::/user.slice/user-1000.slice/session-3.scope")).toBeNull();
  });
});

describe("parseLsofLibraries / parseWindowsModules", () => {
  it("lsof clasico: solo las entradas `txt` son imagenes cargadas", () => {
    const out = parseLsofLibraries(
      [
        "nginx  4321 root  txt  REG  1,4  900000  12  /usr/local/opt/openssl@3/lib/libssl.3.dylib",
        "nginx  4321 root  6u   IPv4 0x1  0t0 TCP *:443 (LISTEN)"
      ].join("\n")
    );
    expect(out.get(4321)).toEqual(["/usr/local/opt/openssl@3/lib/libssl.3.dylib"]);
  });

  it("modulos de Windows: la version la da el propio VERSIONINFO", () => {
    const out = parseWindowsModules(
      JSON.stringify([
        { Pid: 900, FileName: "C:\\Program Files\\App\\libssl-3-x64.dll", FileVersion: "3.2.1.0" },
        { Pid: 900, FileName: "C:\\Windows\\System32\\bcrypt.dll", FileVersion: "10.0.26100.1" }
      ])
    );
    expect(out.get(900)).toHaveLength(2);
    expect(out.get(900)![0]).toEqual({ path: "C:\\Program Files\\App\\libssl-3-x64.dll", version: "3.2.1.0" });
  });

  it("un JSON roto no tira el colector", () => {
    expect(parseWindowsModules("{no json")).toEqual(new Map());
  });
});

describe("collectProcessLibraries", () => {
  const proc = (pid: number, name: string, ports: number[], p?: string) => ({ pid, name, ports, ...(p ? { path: p } : {}) });
  const base = { platform: "linux" as NodeJS.Platform, serviceFor: () => null, readVersion: () => null, realpath: (f: string) => f };

  it("sin procesos a la escucha no hay nada que decir", async () => {
    const r = await collectProcessLibraries({ ...base, processes: [], libraries: new Map() });
    expect(r).toEqual({ processes: 0, libraries: [], truncated: false });
  });

  it("⭐ una plataforma que no sabemos mirar lo DICE, no devuelve una lista vacia", async () => {
    // Una lista vacia se lee como «este equipo no carga ninguna libreria
    // criptografica», que es una afirmacion falsa.
    const r = await collectProcessLibraries({ ...base, platform: "freebsd" as NodeJS.Platform });
    expect(r.unsupported).toBe("platform:freebsd");
    expect(r.libraries).toEqual([]);
  });

  it("⭐ atribuye la libreria al SERVICIO, con sus puertos y su imagen", async () => {
    const r = await collectProcessLibraries({
      ...base,
      processes: [proc(10, "nginx", [443, 80], "/usr/sbin/nginx")],
      libraries: new Map([[10, [{ path: "/usr/lib/libssl.so.3" }, { path: "/usr/lib/libc.so.6" }]]]),
      serviceFor: () => "nginx.service",
      readVersion: () => "3.0.2"
    });
    expect(r.libraries).toHaveLength(1);
    expect(r.libraries[0]).toEqual({
      pid: 10,
      process: "nginx",
      imagePath: "/usr/sbin/nginx",
      service: "nginx.service",
      ports: [80, 443],
      library: "openssl",
      libraryPath: "/usr/lib/libssl.so.3",
      version: "3.0.2",
      versionSource: "file"
    });
  });

  it("⭐ la version del FICHERO gana a la de la soname: `libssl.so.3` puede ser 3.0 o 3.6", async () => {
    const withFile = await collectProcessLibraries({
      ...base,
      processes: [proc(1, "svc", [443])],
      libraries: new Map([[1, [{ path: "/usr/lib/libssl.so.3" }]]]),
      readVersion: () => "3.6.2"
    });
    expect(withFile.libraries[0]).toMatchObject({ version: "3.6.2", versionSource: "file" });

    // Sin poder leer el fichero queda la soname, y se DICE que es eso.
    const withoutFile = await collectProcessLibraries({
      ...base,
      processes: [proc(1, "svc", [443])],
      libraries: new Map([[1, [{ path: "/usr/lib/libssl.so.3" }]]])
    });
    expect(withoutFile.libraries[0]).toMatchObject({ version: "3", versionSource: "soname" });
  });

  it("⭐ se resuelve el enlace: el destino es el que dice la version", async () => {
    const r = await collectProcessLibraries({
      ...base,
      processes: [proc(1, "svc", [443])],
      libraries: new Map([[1, [{ path: "/usr/lib/libssl.so.3" }, { path: "/usr/lib/libssl.so.3.0.2" }]]]),
      realpath: (f) => (f === "/usr/lib/libssl.so.3" ? "/usr/lib/libssl.so.3.0.2" : f)
    });
    // Las dos rutas son el MISMO fichero: una sola fila.
    expect(r.libraries).toHaveLength(1);
    expect(r.libraries[0].libraryPath).toBe("/usr/lib/libssl.so.3.0.2");
  });

  it("la version de un mismo fichero se lee UNA vez aunque la carguen N procesos", async () => {
    let reads = 0;
    await collectProcessLibraries({
      ...base,
      processes: [proc(1, "a", [443]), proc(2, "b", [8443]), proc(3, "c", [9443])],
      libraries: new Map([
        [1, [{ path: "/usr/lib/libssl.so.3" }]],
        [2, [{ path: "/usr/lib/libssl.so.3" }]],
        [3, [{ path: "/usr/lib/libssl.so.3" }]]
      ]),
      readVersion: () => (reads++, "3.0.2")
    });
    expect(reads).toBe(1);
  });

  it("⭐ el presupuesto de pared corta y lo dice", async () => {
    let t = 0;
    const many = Array.from({ length: 40 }, (_, i) => proc(i + 1, `svc${i}`, [1000 + i]));
    const libs = new Map(many.map((p) => [p.pid, [{ path: "/usr/lib/libssl.so.3" }]]));
    const r = await collectProcessLibraries({ ...base, processes: many, libraries: libs, now: () => (t += 10_000) });
    expect(r.truncated).toBe(true);
    expect(r.libraries.length).toBeLessThan(40);
  });

  it("el tope por proceso tambien se dice", async () => {
    const libs = Array.from({ length: MAX_LIBS_PER_PROCESS + 3 }, (_, i) => ({ path: `/usr/lib/libssl.so.${i}` }));
    const r = await collectProcessLibraries({ ...base, processes: [proc(1, "svc", [443])], libraries: new Map([[1, libs]]) });
    expect(r.libraries).toHaveLength(MAX_LIBS_PER_PROCESS);
    expect(r.truncated).toBe(true);
  });

  it("un proceso sin librerias criptograficas no produce filas (pero si cuenta como mirado)", async () => {
    const r = await collectProcessLibraries({
      ...base,
      processes: [proc(1, "sshd", [22])],
      libraries: new Map([[1, [{ path: "/usr/lib/libc.so.6" }]]])
    });
    expect(r.processes).toBe(1);
    expect(r.libraries).toEqual([]);
  });

  it("en Windows la version del modulo se respeta tal cual", async () => {
    const r = await collectProcessLibraries({
      ...base,
      platform: "win32",
      processes: [proc(900, "w3wp.exe", [443], "C:\\Windows\\System32\\inetsrv\\w3wp.exe")],
      libraries: new Map([[900, [{ path: "C:\\App\\libssl-3-x64.dll", version: "3.2.1.0" }]]])
    });
    expect(r.libraries[0]).toMatchObject({ library: "openssl", version: "3.2.1.0", versionSource: "module" });
  });
});
