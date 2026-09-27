// test/privsvc/linux-cdp-process-maps.test.ts
//
// `cdp.process.maps` (PrivSvc de Linux, root): quién escucha en cada puerto y
// qué .so mapea. Con un /proc falso: lo que se fija es que sólo se responde por
// PUERTOS pedidos, que se atribuye bien (inodo → pid) y los topes.

import { describe, it, expect } from "vitest";
import { collectProcessMaps, parseProcMaps } from "../../privsvc/linux/src/cdp-process-maps";

const TCP = [
  "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
  "   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5001 1",
  "   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5002 1",
  "   2: 0100007F:1F90 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 5003 1",
].join("\n");

function fakeProc(): any {
  const files: Record<string, string> = {
    "/proc/net/tcp": TCP,
    "/proc/900/comm": "nginx\n",
    "/proc/900/cgroup": "0::/system.slice/nginx.service\n",
    "/proc/900/maps":
      "7f00-7f10 r-xp 0 08:01 1 /usr/lib/x86_64-linux-gnu/libssl.so.3\n7f10-7f20 r-xp 0 08:01 2 /usr/lib/x86_64-linux-gnu/libssl.so.3\n7f20-7f30 r--p 0 08:01 3 /etc/nginx/nginx.conf\n",
    "/proc/77/comm": "sshd\n",
    "/proc/77/maps": "7f00-7f10 r-xp 0 08:01 9 /usr/lib/libcrypto.so.3 (deleted)\n",
  };
  const links: Record<string, string> = {
    "/proc/900/fd/6": "socket:[5001]",
    "/proc/900/exe": "/usr/sbin/nginx",
    "/proc/77/fd/3": "socket:[5002]",
    "/proc/77/exe": "/usr/sbin/sshd",
  };
  return {
    readFileSync: (p: string) => {
      if (p in files) return files[p];
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    },
    readdirSync: (p: string) => (p === "/proc" ? ["1", "77", "900", "self"] : p === "/proc/900/fd" ? ["6"] : p === "/proc/77/fd" ? ["3"] : []),
    readlinkSync: (p: string) => {
      if (p in links) return links[p];
      throw new Error("ENOENT");
    },
  };
}

describe("cdp.process.maps", () => {
  it("⭐ atribuye cada puerto pedido a su proceso, con unidad, imagen y .so mapeadas (deduplicadas)", () => {
    const out = collectProcessMaps([443, 22], fakeProc());
    const nginx = out.find((p) => p.pid === 900)!;
    expect(nginx).toEqual({ pid: 900, name: "nginx", path: "/usr/sbin/nginx", service: "nginx.service", ports: [443], libs: ["/usr/lib/x86_64-linux-gnu/libssl.so.3"] });
    // Una librería borrada tras actualizar el paquete sigue mapeada: se cuenta sin «(deleted)».
    expect(out.find((p) => p.pid === 77)!.libs).toEqual(["/usr/lib/libcrypto.so.3"]);
  });

  it("⭐ sólo responde por los puertos PEDIDOS; un puerto que no escucha (estado ≠ 0A) no cuenta", () => {
    expect(collectProcessMaps([443], fakeProc()).map((p) => p.pid)).toEqual([900]);
    expect(collectProcessMaps([8080], fakeProc())).toEqual([]);
  });

  it("basura en los parámetros no hace nada", () => {
    expect(collectProcessMaps(["../../etc", -1, 70000, null], fakeProc())).toEqual([]);
    expect(collectProcessMaps(undefined, fakeProc())).toEqual([]);
  });

  it("maps: sólo librerías compartidas, no ficheros de datos", () => {
    expect(parseProcMaps("a r-xp 0 0 1 /usr/lib/libgnutls.so.30.34.1\nb r--p 0 0 2 /var/lib/data.db\n")).toEqual(["/usr/lib/libgnutls.so.30.34.1"]);
  });
});
