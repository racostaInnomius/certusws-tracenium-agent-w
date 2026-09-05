// src/plugins/cdp/providers/ssh-host-keys.ts
//
// Claves de host SSH (analisis de madurez de CDP 2026-09, §5.2).
//
// SSH no usa X.509, asi que ningun almacen lo ve, y el puerto 22 esta
// en la lista de saltados de la sonda porque un ClientHello ensucia el
// auth.log. Pero la clave de host es la identidad criptografica mas
// antigua de cada servidor y una de las que mas tardaran en ser
// post-cuanticas: OpenSSH negocia ya intercambio hibrido
// (sntrup761x25519, mlkem768x25519) pero las claves de HOST siguen
// siendo RSA/ECDSA/Ed25519 y no hay firma PQC estandarizada en SSH.
//
// Se leen los `.pub` de sshd EN DISCO: son publicos, no hace falta
// hablar con el servicio ni tocar la red. Se reporta tipo, tamano y la
// huella SHA256 tal como la pinta `ssh-keygen -lf`.

import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";

export type SshHostKey = {
  /** ssh-rsa, ecdsa-sha2-nistp256, ssh-ed25519… */
  keyType: string;
  /** RSA / EC / Ed25519 / DSA, para clasificar como el resto. */
  algorithm: string;
  bits: number | null;
  curve: string | null;
  /** `SHA256:<base64 sin relleno>` — el formato de OpenSSH. */
  fingerprintSha256: string;
  path: string;
};

export type SshHostKeysResult = {
  host: string;
  keys: SshHostKey[];
  /** sshd escucha en 22 (o el puerto configurado) segun la lista de listeners. */
  listening: boolean;
  unreadable: number;
};

function hostKeyDirs(platform: NodeJS.Platform): string[] {
  if (platform === "win32") return [path.join(process.env.ProgramData || "C:\\ProgramData", "ssh")];
  return ["/etc/ssh"];
}

/** Lee un mpint/string SSH (uint32 len + bytes). */
function readField(buf: Buffer, off: number): { value: Buffer; next: number } | null {
  if (off + 4 > buf.length) return null;
  const len = buf.readUInt32BE(off);
  if (len > buf.length - off - 4) return null;
  return { value: buf.subarray(off + 4, off + 4 + len), next: off + 4 + len };
}

/** `<type> <base64> [comment]` → clave con tipo/tamano/huella, o null. */
export function parseSshPublicKey(line: string, filePath = ""): SshHostKey | null {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 2) return null;
  const [keyType, b64] = parts;
  let blob: Buffer;
  try {
    blob = Buffer.from(b64, "base64");
  } catch {
    return null;
  }
  const t = readField(blob, 0);
  if (!t || t.value.toString("ascii") !== keyType) return null;
  let algorithm: string;
  let bits: number | null = null;
  let curve: string | null = null;
  if (keyType === "ssh-rsa") {
    algorithm = "RSA";
    const e = readField(blob, t.next);
    const n = e ? readField(blob, e.next) : null;
    if (n) {
      // mpint: puede llevar un 0x00 de relleno para el signo.
      let i = 0;
      while (i < n.value.length && n.value[i] === 0) i += 1;
      const first = n.value[i] ?? 0;
      bits = (n.value.length - i - 1) * 8 + (first ? 32 - Math.clz32(first) : 0);
    }
  } else if (keyType.startsWith("ecdsa-sha2-")) {
    algorithm = "EC";
    curve = keyType.slice("ecdsa-sha2-".length);
    bits = { nistp256: 256, nistp384: 384, nistp521: 521 }[curve] ?? null;
  } else if (keyType === "ssh-ed25519") {
    algorithm = "Ed25519";
    bits = 256;
    curve = "Ed25519";
  } else if (keyType === "ssh-dss") {
    algorithm = "DSA";
    bits = 1024;
  } else if (keyType.startsWith("sk-")) {
    // Claves FIDO: no son de host.
    return null;
  } else {
    algorithm = keyType.toUpperCase();
  }
  const fp = crypto.createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
  return { keyType, algorithm, bits, curve, fingerprintSha256: `SHA256:${fp}`, path: filePath };
}

export async function collectSshHostKeys(opts: { platform?: NodeJS.Platform; dirs?: string[]; listeningPorts?: number[]; hostname?: string } = {}): Promise<SshHostKeysResult> {
  const platform = opts.platform ?? os.platform();
  const dirs = opts.dirs ?? hostKeyDirs(platform);
  const keys: SshHostKey[] = [];
  let unreadable = 0;
  for (const dir of dirs) {
    let entries: string[];
    try {
      entries = fs.readdirSync(dir);
    } catch {
      continue; // sin sshd instalado no hay directorio: no es un fallo
    }
    for (const name of entries) {
      if (!/^ssh_host_.*_key\.pub$/.test(name)) continue;
      const full = path.join(dir, name);
      try {
        const k = parseSshPublicKey(fs.readFileSync(full, "utf8"), full);
        if (k) keys.push(k);
        else unreadable += 1;
      } catch {
        unreadable += 1;
      }
    }
  }
  const ports = opts.listeningPorts ?? [];
  return { host: opts.hostname ?? os.hostname(), keys, listening: ports.includes(22), unreadable };
}
