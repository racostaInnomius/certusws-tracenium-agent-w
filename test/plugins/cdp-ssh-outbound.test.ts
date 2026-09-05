// test/plugins/cdp-ssh-outbound.test.ts
//
// §5.2: claves de host SSH (de disco, sin tocar la red) y candidatos a
// objetivo de sonda (conexiones salientes a servicios TLS internos).

import { describe, it, expect } from "vitest";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import { parseSshPublicKey, collectSshHostKeys } from "../../src/plugins/cdp/providers/ssh-host-keys";
import { candidatesFromConnections, isPrivateAddress, CANDIDATE_PORTS } from "../../src/plugins/cdp/providers/outbound-tls";

const sshString = (b: Buffer) => Buffer.concat([Buffer.from([0, 0, 0, b.length >> 24 & 0xff, (b.length >> 16) & 0xff, (b.length >> 8) & 0xff, b.length & 0xff].slice(-4)), b]);
const field = (b: Buffer) => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length, 0);
  return Buffer.concat([len, b]);
};
const mpint = (b: Buffer) => (b[0] & 0x80 ? field(Buffer.concat([Buffer.from([0]), b])) : field(b));

function rsaPubLine(bits: number): { line: string; expectedFp: string } {
  const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: bits });
  const jwk = publicKey.export({ format: "jwk" }) as any;
  const blob = Buffer.concat([field(Buffer.from("ssh-rsa")), mpint(Buffer.from(jwk.e, "base64url")), mpint(Buffer.from(jwk.n, "base64url"))]);
  return { line: `ssh-rsa ${blob.toString("base64")} root@host`, expectedFp: "SHA256:" + crypto.createHash("sha256").update(blob).digest("base64").replace(/=+$/, "") };
}

function ed25519PubLine(): string {
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as any;
  const blob = Buffer.concat([field(Buffer.from("ssh-ed25519")), field(Buffer.from(jwk.x, "base64url"))]);
  return `ssh-ed25519 ${blob.toString("base64")}`;
}

describe("parseSshPublicKey", () => {
  it("⭐ RSA: tipo, bits del modulo y huella SHA256 como ssh-keygen", () => {
    const { line, expectedFp } = rsaPubLine(2048);
    const k = parseSshPublicKey(line, "/etc/ssh/ssh_host_rsa_key.pub")!;
    expect(k).toEqual(expect.objectContaining({ keyType: "ssh-rsa", algorithm: "RSA", bits: 2048, fingerprintSha256: expectedFp, path: "/etc/ssh/ssh_host_rsa_key.pub" }));
    expect(parseSshPublicKey(rsaPubLine(3072).line)!.bits).toBe(3072);
  });

  it("Ed25519 y ECDSA; una linea rota o una clave FIDO se descartan", () => {
    expect(parseSshPublicKey(ed25519PubLine())).toEqual(expect.objectContaining({ algorithm: "Ed25519", bits: 256 }));
    const ec = Buffer.concat([field(Buffer.from("ecdsa-sha2-nistp384")), field(Buffer.from("nistp384")), field(Buffer.alloc(97, 4))]);
    expect(parseSshPublicKey(`ecdsa-sha2-nistp384 ${ec.toString("base64")}`)).toEqual(expect.objectContaining({ algorithm: "EC", bits: 384, curve: "nistp384" }));
    expect(parseSshPublicKey("garbage")).toBeNull();
    expect(parseSshPublicKey("ssh-rsa notbase64!!")).toBeNull();
    const sk = Buffer.concat([field(Buffer.from("sk-ssh-ed25519@openssh.com")), field(Buffer.alloc(32))]);
    expect(parseSshPublicKey(`sk-ssh-ed25519@openssh.com ${sk.toString("base64")}`)).toBeNull();
  });
  void sshString;
});

describe("collectSshHostKeys", () => {
  it("lee los ssh_host_*_key.pub del directorio, ignora lo demas, y dice si sshd escucha", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-ssh-"));
    try {
      fs.writeFileSync(path.join(dir, "ssh_host_rsa_key.pub"), rsaPubLine(2048).line);
      fs.writeFileSync(path.join(dir, "ssh_host_ed25519_key.pub"), ed25519PubLine());
      fs.writeFileSync(path.join(dir, "ssh_host_rsa_key"), "PRIVATE-NEVER-READ");
      fs.writeFileSync(path.join(dir, "ssh_host_dsa_key.pub"), "broken line");
      const r = await collectSshHostKeys({ dirs: [dir], listeningPorts: [22, 443], hostname: "srv-01" });
      expect(r.host).toBe("srv-01");
      expect(r.listening).toBe(true);
      expect(r.keys.map((k) => k.algorithm).sort()).toEqual(["Ed25519", "RSA"]);
      expect(r.unreadable).toBe(1);
      expect(JSON.stringify(r)).not.toContain("PRIVATE-NEVER-READ");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    const none = await collectSshHostKeys({ dirs: ["/nonexistent/ssh"], listeningPorts: [] });
    expect(none.keys).toEqual([]);
    expect(none.listening).toBe(false);
  });
});

describe("candidatos a objetivo de sonda", () => {
  const conn = (peer: string, port: number, over: any = {}) => ({ protocol: "tcp", peerAddress: peer, peerPort: String(port), state: "ESTABLISHED", process: "chrome", ...over });

  it("⭐ solo destinos privados, en puertos TLS, establecidos; agrega por host:puerto", () => {
    const out = candidatesFromConnections([
      conn("10.0.0.5", 443), conn("10.0.0.5", 443, { process: "java" }), conn("10.0.0.5", 636),
      conn("192.168.1.20", 5432), conn("172.16.9.1", 8443),
      conn("142.250.1.1", 443), // publico: fuera
      conn("10.0.0.7", 80), // no TLS
      conn("10.0.0.8", 443, { state: "TIME_WAIT" }),
      conn("127.0.0.1", 443),
      conn("10.0.0.9", 443, { protocol: "udp" })
    ]);
    expect(out.map((c) => `${c.host}:${c.port}=${c.connections}`)).toEqual(["10.0.0.5:443=2", "10.0.0.5:636=1", "172.16.9.1:8443=1", "192.168.1.20:5432=1"]);
    expect(out[0].process).toBe("chrome");
  });

  it("IPv6 privado y mapeado IPv4; RFC 6598; nada publico", () => {
    expect(isPrivateAddress("fd12::1")).toBe(true);
    expect(isPrivateAddress("::ffff:10.1.1.1")).toBe(true);
    expect(isPrivateAddress("100.64.0.1")).toBe(true);
    expect(isPrivateAddress("8.8.8.8")).toBe(false);
    expect(isPrivateAddress("2001:db8::1")).toBe(false);
    expect(CANDIDATE_PORTS.has(6443)).toBe(true);
    expect(CANDIDATE_PORTS.has(80)).toBe(false);
  });
});
