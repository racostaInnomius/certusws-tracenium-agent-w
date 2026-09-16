// src/plugins/cdp/providers/os-tls-capability.ts
//
// ¿Puede la pila TLS del PROPIO sistema negociar intercambio de clave
// híbrido post-cuántico (X25519MLKEM768)? Medido, no deducido (15-sep).
//
// ── Por qué medir ───────────────────────────────────────────────────
//
// El control plane deducía «SChannel puede» del número de build
// (10.0.26200 ≥ 26100). Pero los grupos ML-KEM llegaron a Windows 11 por
// una actualización acumulativa (26100.8514) y además se activan por
// política: dos equipos con el mismo build pueden estar en lados
// distintos, y el agente ni siquiera mandaba el número de revisión (UBR).
// Deducir de la versión era, en el mejor caso, «podría»; en el peor, un
// falso «no puede» para un equipo parcheado o un falso «puede» para uno
// sin parchear. Aquí se le pregunta al sistema.
//
// ── Cómo ────────────────────────────────────────────────────────────
//
// El agente levanta en 127.0.0.1 dos servidores TLS 1.3 efímeros con un
// certificado autofirmado de un solo uso:
//
//   - el de PRUEBA ofrece únicamente el grupo X25519MLKEM768;
//   - el de CONTROL ofrece X25519, para separar «no tiene el grupo» de
//     «no hace TLS 1.3 por esta vía».
//
// Y pide a la pila del sistema que se conecte a los dos. En Windows es
// SChannel a través de .NET (`SslStream` desde PowerShell, protocolo
// «el que decida el sistema»), que es exactamente lo que usan IIS, RDP,
// WinRM, LDAPS y HttpClient. Si el de prueba entra, el sistema soporta y
// tiene habilitado el grupo; si entra el de control y el de prueba no,
// no lo tiene (ausente o apagado por política); si no entra ninguno, no
// se sabe y se dice. macOS y Linux no se miden todavía: Network.framework
// no se puede invocar desde un script sin compilar, y en Linux no hay
// «la pila del sistema».
//
// El agente necesita un OpenSSL con el grupo (Node ≥ 22.21 / OpenSSL
// 3.5); si no lo tiene, el veredicto es null y se dice, como en la sonda.

import crypto from "crypto";
import net from "net";
import os from "os";
import tls from "tls";
import { execFile } from "child_process";
import { HYBRID_KEM_GROUP, kemProbeSupported } from "./tls-listeners";
import type { CdpOsTlsCapability } from "../../../domain/cdp-types";

export const CONTROL_GROUP = "X25519";
const LOOPBACK_SERVERNAME = "tracenium-loopback";
const HANDSHAKE_TIMEOUT_MS = 20_000;

// ── Certificado autofirmado efímero, sin dependencias ─────────────────
//
// Node no sabe emitir X.509. Una clave EC P-256 nueva por medición y un
// TBSCertificate mínimo escrito a mano: no sale de 127.0.0.1, el cliente
// no lo valida y muere con el proceso.

const tlv = (tag: number, content: Buffer): Buffer => {
  const n = content.length;
  let len: Buffer;
  if (n < 0x80) len = Buffer.from([n]);
  else if (n < 0x100) len = Buffer.from([0x81, n]);
  else if (n < 0x10000) len = Buffer.from([0x82, n >> 8, n & 0xff]);
  else len = Buffer.from([0x83, n >> 16, (n >> 8) & 0xff, n & 0xff]);
  return Buffer.concat([Buffer.from([tag]), len, content]);
};
const seq = (...parts: Buffer[]) => tlv(0x30, Buffer.concat(parts));
const set = (...parts: Buffer[]) => tlv(0x31, Buffer.concat(parts));
const der = {
  int: (v: Buffer) => tlv(0x02, v[0] & 0x80 ? Buffer.concat([Buffer.from([0]), v]) : v),
  oid: (s: string) => {
    const p = s.split(".").map(Number);
    const bytes: number[] = [p[0] * 40 + p[1]];
    for (const x of p.slice(2)) {
      const chunk: number[] = [x & 0x7f];
      let v = x >> 7;
      while (v > 0) {
        chunk.unshift((v & 0x7f) | 0x80);
        v >>= 7;
      }
      bytes.push(...chunk);
    }
    return tlv(0x06, Buffer.from(bytes));
  },
  utf8: (s: string) => tlv(0x0c, Buffer.from(s, "utf8")),
  utcTime: (d: Date) => tlv(0x17, Buffer.from(d.toISOString().replace(/^20|[-:T]|\.\d+Z$/g, "") + "Z", "ascii")),
  bitString: (b: Buffer) => tlv(0x03, Buffer.concat([Buffer.from([0]), b])),
  explicit: (n: number, content: Buffer) => tlv(0xa0 | n, content),
};

const OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const OID_CN = "2.5.4.3";

/** Un certificado EC P-256 autofirmado válido un día, en PEM, y su clave. */
export function makeEphemeralCertificate(now = new Date()): { keyPem: string; certPem: string; certDer: Buffer } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const name = seq(set(seq(der.oid(OID_CN), der.utf8(LOOPBACK_SERVERNAME))));
  const sigAlg = seq(der.oid(OID_ECDSA_SHA256));
  const notBefore = new Date(now.getTime() - 3600_000);
  const notAfter = new Date(now.getTime() + 86_400_000);
  const tbs = seq(
    der.explicit(0, der.int(Buffer.from([2]))),
    der.int(crypto.randomBytes(8)),
    sigAlg,
    name,
    seq(der.utcTime(notBefore), der.utcTime(notAfter)),
    name,
    spki
  );
  const signature = crypto.sign("sha256", tbs, privateKey);
  const certDer = seq(tbs, sigAlg, der.bitString(signature));
  const b64 = certDer.toString("base64").replace(/(.{64})/g, "$1\n").trimEnd();
  return {
    keyPem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    certPem: `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`,
    certDer,
  };
}

// ── Servidores de bucle local ─────────────────────────────────────────

export type LoopbackServer = {
  port: number;
  /** Grupos negociados por los clientes que llegaron a completar el handshake. */
  negotiated: string[];
  close: () => Promise<void>;
};

/** Un servidor TLS 1.3 en 127.0.0.1 que sólo acepta `group`. */
export async function startLoopbackServer(group: string, cert: { keyPem: string; certPem: string }): Promise<LoopbackServer> {
  const negotiated: string[] = [];
  const server = tls.createServer(
    { key: cert.keyPem, cert: cert.certPem, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ecdhCurve: group },
    (socket) => {
      // El servidor sólo admite `group`, así que un handshake completado
      // ES ese grupo. OpenSSL no siempre expone el KEM híbrido por
      // getEphemeralKeyInfo (lo da para ECDH clásico), de ahí el fallback.
      const info = socket.getEphemeralKeyInfo() as { name?: string } | null;
      negotiated.push(info?.name ? String(info.name) : group);
      socket.end();
    }
  );
  server.on("tlsClientError", () => undefined);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const port = (server.address() as net.AddressInfo).port;
  return {
    port,
    negotiated,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

// ── El cliente del sistema ────────────────────────────────────────────

export type SystemHandshake = {
  ok: boolean;
  /** Mensaje de la excepción cuando no entró. */
  error?: string | null;
  protocol?: string | null;
};

export type SystemClientResult = {
  hybrid: SystemHandshake;
  control: SystemHandshake;
  osBuild?: string | null;
  ubr?: number | null;
  displayVersion?: string | null;
  /** ADR-0024: si existen los cmdlets TLS (`Get-TlsEccCurve`…). */
  tlsCmdlets?: boolean | null;
  /** ADR-0024: la lista EFECTIVA de grupos, en orden (`Get-TlsEccCurve`). */
  eccCurves?: string[] | null;
  /** ADR-0024: una GPO «ECC Curve Order» gobierna la lista y pisaría un cambio local. */
  policyManaged?: boolean | null;
  policyCurves?: string[] | null;
  /** El script no corrió (PowerShell ausente, timeout, JSON ilegible). */
  runError?: string;
};

/** Lo que corre SChannel: .NET SslStream con el protocolo que decida el sistema. */
export function windowsScript(hybridPort: number, controlPort: number): string {
  return `
$ErrorActionPreference = 'Continue'
$o = [ordered]@{ hybrid = $null; control = $null; osBuild = $null; ubr = $null; displayVersion = $null; tlsCmdlets = $false; eccCurves = $null; policyManaged = $false; policyCurves = $null }
try {
  $k = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
  $o.osBuild = [string]$k.CurrentBuildNumber
  if ($null -ne $k.UBR) { $o.ubr = [int]$k.UBR }
  $o.displayVersion = [string]$k.DisplayVersion
} catch {}
# ADR-0024: la lista efectiva de grupos y si una GPO la gobierna. Solo se LEE.
try {
  if (Get-Command Get-TlsEccCurve -ErrorAction SilentlyContinue) {
    $o.tlsCmdlets = $true
    $o.eccCurves = @(Get-TlsEccCurve | ForEach-Object { [string]$_ })
  }
} catch {}
try {
  $gp = Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002' -ErrorAction Stop
  if ($null -ne $gp.EccCurves) {
    $o.policyManaged = $true
    $o.policyCurves = @($gp.EccCurves | ForEach-Object { [string]$_ })
  }
} catch {}
function Try-Handshake([int]$port) {
  $r = [ordered]@{ ok = $false; error = $null; protocol = $null }
  $c = $null; $s = $null
  try {
    $c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', $port)
    $cb = [System.Net.Security.RemoteCertificateValidationCallback]{ param($sender, $cert, $chain, $errors) return $true }
    $s = New-Object System.Net.Security.SslStream($c.GetStream(), $false, $cb)
    $s.AuthenticateAsClient('${LOOPBACK_SERVERNAME}', $null, [System.Security.Authentication.SslProtocols]::None, $false)
    $r.ok = $true
    $r.protocol = [string]$s.SslProtocol
  } catch {
    $r.error = [string]$_.Exception.GetBaseException().Message
  } finally {
    if ($s) { try { $s.Dispose() } catch {} }
    if ($c) { try { $c.Close() } catch {} }
  }
  return $r
}
$o.control = Try-Handshake ${controlPort}
$o.hybrid = Try-Handshake ${hybridPort}
$o | ConvertTo-Json -Compress -Depth 4
`;
}

function runPowerShell(script: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(script, "utf16le").toString("base64");
    execFile(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 1024 * 256 },
      (err, stdout) => (err ? reject(err) : resolve(String(stdout ?? "")))
    );
  });
}

/**
 * PowerShell 5.1 aplana a veces un array de un elemento a escalar al
 * serializar: se aceptan las dos formas. null si no vino.
 */
function stringList(v: unknown): string[] | null {
  if (v == null) return null;
  const arr = Array.isArray(v) ? v : [v];
  return arr.map((x) => String(x ?? "").trim()).filter(Boolean).slice(0, 64);
}

/** Puro: del JSON del script al resultado. Exportado para probar la forma sin PowerShell. */
export function parseSystemClientJson(j: any): Omit<SystemClientResult, "runError"> {
  return {
    hybrid: handshakeOf(j?.hybrid),
    control: handshakeOf(j?.control),
    osBuild: j?.osBuild ? String(j.osBuild) : null,
    ubr: Number.isInteger(j?.ubr) ? Number(j.ubr) : null,
    displayVersion: j?.displayVersion ? String(j.displayVersion) : null,
    tlsCmdlets: j?.tlsCmdlets === true ? true : j?.tlsCmdlets === false ? false : null,
    eccCurves: stringList(j?.eccCurves),
    policyManaged: j?.policyManaged === true ? true : j?.policyManaged === false ? false : null,
    policyCurves: stringList(j?.policyCurves),
  };
}

function handshakeOf(v: any): SystemHandshake {
  return { ok: v?.ok === true, error: v?.error ? String(v.error).slice(0, 300) : null, protocol: v?.protocol ? String(v.protocol) : null };
}

/** Lanza el script de Windows y lee su JSON. Nunca lanza: el fallo va en `runError`. */
export async function runWindowsSystemClient(hybridPort: number, controlPort: number): Promise<SystemClientResult> {
  const empty = { ok: false, error: null };
  try {
    const out = await runPowerShell(windowsScript(hybridPort, controlPort), HANDSHAKE_TIMEOUT_MS);
    const line = out.trim().split(/\r?\n/).filter((l) => l.trim().startsWith("{")).pop();
    if (!line) return { hybrid: empty, control: empty, runError: `no JSON from PowerShell: ${out.trim().slice(0, 200)}` };
    return parseSystemClientJson(JSON.parse(line));
  } catch (err: any) {
    return { hybrid: empty, control: empty, runError: String(err?.message || err).slice(0, 300) };
  }
}

// ── Veredicto ─────────────────────────────────────────────────────────

/**
 * Puro: de lo que hicieron los dos handshakes al veredicto. `hybridSeen`
 * es lo que el servidor de prueba vio negociar de verdad; el «ok» del
 * cliente sin ese eco no vale (sería fiarse del que se examina).
 */
export function verdictFrom(client: SystemClientResult, hybridSeen: string[]): Pick<CdpOsTlsCapability, "supported" | "detail" | "error"> {
  if (client.runError) return { supported: null, detail: "The system TLS client could not be exercised.", error: client.runError };
  const sawHybrid = hybridSeen.some((g) => /MLKEM/i.test(g));
  if (client.hybrid.ok && sawHybrid) return { supported: true, detail: `The system TLS stack negotiated ${HYBRID_KEM_GROUP} on a loopback handshake (${client.hybrid.protocol || "TLS 1.3"}).` };
  if (client.control.ok) {
    return {
      supported: false,
      detail: `The system TLS stack completed TLS 1.3 with ${CONTROL_GROUP} but refused a server offering only ${HYBRID_KEM_GROUP}: the group is absent or disabled by policy.`,
      error: client.hybrid.error ?? null,
    };
  }
  return {
    supported: null,
    detail: `The system TLS client could not complete TLS 1.3 on loopback even with ${CONTROL_GROUP}; nothing can be said about ${HYBRID_KEM_GROUP}.`,
    error: client.control.error ?? client.hybrid.error ?? null,
  };
}

export type MeasureOptions = {
  platform?: NodeJS.Platform;
  /** Test seam: el cliente del sistema. */
  systemClient?: (hybridPort: number, controlPort: number) => Promise<SystemClientResult>;
  now?: () => Date;
};

/** La medición completa. Nunca lanza: un fallo es un veredicto null con motivo. */
export async function measureOsTlsCapability(options: MeasureOptions = {}): Promise<CdpOsTlsCapability> {
  const platform = options.platform ?? os.platform();
  const now = options.now ?? (() => new Date());
  const base: CdpOsTlsCapability = {
    platform: platform === "win32" ? "windows" : platform === "darwin" ? "macos" : "linux",
    group: HYBRID_KEM_GROUP,
    supported: null,
    method: "not_measured",
    measuredAt: now().toISOString(),
  };
  if (platform !== "win32") {
    return { ...base, detail: platform === "darwin" ? "Network.framework cannot be exercised from a script; the build-number rule applies." : "Linux has no single system TLS stack; the OpenSSL rule applies." };
  }
  if (!kemProbeSupported()) {
    return { ...base, method: "agent_openssl_lacks_group", detail: "This agent's OpenSSL cannot offer the group, so the system could not be tested." };
  }

  let hybrid: LoopbackServer | null = null;
  let control: LoopbackServer | null = null;
  try {
    const cert = makeEphemeralCertificate(now());
    hybrid = await startLoopbackServer(HYBRID_KEM_GROUP, cert);
    control = await startLoopbackServer(CONTROL_GROUP, cert);
    const client = await (options.systemClient ?? runWindowsSystemClient)(hybrid.port, control.port);
    // En TLS 1.3 el cliente termina antes de que el servidor procese su
    // Finished: un respiro para que el servidor anote lo negociado.
    await new Promise((r) => setTimeout(r, 150));
    const verdict = verdictFrom(client, hybrid.negotiated);
    return {
      ...base,
      method: "loopback_schannel",
      ...verdict,
      ...(client.osBuild ? { osBuild: client.osBuild } : {}),
      ...(client.ubr != null ? { ubr: client.ubr } : {}),
      ...(client.displayVersion ? { displayVersion: client.displayVersion } : {}),
      ...(client.tlsCmdlets != null ? { tlsCmdlets: client.tlsCmdlets } : {}),
      ...(client.eccCurves ? { eccCurves: client.eccCurves } : {}),
      ...(client.policyManaged != null ? { policyManaged: client.policyManaged } : {}),
      ...(client.policyCurves ? { policyCurves: client.policyCurves } : {}),
    };
  } catch (err: any) {
    return { ...base, method: "loopback_schannel", detail: "The loopback test could not be set up.", error: String(err?.message || err).slice(0, 300) };
  } finally {
    await hybrid?.close().catch(() => undefined);
    await control?.close().catch(() => undefined);
  }
}
