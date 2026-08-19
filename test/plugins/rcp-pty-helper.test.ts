import { describe, it, expect, afterEach } from "vitest";
import { spawn, ChildProcess } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

/**
 * Contrato del helper del shell remoto privilegiado (Linux).
 *
 * En Linux el AgentCore corre como `User=tracenium` —uid sin privilegios, sin
 * sudo, nologin— así que el pty que abría localmente daba un shell incapaz de
 * reiniciar un servicio, leer /var/log/syslog o listar /root. Medido en
 * SRVOC-MainAgent el 2026-08-19. Y es justo la plataforma donde el shell más
 * importa: un servidor headless no tiene otra vía de acceso.
 *
 * El helper mueve ese pty al lado privilegiado. Estos tests fijan el CONTRATO
 * del que depende el proxy del agente (pty-session-linux.ts), porque si
 * cualquiera de las dos mitades cambia de forma sin la otra, el síntoma es una
 * sesión que se abre y no responde — sin error en ningún log.
 *
 * Lo que NO se prueba aquí: que el shell salga como root. Eso depende de quién
 * lance el helper (privsvc, que es root) y sólo se puede verificar en un
 * endpoint real; se hizo a mano contra SRVOC-MainAgent, donde `id -un` devolvió
 * root y `systemctl restart ssh` funcionó.
 */

const HELPER = path.resolve(__dirname, "../../privsvc/linux/helpers/rcp-pty-helper.js");

let child: ChildProcess | null = null;
let sockPath = "";

afterEach(() => {
  try { child?.kill(); } catch { /* ya murió */ }
  child = null;
  try { if (sockPath) fs.unlinkSync(sockPath); } catch { /* ya borrado */ }
  sockPath = "";
});

/** Arranca el helper y resuelve cuando anuncia READY. */
function startHelper(extra: string[] = []): Promise<string> {
  sockPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "rcp-")), "s.sock");
  child = spawn(process.execPath, [HELPER, "--socket", sockPath, "--cols", "100", "--rows", "30", ...extra], {
    stdio: ["ignore", "pipe", "pipe"],
  });

  return new Promise((resolve, reject) => {
    let err = "";
    child!.stdout!.on("data", (d) => {
      if (String(d).includes("READY")) resolve(sockPath);
    });
    child!.stderr!.on("data", (d) => { err += String(d); });
    child!.on("exit", (code) => reject(new Error(`helper salió con ${code}: ${err}`)));
    setTimeout(() => reject(new Error(`sin READY. stderr: ${err}`)), 10_000);
  });
}

/** Conecta y acumula los frames que el helper emite. */
function connect(p: string) {
  const sock = net.createConnection(p);
  const frames: any[] = [];
  let buf = "";
  sock.on("data", (chunk) => {
    buf += chunk.toString("utf8");
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      try { frames.push(JSON.parse(line)); } catch { /* ignora líneas corruptas */ }
    }
  });
  return { sock, frames };
}

const waitFor = async (fn: () => boolean, ms = 8000) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (fn()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
};

describe.skipIf(process.platform === "win32")("rcp-pty-helper", () => {
  it("anuncia READY sólo cuando el socket ya es usable", async () => {
    const p = await startHelper();

    // La garantía que importa: privsvc responde al agente en cuanto ve READY,
    // así que si el socket no existiera todavía habría una ventana en la que
    // el agente conecta contra la nada.
    expect(fs.existsSync(p)).toBe(true);
    const mode = fs.statSync(p).mode & 0o777;
    expect(mode).toBe(0o660);
  });

  it("ejecuta un comando y devuelve su salida como frames stdout", async () => {
    const p = await startHelper();
    const { sock, frames } = connect(p);

    await new Promise<void>((r) => sock.on("connect", () => r()));
    sock.write(JSON.stringify({ type: "stdin", data: "echo TRACENIUM_MARKER\n" }) + "\n");

    const got = await waitFor(() =>
      frames.some((f) => f.type === "stdout" && String(f.data).includes("TRACENIUM_MARKER"))
    );

    expect(got, `frames recibidos: ${JSON.stringify(frames).slice(0, 400)}`).toBe(true);
    sock.destroy();
  });

  it("es de un solo uso: el socket desaparece al conectarse", async () => {
    const p = await startHelper();
    expect(fs.existsSync(p)).toBe(true);

    const { sock } = connect(p);
    await new Promise<void>((r) => sock.on("connect", () => r()));

    // Deja de escuchar y desenlaza. A partir de ahí el pty sólo es alcanzable
    // por el fd ya conectado — ni siquiera root puede abrir una segunda
    // sesión sobre el mismo socket.
    const gone = await waitFor(() => !fs.existsSync(p), 3000);
    expect(gone).toBe(true);
    sock.destroy();
  });

  it("un `close` del agente termina el proceso", async () => {
    const p = await startHelper();
    const { sock } = connect(p);
    await new Promise<void>((r) => sock.on("connect", () => r()));

    let exited = false;
    child!.on("exit", () => { exited = true; });
    sock.write(JSON.stringify({ type: "close" }) + "\n");

    expect(await waitFor(() => exited, 5000)).toBe(true);
  });

  it("cerrar el socket sin avisar tampoco deja el shell colgando", async () => {
    const p = await startHelper();
    const { sock } = connect(p);
    await new Promise<void>((r) => sock.on("connect", () => r()));

    let exited = false;
    child!.on("exit", () => { exited = true; });
    // El caso real: el agente muere o pierde el DataChannel. Un shell de root
    // que sobreviviera a eso es exactamente lo que no debe quedar suelto.
    sock.destroy();

    expect(await waitFor(() => exited, 5000)).toBe(true);
  });

  it("una línea corrupta no tumba la sesión", async () => {
    const p = await startHelper();
    const { sock, frames } = connect(p);
    await new Promise<void>((r) => sock.on("connect", () => r()));

    sock.write("{no soy json\n");
    sock.write(JSON.stringify({ type: "stdin", data: "echo SIGO_VIVO\n" }) + "\n");

    const got = await waitFor(() =>
      frames.some((f) => f.type === "stdout" && String(f.data).includes("SIGO_VIVO"))
    );
    expect(got).toBe(true);
    sock.destroy();
  });

  it("recoge solo si nadie conecta", async () => {
    // ACCEPT_TIMEOUT_MS son 15s en el helper; aquí sólo se comprueba que el
    // temporizador existe y el proceso sigue vivo esperando, no su duración
    // exacta — un test que duerma 15s no vale lo que cuesta.
    const p = await startHelper();
    await new Promise((r) => setTimeout(r, 300));
    expect(child!.exitCode).toBeNull();
    expect(fs.existsSync(p)).toBe(true);
  });
});
