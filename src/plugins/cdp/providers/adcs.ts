// src/plugins/cdp/providers/adcs.ts
//
// Conector AD CS (fase 4): si este equipo es una Certification Authority
// de Windows y la policy lo pide, lee su base de emisiones por el
// PrivSvc y la reporta como un bloque propio del namespace CDP.
//
// ── Por que un bloque aparte y no `certificates.items` ──────────────
//
// Lo que la CA ha emitido NO esta en este equipo. Meterlo en la lista de
// certificados del equipo lo convertiria en «un certificado EN
// MSIG-RADIUS-CA», y el embudo de propiedad, las alertas de caducidad y
// el rescan actuarian sobre algo que no vive ahi. El control plane lo
// proyecta a `cdp_crypto_assets` con origen `adcs`, junto a lo que llega
// por CBOM: activos que sabemos que existen sin haberlos visto en un
// almacen.
//
// ── Incremental ─────────────────────────────────────────────────────
//
// Una CA RADIUS emite un certificado por equipo y por renovacion; la base
// crece sin parar. Se lee por RequestID desde el ultimo visto (guardado
// en SQLite) y con tope por escaneo. El primer escaneo trae los ultimos
// N; el resto llega en escaneos sucesivos, hasta ponerse al dia.

import type { AgentContext } from "../../../core/agent-context";
import type { CdpAdcsReport } from "../../../domain/cdp-types";
import { parseCertutilCsv } from "../adcs-csv";
import { readAdcsCursor, writeAdcsCursor } from "../../../domain/cdp-adcs-repo";

type Options = {
  /** Test seam. */
  call?: (params: { sinceRequestId: number; maxRows: number }) => Promise<any>;
};

export async function collectAdcs(ctx: AgentContext, options: Options = {}): Promise<CdpAdcsReport | undefined> {
  const cfg = ctx.policyRuntime.getCdpAdcs?.();
  if (!cfg?.enabled) return undefined;
  const maxRows = Math.min(Math.max(Number(cfg.maxPerScan) || 2000, 50), 5000);

  const call =
    options.call ??
    (async (params) =>
      ctx.priv.call({
        v: 1,
        id: `cdpadcs_${Date.now()}`,
        method: "cdp.adcs.read",
        params,
        meta: { tenantId: ctx.enrollment?.tenantId, deviceId: ctx.enrollment?.deviceId }
      }));

  // El cursor es por CA, y la CA no se sabe hasta que el PrivSvc contesta.
  // Primera llamada con el cursor «anonimo» (0 si es la primera vez).
  const sinceFirst = readAdcsCursor("*");
  const resp = await call({ sinceRequestId: sinceFirst, maxRows });
  if (!resp?.ok) {
    if (resp?.error?.code !== "not_supported") {
      ctx.logger?.warn?.("CDP/ADCS: lectura fallida", { code: resp?.error?.code, message: resp?.error?.message });
    }
    return undefined;
  }
  const res = resp.result || {};
  if (res.isCa !== true) {
    return { isCa: false, caName: null, sinceRequestId: 0, lastRequestId: 0, issued: [], truncated: false, parseFailures: 0, columnsFound: null };
  }

  const caName = String(res.caName || "unknown-ca").slice(0, 200);
  const parsed = parseCertutilCsv(String(res.csv || ""), caName, maxRows);
  if (!parsed.columnsFound.requestId || !parsed.columnsFound.rawCertificate) {
    // La cabecera no es la esperada: se dice con la cabecera recibida, que
    // es lo unico que permite arreglar el parser sin ir al servidor.
    ctx.logger?.warn?.("CDP/ADCS: cabecera de certutil no reconocida", { header: parsed.header.slice(0, 12), stderr: res.stderr });
  }
  if (parsed.lastRequestId > 0) {
    writeAdcsCursor("*", parsed.lastRequestId);
    writeAdcsCursor(caName, parsed.lastRequestId);
  }
  ctx.logger?.info?.("CDP/ADCS: emisiones leidas", {
    caName, since: sinceFirst, rows: res.rows, issued: parsed.issued.length, parseFailures: parsed.parseFailures, truncated: res.truncated === true
  });
  return {
    isCa: true,
    caName,
    sinceRequestId: sinceFirst,
    lastRequestId: parsed.lastRequestId,
    issued: parsed.issued,
    truncated: res.truncated === true,
    parseFailures: parsed.parseFailures,
    columnsFound: parsed.columnsFound
  };
}
