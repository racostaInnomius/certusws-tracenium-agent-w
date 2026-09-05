// src/plugins/cdp/adcs-csv.ts
//
// Parser del CSV de `certutil -view -csv` (conector AD CS, fase 4).
//
// Puro: sin IPC ni ficheros, para probarlo con un fixture. Lo que sabe
// hacer: CSV con campos entre comillas que pueden ocupar VARIAS lineas
// (RawCertificate es un PEM), cabecera con los nombres de columna tal
// como certutil los pinta, y filas con RequestID numerico.
//
// ⚠️ Escrito contra la documentacion, no contra una CA real. Por eso la
// cabecera que se recibio viaja en el resultado: si el nombre de una
// columna no es el esperado, se ve en el log del agente y en el payload,
// no en un cero silencioso.

import { parseCertToItem } from "./parse-cert";
import type { CdpCertItem, CdpStoreInfo } from "../../domain/cdp-types";

export type CertutilRow = Record<string, string>;

/** RFC 4180 con comillas dobles y saltos de linea dentro de campos. */
export function parseCsv(text: string): { header: string[]; rows: string[][] } {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  const src = text.replace(/^﻿/, "");
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (inQuotes) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === '"') inQuotes = true;
    else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && src[i + 1] === "\n") i += 1;
      row.push(field);
      field = "";
      if (row.some((f) => f.trim() !== "")) rows.push(row);
      row = [];
    } else field += ch;
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    if (row.some((f) => f.trim() !== "")) rows.push(row);
  }
  const header = (rows.shift() || []).map((h) => h.trim());
  return { header, rows };
}

/** Localiza una columna por varios nombres posibles (certutil los muestra
 *  localizados y con espacios). Case-insensitive, sin espacios ni puntos. */
function findCol(header: string[], ...names: string[]): number {
  const norm = (s: string) => s.toLowerCase().replace(/[\s.]/g, "");
  const wanted = names.map(norm);
  return header.findIndex((h) => wanted.includes(norm(h)));
}

export type AdcsIssued = CdpCertItem & {
  requestId: number;
  /** 20 = emitido, 21 = revocado, 30/31 = denegado/error (no traen cert). */
  disposition: number | null;
  requester?: string;
  template?: string;
};

export type AdcsParseResult = {
  header: string[];
  issued: AdcsIssued[];
  parseFailures: number;
  lastRequestId: number;
  columnsFound: { requestId: boolean; disposition: boolean; requester: boolean; template: boolean; rawCertificate: boolean };
};

/** Base64 con o sin cabeceras PEM y con saltos de linea → PEM limpio. */
function toPem(raw: string): string | null {
  const b64 = raw.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/[^A-Za-z0-9+/=]/g, "");
  if (b64.length < 64) return null;
  return `-----BEGIN CERTIFICATE-----\n${b64.replace(/(.{64})/g, "$1\n")}\n-----END CERTIFICATE-----\n`;
}

export function parseCertutilCsv(text: string, caName: string, max = 5000): AdcsParseResult {
  const { header, rows } = parseCsv(text);
  const iReq = findCol(header, "RequestID", "Request ID", "Issued Request ID");
  const iDisp = findCol(header, "Request.Disposition", "Request Disposition", "Disposition");
  const iWho = findCol(header, "Request.RequesterName", "Requester Name", "RequesterName");
  const iTpl = findCol(header, "CertificateTemplate", "Certificate Template");
  const iRaw = findCol(header, "RawCertificate", "Binary Certificate", "Raw Certificate");
  const columnsFound = { requestId: iReq >= 0, disposition: iDisp >= 0, requester: iWho >= 0, template: iTpl >= 0, rawCertificate: iRaw >= 0 };

  const store: CdpStoreInfo = { id: `adcs/${caName}`, name: caName, scope: "network" };
  const issued: AdcsIssued[] = [];
  let parseFailures = 0;
  let lastRequestId = 0;

  if (iReq < 0 || iRaw < 0) {
    return { header, issued, parseFailures: rows.length, lastRequestId, columnsFound };
  }

  for (const r of rows) {
    if (issued.length >= max) break;
    const requestId = Number(String(r[iReq] || "").trim());
    if (!Number.isInteger(requestId) || requestId <= 0) continue;
    lastRequestId = Math.max(lastRequestId, requestId);
    const pem = toPem(String(r[iRaw] || ""));
    if (!pem) {
      // Denegadas / pendientes no traen certificado: no es un fallo.
      const disp = iDisp >= 0 ? Number(String(r[iDisp] || "").replace(/\D/g, "")) : NaN;
      if (Number.isFinite(disp) && disp !== 20 && disp !== 21) continue;
      parseFailures += 1;
      continue;
    }
    const item = parseCertToItem(pem, { store, hasPrivateKey: false });
    if (!item) {
      parseFailures += 1;
      continue;
    }
    item.source = "adcs";
    item.hasPrivateKey = false;
    const dispRaw = iDisp >= 0 ? String(r[iDisp] || "") : "";
    const dispNum = Number(dispRaw.replace(/\D/g, ""));
    issued.push({
      ...item,
      requestId,
      disposition: Number.isFinite(dispNum) && dispRaw !== "" ? dispNum : null,
      ...(iWho >= 0 && r[iWho] ? { requester: String(r[iWho]).trim().slice(0, 256) } : {}),
      ...(iTpl >= 0 && r[iTpl] ? { template: String(r[iTpl]).trim().slice(0, 256) } : {})
    });
  }
  return { header, issued, parseFailures, lastRequestId, columnsFound };
}
