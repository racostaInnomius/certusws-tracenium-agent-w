// src/plugins/cdp/adcs-csv.ts
//
// Parser de la salida de `certutil -view` (conector AD CS, fase 4).
//
// ── Por que el VOLCADO y no el CSV ────────────────────────────────────
//
// Medido en MSIG-RADIUS-CA (2026-09-07): en modo `csv` certutil imprime
// las columnas binarias como su tamano —«1657 Bytes»— y NO el
// certificado. El CSV sirve para los metadatos, pero sin RawCertificate
// no hay huella, ni clave, ni fecha. El volcado por filas (sin `csv`) si
// imprime el binario como PEM. Asi que se lee el volcado:
//
//   Schema:                              ← preambulo, se ignora
//     Column Name   Localized Name  Type  MaxLength
//     RequestID     Issued Request ID  Long  4 -- Indexed
//     …
//   Row 1:                               ← numero de fila, NO el RequestId
//     Issued Request ID: 0x2             ← solo hex
//     Request Disposition: 0x14 (20) -- Issued
//     Requester Name: "MOUNTAINSIDE\MSIG-RADIUS$"
//     Certificate Template: "1.3.6.1.4.1.311.21.8.…207.1845288.9471314" NetworkPolicyServer
//     Binary Certificate:
//   -----BEGIN CERTIFICATE-----
//   MIIG…
//   -----END CERTIFICATE-----
//
//   Maximum Row Index: 2                 ← cola, se ignora
//   2 Rows
//   CertUtil: -view command completed successfully.
//
// Formato MEDIDO en MSIG-RADIUS-CA el 2026-09-07 (dos filas reales). Puro:
// sin IPC ni ficheros, para probarlo con un fixture. Los campos se asignan
// por ORDEN dentro de cada fila, que es el orden de `-out` (fijo en
// CdpAdcs.cs); los nombres en ingles solo confirman. Asi una CA en otro
// idioma («Id. de solicitud emitida») se lee igual y se marca `positional`.
// La disposicion: «20 -- Issued» / «21 -- Revoked» / «15 -- CA Cert» /
// «30 -- Error»; la plantilla: «"<OID>" <nombre>» o «"<nombre>"» («Machine»).

import { parseCertToItem } from "./parse-cert";
import type { CdpCertItem, CdpStoreInfo } from "../../domain/cdp-types";

export type AdcsIssued = CdpCertItem & {
  requestId: number;
  /** 15 = cert de la propia CA, 20 = emitido, 21 = revocado, 30/31 = error/denegado (sin cert). */
  disposition: number | null;
  requester?: string;
  template?: string;
  templateOid?: string;
};

export type AdcsParseResult = {
  /** Etiquetas de columna tal como llegaron (primera fila), para el log. */
  header: string[];
  issued: AdcsIssued[];
  parseFailures: number;
  lastRequestId: number;
  columnsFound: { requestId: boolean; disposition: boolean; requester: boolean; template: boolean; rawCertificate: boolean; positional: boolean };
};

type Field = { label: string; value: string };
type Row = { fields: Field[]; pem: string | null };

const ROW_RE = /^Row\s+(\d+)\s*:/i;
const FIELD_RE = /^\s{1,8}([^:]{1,80}):\s?(.*)$/;

/** Nombres en ingles conocidos → indice esperado en el orden de -out. */
const KNOWN: Array<{ idx: number; names: string[] }> = [
  { idx: 0, names: ["issuedrequestid", "requestid", "requestidissued"] },
  { idx: 1, names: ["requestdisposition", "disposition"] },
  { idx: 2, names: ["requestername", "requestrequestername"] },
  { idx: 3, names: ["certificatetemplate"] },
  { idx: 4, names: ["binarycertificate", "rawcertificate"] }
];
const norm = (s: string) => s.toLowerCase().replace(/[\s._"]/g, "");

/** Separa el volcado en filas; dentro de cada una, campos en orden y el PEM. */
export function splitCertutilDump(text: string): Row[] {
  const rows: Row[] = [];
  let cur: Row | null = null;
  let pemLines: string[] | null = null;
  const lines = text.replace(/^﻿/, "").split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.replace(/\s+$/, "");
    if (ROW_RE.test(line)) {
      if (cur) rows.push(cur);
      cur = { fields: [], pem: null };
      pemLines = null;
      continue;
    }
    if (!cur) continue;
    if (pemLines) {
      pemLines.push(line.replace(/^"|"$/g, ""));
      if (/-----END CERTIFICATE-----/.test(line)) {
        cur.pem = pemLines.join("\n") + "\n";
        pemLines = null;
      }
      continue;
    }
    if (/-----BEGIN CERTIFICATE-----/.test(line)) {
      pemLines = [line.replace(/^"|"$/g, "")];
      continue;
    }
    const m = FIELD_RE.exec(line);
    if (m) {
      cur.fields.push({ label: m[1].trim(), value: m[2].trim() });
    }
  }
  if (cur) rows.push(cur);
  return rows;
}

/**
 * «0x14 (20) -- Issued» → 20; «0x2» → 2 (el RequestId sale SOLO en hex,
 * medido); «20 -- Issued» → 20; «"x"» → null.
 */
function parseNumber(v: string): number | null {
  const paren = /\((\d+)\)/.exec(v);
  if (paren) return Number(paren[1]);
  const hex = /^\s*0x([0-9a-f]+)\b/i.exec(v);
  if (hex) return parseInt(hex[1], 16);
  const lead = /^\s*(\d+)\b/.exec(v);
  if (lead) return Number(lead[1]);
  return null;
}
/** Quita TODAS las comillas: la plantilla sale como «"<OID>" <nombre>», con
 *  comillas solo alrededor del OID (medido en MSIG-RADIUS-CA). */
const unquote = (v: string) => v.replace(/"/g, "").trim();

export function parseCertutilDump(text: string, caName: string, max = 5000): AdcsParseResult {
  const rows = splitCertutilDump(text);
  const header = rows[0]?.fields.map((f) => f.label) ?? [];
  // Orden fijo de -out: si las etiquetas son las inglesas conocidas se
  // confirma; si no (localizadas), se asigna por posicion y se dice.
  const byName = (row: Row, idx: number): Field | undefined =>
    row.fields.find((f) => KNOWN[idx].names.includes(norm(f.label)));
  const labelsKnown = header.length >= 4 && KNOWN.slice(0, 4).every((k) => header.some((h) => k.names.includes(norm(h))));
  const positional = !labelsKnown && header.length >= 4;
  const pick = (row: Row, idx: number): string | undefined =>
    (labelsKnown ? byName(row, idx) : row.fields[idx])?.value;

  const columnsFound = {
    requestId: rows.some((r) => pick(r, 0) != null),
    disposition: rows.some((r) => pick(r, 1) != null),
    requester: rows.some((r) => pick(r, 2) != null),
    template: rows.some((r) => pick(r, 3) != null),
    rawCertificate: rows.some((r) => r.pem != null),
    positional
  };

  const store: CdpStoreInfo = { id: `adcs/${caName}`, name: caName, scope: "network" };
  const issued: AdcsIssued[] = [];
  let parseFailures = 0;
  let lastRequestId = 0;

  if (rows.length === 0 || !columnsFound.requestId) {
    return { header, issued, parseFailures: rows.length, lastRequestId, columnsFound };
  }

  for (const r of rows) {
    if (issued.length >= max) break;
    const requestId = parseNumber(pick(r, 0) ?? "");
    if (requestId == null || !Number.isInteger(requestId) || requestId <= 0) continue;
    lastRequestId = Math.max(lastRequestId, requestId);
    const disposition = parseNumber(pick(r, 1) ?? "");
    if (!r.pem) {
      // Denegadas (31), con error (30) y pendientes no traen certificado:
      // no es un fallo. Emitidas (20), revocadas (21) o el propio cert de
      // la CA (15) sin PEM si lo son.
      if (disposition != null && disposition !== 15 && disposition !== 20 && disposition !== 21) continue;
      parseFailures += 1;
      continue;
    }
    const item = parseCertToItem(r.pem, { store, hasPrivateKey: false });
    if (!item) {
      parseFailures += 1;
      continue;
    }
    item.source = "adcs";
    item.hasPrivateKey = false;
    const requester = unquote(pick(r, 2) ?? "");
    const templateRaw = unquote(pick(r, 3) ?? "");
    // «<OID> <nombre>» o solo «<nombre>»; EMPTY = sin plantilla (cert de CA).
    const tm = /^(\d+(?:\.\d+)+)\s+(.+)$/.exec(templateRaw);
    const template = templateRaw && templateRaw !== "EMPTY" ? (tm ? tm[2] : templateRaw).slice(0, 256) : undefined;
    const templateOid = tm ? tm[1].slice(0, 128) : undefined;
    issued.push({
      ...item,
      requestId,
      disposition,
      ...(requester && requester !== "EMPTY" ? { requester: requester.slice(0, 256) } : {}),
      ...(template ? { template } : {}),
      ...(templateOid ? { templateOid } : {})
    });
  }
  return { header, issued, parseFailures, lastRequestId, columnsFound };
}
