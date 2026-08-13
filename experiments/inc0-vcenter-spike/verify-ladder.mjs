#!/usr/bin/env node
// ADR-0001 — Verification ladder PoC.
//
// Answers: with an E2E-sealed credential the backend cannot validate anything,
// so the GATEWAY must self-verify and report a structured diagnostic. This proves
// each rung can be tested independently and non-destructively against vCenter 8.
//
// Rungs:  reachability -> tls pin -> authentication -> privileges -> scope -> correlation
//
// The privilege rung is the interesting one: AuthorizationManager.HasPrivilegeOnEntity
// answers "does this session hold privilege X on entity Y?" WITHOUT creating anything.
//
//   node verify-ladder.mjs                 # happy path, uses .env
//   VC_USER=bogus@vsphere.local node verify-ladder.mjs   # auth-failure path
//
// NOTE: never probe a wrong PASSWORD against a real account — vSphere lockout
// policy will lock it. Use a non-existent USERNAME to exercise the auth-failure rung.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import https from "node:https";
import tls from "node:tls";
import crypto from "node:crypto";
import process from "node:process";

(function loadDotEnv() {
  const file = path.join(path.dirname(fileURLToPath(import.meta.url)), ".env");
  if (!fs.existsSync(file)) return;
  for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const k = line.slice(0, eq).trim();
    let v = line.slice(eq + 1);
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    if (process.env[k] === undefined) process.env[k] = v;
  }
})();

const base = new URL(process.env.VC_URL);
const PINNED = (process.env.VC_THUMBPRINT || "").replace(/[:\s]/g, "").toLowerCase();

// The exact privileges the Infrastructure Gateway needs — nothing more.
const REQUIRED_PRIVS = (process.env.VERIFY_PRIVS ? process.env.VERIFY_PRIVS.split(",") : [
  "VirtualMachine.State.CreateSnapshot",
  "VirtualMachine.State.RemoveSnapshot",
  "VirtualMachine.State.RevertToSnapshot",
]);

let cookie = null;
const report = { stages: [], ok: false, failedStage: null, remediation: null };

main().then((c) => process.exit(c), (e) => { console.error("FATAL", e); process.exit(2); });

async function main() {
  console.log("═".repeat(70));
  console.log("  Verification ladder — gateway self-check (ADR-0001)");
  console.log("═".repeat(70));
  console.log(`vCenter: ${base.origin}   user: ${process.env.VC_USER}\n`);

  if (!(await rung("reachability", reachability))) return finish();
  if (!(await rung("tls_pin", tlsPin))) return finish();
  const sessionKey = await rung("authentication", authenticate);
  if (!sessionKey) return finish();
  if (!(await rung("privileges", () => privileges(sessionKey)))) return finish();
  await rung("scope", scope);
  report.ok = true;
  return finish();
}

// --- rung 1: can we even reach it? ------------------------------------------
async function reachability() {
  const t0 = Date.now();
  await new Promise((res, rej) => {
    const s = tls.connect({ host: base.hostname, port: Number(base.port || 443), rejectUnauthorized: false }, () => { s.end(); res(); });
    s.on("error", rej);
    s.setTimeout(8000, () => { s.destroy(); rej(new Error("timeout")); });
  });
  return { detail: `TCP+TLS handshake in ${Date.now() - t0} ms` };
}

// --- rung 2: does the cert match the pin? -----------------------------------
async function tlsPin() {
  const fp = await new Promise((res, rej) => {
    const s = tls.connect({ host: base.hostname, port: Number(base.port || 443), rejectUnauthorized: false }, () => {
      const c = s.getPeerCertificate(); s.end();
      res(crypto.createHash("sha256").update(c.raw).digest("hex"));
    });
    s.on("error", rej);
  });
  if (!PINNED) return { detail: `no pin configured; observed ${fp.slice(0, 16)}…`, warn: true };
  if (fp !== PINNED) {
    const e = new Error(`pinned ${PINNED.slice(0, 16)}… but server presented ${fp.slice(0, 16)}…`);
    e.remediation = "El certificado de vCenter cambió (o hay interceptación). Verificar y re-registrar el thumbprint.";
    throw e;
  }
  return { detail: "server certificate matches pinned thumbprint" };
}

// --- rung 3: are the credentials right? -------------------------------------
async function authenticate() {
  const sc = await soap(`<urn:RetrieveServiceContent><urn:_this type="ServiceInstance">ServiceInstance</urn:_this></urn:RetrieveServiceContent>`);
  globalThis.__svc = {
    sessionManager: tag(sc, "sessionManager"),
    authorizationManager: tag(sc, "authorizationManager"),
    viewManager: tag(sc, "viewManager"),
    rootFolder: tag(sc, "rootFolder"),
  };
  let xml;
  try {
    xml = await soap(
      `<urn:Login><urn:_this type="SessionManager">${globalThis.__svc.sessionManager}</urn:_this>` +
      `<urn:userName>${esc(process.env.VC_USER)}</urn:userName><urn:password>${esc(process.env.VC_PASS)}</urn:password></urn:Login>`
    );
  } catch (e) {
    const m = String(e.message || "");
    if (/InvalidLogin|Cannot complete login|incorrect user name or password/i.test(m)) {
      const err = new Error("vCenter rejected the credentials (InvalidLogin)");
      err.remediation = "Usuario o contraseña incorrectos. NO reintentar automáticamente: vSphere bloquea la cuenta tras N fallos.";
      err.classify = "bad_credentials";
      throw err;
    }
    if (/password.*expired|expired.*password/i.test(m)) {
      const err = new Error("password expired");
      err.remediation = "La contraseña del service account expiró. Renovarla en vSphere y re-provisionar.";
      throw err;
    }
    if (/locked/i.test(m)) {
      const err = new Error("account locked out");
      err.remediation = "La cuenta está bloqueada en vSphere. Desbloquear y esperar la ventana de lockout antes de reintentar.";
      throw err;
    }
    throw e;
  }
  const key = (xml.match(/<key>([^<]+)<\/key>/) || [])[1];
  const uname = (xml.match(/<userName>([^<]+)<\/userName>/) || [])[1];
  return { detail: `authenticated as ${uname}`, value: key };
}

// --- rung 4: does it hold the RIGHT privileges? (non-destructive) ------------
async function privileges(sessionKey) {
  const am = globalThis.__svc.authorizationManager;
  const root = globalThis.__svc.rootFolder;
  if (!am) throw new Error("authorizationManager not present in ServiceContent");

  const xml = await soap(
    `<urn:HasPrivilegeOnEntity><urn:_this type="AuthorizationManager">${am}</urn:_this>` +
    `<urn:entity type="Folder">${root}</urn:entity>` +
    `<urn:sessionId>${esc(sessionKey)}</urn:sessionId>` +
    REQUIRED_PRIVS.map((p) => `<urn:privId>${p}</urn:privId>`).join("") +
    `</urn:HasPrivilegeOnEntity>`
  );
  const vals = [...matchAll(xml, /<returnval>([^<]*)<\/returnval>/g)].map((m) => m[1] === "true");
  const rows = REQUIRED_PRIVS.map((p, i) => ({ priv: p, granted: vals[i] === true }));
  for (const r of rows) console.log(`      ${r.granted ? "✓" : "✗"} ${r.priv}`);

  const missing = rows.filter((r) => !r.granted).map((r) => r.priv);
  if (missing.length) {
    const e = new Error(`missing ${missing.length} privilege(s): ${missing.join(", ")}`);
    e.remediation = `Otorgar al service account el rol con: ${missing.join(", ")} sobre el folder/datacenter objetivo (propagado).`;
    e.classify = "insufficient_privileges";
    e.rows = rows;
    throw e;
  }
  return { detail: `all ${rows.length} required privileges granted on root folder`, rows };
}

// --- rung 5: does the configured scope resolve to anything? ------------------
async function scope() {
  const cv = await soap(
    `<urn:CreateContainerView><urn:_this type="ViewManager">${globalThis.__svc.viewManager}</urn:_this>` +
    `<urn:container type="Folder">${globalThis.__svc.rootFolder}</urn:container>` +
    `<urn:type>VirtualMachine</urn:type><urn:recursive>true</urn:recursive></urn:CreateContainerView>`
  );
  const view = (cv.match(/<returnval[^>]*type="ContainerView"[^>]*>([^<]+)<\/returnval>/) || [])[1];
  const xml = await soap(
    `<urn:RetrieveProperties><urn:_this type="PropertyCollector">propertyCollector</urn:_this><urn:specSet>` +
    `<urn:propSet><urn:type>VirtualMachine</urn:type><urn:pathSet>config.uuid</urn:pathSet></urn:propSet>` +
    `<urn:objectSet><urn:obj type="ContainerView">${view}</urn:obj><urn:skip>true</urn:skip>` +
    `<urn:selectSet xsi:type="urn:TraversalSpec"><urn:name>v</urn:name><urn:type>ContainerView</urn:type><urn:path>view</urn:path><urn:skip>false</urn:skip></urn:selectSet>` +
    `</urn:objectSet></urn:specSet></urn:RetrieveProperties>`
  );
  const n = [...matchAll(xml, /<obj[^>]*type="VirtualMachine"[^>]*>/g)].length;
  if (n === 0) {
    const e = new Error("scope resolves to 0 VMs");
    e.remediation = "El service account no ve VMs en el scope configurado. Revisar folders/permisos propagados.";
    throw e;
  }
  return { detail: `${n} VM(s) visible in scope` };
}

// --- harness ----------------------------------------------------------------
async function rung(name, fn) {
  process.stdout.write(`  ${name.padEnd(16)} … `);
  try {
    const r = (await fn()) || {};
    console.log(`${r.warn ? "⚠️" : "✅"}  ${r.detail || "ok"}`);
    report.stages.push({ stage: name, ok: true, detail: r.detail, rows: r.rows });
    return r.value ?? true;
  } catch (e) {
    console.log(`❌  ${e.message}`);
    if (e.remediation) console.log(`      ↳ ${e.remediation}`);
    report.stages.push({ stage: name, ok: false, error: e.message, classify: e.classify, remediation: e.remediation, rows: e.rows });
    report.failedStage = name;
    report.remediation = e.remediation || null;
    return null;
  }
}

function finish() {
  console.log("\n" + "─".repeat(70));
  console.log(report.ok ? "🟢 VERIFIED — gateway can snapshot" : `🔴 FAILED at rung: ${report.failedStage}`);
  console.log("\nStructured report the gateway would ACK back to the control plane:");
  const wire = Buffer.from(JSON.stringify(report)).toString("base64url");
  console.log(JSON.stringify(report, null, 2));
  console.log(`\nACK wire form: vcenter_verify:${report.ok ? "ok" : "failed"};stage=${report.failedStage || "-"};report=<b64url ${wire.length}B>`);
  return report.ok ? 0 : 1;
}

function soap(inner) {
  const body = `<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:urn="urn:vim25"><soapenv:Body>${inner}</soapenv:Body></soapenv:Envelope>`;
  return new Promise((resolve, reject) => {
    const req = https.request({
      host: base.hostname, port: Number(base.port || 443), path: "/sdk", method: "POST",
      headers: { "Content-Type": "text/xml; charset=utf-8", SOAPAction: '"urn:vim25/8.0.0.0"', "Content-Length": Buffer.byteLength(body), ...(cookie ? { Cookie: cookie } : {}) },
      rejectUnauthorized: false,
    }, (res) => {
      let d = ""; res.setEncoding("utf8");
      res.on("data", (c) => (d += c));
      res.on("end", () => {
        const sc = res.headers["set-cookie"]; if (sc?.length) cookie = sc[0].split(";")[0];
        if (/faultstring|<(?:\w+:)?Fault>/.test(d)) {
          const m = (d.match(/<localizedMessage>([\s\S]*?)<\/localizedMessage>/) || d.match(/<faultstring[^>]*>([\s\S]*?)<\/faultstring>/) || [])[1] || d.slice(0, 200);
          return reject(new Error(dec(m).trim().replace(/\s+/g, " ")));
        }
        resolve(d);
      });
    });
    req.on("error", reject); req.write(body); req.end();
  });
}
function* matchAll(s, re) { let m; while ((m = re.exec(s)) !== null) yield m; }
function tag(xml, t) { const m = xml.match(new RegExp(`<${t}[^>]*>([^<]+)</${t}>`)); return m ? m[1] : null; }
function dec(s) { return String(s).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&"); }
function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;"); }
