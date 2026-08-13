#!/usr/bin/env node
// ADR-0001 · Inc 0 spike — Patch Management Gateway (VGP)
// Throwaway PoC. Validates against a REAL vCenter 8 lab:
//   1) TLS reachability + server cert SHA-256 (for future pinning).
//   2) SOAP login (vSphere Web Services API, /sdk).
//   3) SMBIOS-UUID -> vCenter VM matching, incl. the ESXi byte-swap question.
//   4) Snapshot lifecycle: create -> (optional revert) -> remove, with timings.
//   5) EMPIRICAL probe: does this build expose snapshots over the REST API,
//      or must Inc 1 use SOAP? (We do not guess — we ask the lab.)
//
// Zero dependencies: Node >= 18 built-ins only (uses global URL, https, tls, crypto).
// Nothing here is production code. See README.md.

import https from "node:https";
import tls from "node:tls";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

// ----------------------------------------------------------------------------
// .env loader — read the file HERE, in Node.
// Deliberately NOT `source .env` in the shell: zsh/bash expand `=`, `$`, backticks
// and quotes inside values, which both corrupts passwords and can leak fragments
// of them into shell error messages. Parsing it ourselves keeps the secret in
// this process only. Existing process.env always wins.
// ----------------------------------------------------------------------------
function loadDotEnv() {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  const file = path.join(dir, ".env");
  if (!fs.existsSync(file)) return;
  for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1); // everything after the FIRST '=' , verbatim
    if ((val.startsWith('"') && val.endsWith('"') && val.length > 1) ||
        (val.startsWith("'") && val.endsWith("'") && val.length > 1)) {
      val = val.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = val;
  }
}
loadDotEnv();

// ----------------------------------------------------------------------------
// Config (env-driven; never hardcode lab creds)
// ----------------------------------------------------------------------------
const cfg = {
  url: reqEnv("VC_URL"),                       // https://vcenter.lab.local[:443]
  user: reqEnv("VC_USER"),                     // e.g. svc-tracenium@vsphere.local
  pass: reqEnv("VC_PASS"),
  vmUuid: (process.env.TARGET_VM_UUID || "").trim(), // SMBIOS uuid as the agent reports (system.uuid)
  vmName: (process.env.TARGET_VM_NAME || "").trim(),  // optional fallback / disambiguation
  insecure: process.env.VC_INSECURE === "true",
  thumbprint: normThumb(process.env.VC_THUMBPRINT),  // sha256 hex, optional pin
  quiesce: process.env.SNAP_QUIESCE !== "false",     // default true
  memory: process.env.SNAP_MEMORY === "true",        // default false
  doCreate: process.env.SPIKE_CREATE !== "false",    // default true (create+remove)
  doRevert: process.env.SPIKE_REVERT === "true",     // default FALSE (disruptive!)
};

const base = new URL(cfg.url);
let cookie = null; // vmware_soap_session
const results = []; // summary rows: {name, ok, detail}

// ----------------------------------------------------------------------------
main().then(
  (code) => process.exit(code),
  (err) => { console.error("\n💥 FATAL:", err?.stack || err); process.exit(2); }
);

async function main() {
  banner("ADR-0001 Inc 0 — vCenter 8 snapshot + UUID spike");
  console.log(`Target vCenter : ${base.origin}`);
  console.log(`User           : ${cfg.user}`);
  console.log(`TLS verify     : ${cfg.insecure ? "DISABLED (insecure)" : cfg.thumbprint ? "pinned thumbprint" : "system CA"}`);
  console.log(`SMBIOS UUID in  : ${cfg.vmUuid || "(none — will list VMs)"}`);
  console.log(`Snapshot        : memory=${cfg.memory} quiesce=${cfg.quiesce}  create=${cfg.doCreate} revert=${cfg.doRevert}\n`);

  // 1) TLS + fingerprint --------------------------------------------------
  const fp = await serverFingerprint(base.hostname, Number(base.port || 443));
  console.log(`🔐 Server cert SHA-256: ${fp}`);
  if (cfg.thumbprint) {
    // compare canonical forms: strip separators + lowercase on BOTH sides
    const ok = normThumb(fp) === cfg.thumbprint;
    record("TLS thumbprint pin", ok, ok ? "matches" : `MISMATCH vs VC_THUMBPRINT (${cfg.thumbprint})`);
    if (!ok) throw new Error("Server fingerprint does not match VC_THUMBPRINT — aborting before auth.");
  } else {
    record("TLS reachability", true, `fingerprint captured (pin this later): ${fp}`);
  }

  // 2) SOAP service content + login --------------------------------------
  const svc = await retrieveServiceContent();
  console.log(`🧭 API: ${svc.apiType} ${svc.apiVersion}  (product: ${svc.name})`);
  record("SOAP RetrieveServiceContent", true, `${svc.apiType} ${svc.apiVersion}`);
  await login(svc.sessionManager);
  record("SOAP Login", true, cfg.user);

  // 3) Inventory + UUID matching -----------------------------------------
  const vms = await listAllVms(svc.viewManager, svc.rootFolder);
  console.log(`\n📋 VMs visible to this account: ${vms.length}`);
  for (const v of vms.slice(0, 25)) {
    console.log(`   ${pad(v.moref, 10)}  uuid=${v.uuid || "-"}  instanceUuid=${v.instanceUuid || "-"}  name=${v.name}`);
  }
  if (vms.length > 25) console.log(`   … (+${vms.length - 25} more)`);
  record("SOAP inventory (ContainerView)", vms.length > 0, `${vms.length} VM(s)`);

  let target = null;      // {moref,name,uuid,instanceUuid}
  let matchMode = null;   // 'bios-raw' | 'bios-swapped' | 'instance' | 'name'

  if (cfg.vmUuid) {
    const raw = cfg.vmUuid.toLowerCase();
    const swapped = byteSwapUuid(raw);
    console.log(`\n🔎 UUID matching for SMBIOS uuid=${raw}`);
    console.log(`   byte-swapped candidate      =${swapped}`);

    const biosRaw = await findByUuid(svc.searchIndex, raw, /*instanceUuid*/ false);
    const biosSwap = raw === swapped ? null : await findByUuid(svc.searchIndex, swapped, false);
    const inst = await findByUuid(svc.searchIndex, raw, /*instanceUuid*/ true);

    console.log(`   FindByUuid(raw,   bios)     -> ${biosRaw || "not found"}`);
    console.log(`   FindByUuid(swap,  bios)     -> ${biosSwap || "n/a"}`);
    console.log(`   FindByUuid(raw,   instance) -> ${inst || "not found"}`);

    const chosen = biosRaw || biosSwap || inst;
    matchMode = biosRaw ? "bios-raw" : biosSwap ? "bios-swapped" : inst ? "instance" : null;
    if (chosen) target = vms.find((v) => v.moref === chosen) || { moref: chosen };

    // The crux finding for Inc 1:
    if (biosRaw) {
      record("UUID match (byte-swap needed?)", true, "RAW SMBIOS uuid matched config.uuid directly — NO swap needed");
    } else if (biosSwap) {
      record("UUID match (byte-swap needed?)", true, "BYTE-SWAPPED uuid matched — Inc1 MUST swap first 3 fields");
    } else if (inst) {
      record("UUID match (byte-swap needed?)", false, "Only instanceUuid matched — SMBIOS uuid does NOT equal config.uuid here; revisit correlation key");
    } else {
      record("UUID match (byte-swap needed?)", false, "No VM matched raw/swapped/instance — check the UUID or account visibility");
    }
  } else if (cfg.vmName) {
    target = vms.find((v) => v.name === cfg.vmName) || null;
    matchMode = target ? "name" : null;
    record("UUID match", false, "skipped (no TARGET_VM_UUID) — matched by name instead");
  } else {
    record("UUID match", false, "skipped — set TARGET_VM_UUID to validate correlation");
  }

  if (target?.moref && !target.uuid) {
    const props = await retrieveProps("VirtualMachine", target.moref, ["name", "config.uuid", "config.instanceUuid"]);
    Object.assign(target, { name: props["name"], uuid: props["config.uuid"], instanceUuid: props["config.instanceUuid"] });
  }
  if (target?.moref) {
    console.log(`\n🎯 Target VM: ${target.moref}  name=${target.name}  config.uuid=${target.uuid}  (match: ${matchMode})`);
  }

  // 4) Snapshot lifecycle -------------------------------------------------
  if (target?.moref && cfg.doCreate) {
    const snapName = `tracenium-prepatch-spike-${shortStamp()}`;
    console.log(`\n📸 CreateSnapshot_Task "${snapName}" (memory=${cfg.memory}, quiesce=${cfg.quiesce}) …`);
    const t0 = hrms();
    const createTask = await createSnapshot(target.moref, snapName, "ADR-0001 Inc0 spike — safe to delete", cfg.memory, cfg.quiesce);
    await waitTask(createTask);
    const createMs = hrms() - t0;
    record("Snapshot create", true, `${createMs} ms`);
    console.log(`   ✓ created in ${createMs} ms`);

    const snapMoref = await currentSnapshotMoref(target.moref);
    console.log(`   current snapshot MoRef: ${snapMoref}`);

    if (cfg.doRevert && snapMoref) {
      console.log(`\n⏪ RevertToSnapshot_Task (DISRUPTIVE — reverts VM state!) …`);
      const t1 = hrms();
      const revertTask = await revertSnapshot(snapMoref);
      await waitTask(revertTask);
      const revertMs = hrms() - t1;
      record("Snapshot revert", true, `${revertMs} ms`);
      console.log(`   ✓ reverted in ${revertMs} ms`);
    } else {
      record("Snapshot revert", true, cfg.doRevert ? "no snapshot moref" : "skipped (SPIKE_REVERT!=true)");
    }

    if (snapMoref) {
      console.log(`\n🧹 RemoveSnapshot_Task (cleanup) …`);
      const t2 = hrms();
      const removeTask = await removeSnapshot(snapMoref, false);
      await waitTask(removeTask);
      const removeMs = hrms() - t2;
      record("Snapshot remove", true, `${removeMs} ms`);
      console.log(`   ✓ removed in ${removeMs} ms`);
    }
  } else {
    record("Snapshot lifecycle", false, target?.moref ? "skipped (SPIKE_CREATE=false)" : "skipped (no target VM)");
  }

  // 5) REST API probe (empirical) ----------------------------------------
  await restProbe(target?.moref);

  await logout(svc.sessionManager).catch(() => {});

  // Summary ---------------------------------------------------------------
  printSummary();
  const gate = results.find((r) => r.name.startsWith("UUID match (byte-swap"));
  const snapOk = results.find((r) => r.name === "Snapshot create")?.ok;
  console.log(`\n🚦 DECISION GATE:`);
  console.log(`   • Snapshot create/remove works : ${snapOk ? "YES" : "NOT PROVEN"}`);
  console.log(`   • UUID correlation reliable    : ${gate?.ok ? "YES — " + gate.detail : "NEEDS REVIEW — " + (gate?.detail || "not tested")}`);
  console.log(`   • Snapshot API for Inc 1       : see "REST snapshots probe" row above (REST if 200, else SOAP)\n`);
  return results.every((r) => r.ok) ? 0 : 1;
}

// ============================================================================
// SOAP plumbing
// ============================================================================
function envelope(inner) {
  return (
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ` +
    `xmlns:xsd="http://www.w3.org/2001/XMLSchema" ` +
    `xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ` +
    `xmlns:urn="urn:vim25">` +
    `<soapenv:Body>${inner}</soapenv:Body></soapenv:Envelope>`
  );
}

async function soap(inner) {
  const res = await httpsRequest("POST", "/sdk", {
    "Content-Type": "text/xml; charset=utf-8",
    SOAPAction: '"urn:vim25/8.0.0.0"',
    ...(cookie ? { Cookie: cookie } : {}),
  }, envelope(inner));
  const sc = res.headers["set-cookie"];
  if (sc && sc.length) cookie = sc[0].split(";")[0];
  if (/<(?:\w+:)?Fault>/.test(res.body) || /faultstring/.test(res.body)) {
    // faultstring is usually unprefixed; localizedMessage carries the human text.
    const msg =
      extractTag(res.body, "localizedMessage") ||
      extractTag(res.body, "faultstring") ||
      (res.body.match(/<faultstring[^>]*>([\s\S]*?)<\/faultstring>/) || [])[1] ||
      res.body.replace(/\s+/g, " ").slice(0, 400);
    throw new Error(`SOAP fault: ${decode(msg).trim()}`);
  }
  if (res.status >= 400) throw new Error(`HTTP ${res.status} on /sdk: ${res.body.slice(0, 300)}`);
  return res.body;
}

async function retrieveServiceContent() {
  const xml = await soap(`<urn:RetrieveServiceContent><urn:_this type="ServiceInstance">ServiceInstance</urn:_this></urn:RetrieveServiceContent>`);
  return {
    sessionManager: moref(xml, "sessionManager"),
    searchIndex: moref(xml, "searchIndex"),
    propertyCollector: moref(xml, "propertyCollector"),
    viewManager: moref(xml, "viewManager"),
    rootFolder: moref(xml, "rootFolder"),
    apiType: extractTag(xml, "apiType"),
    apiVersion: extractTag(xml, "apiVersion"),
    name: decode(extractTag(xml, "fullName") || extractTag(xml, "name") || "vCenter"),
  };
}

async function login(sessionManager) {
  await soap(
    `<urn:Login><urn:_this type="SessionManager">${sessionManager}</urn:_this>` +
    `<urn:userName>${xesc(cfg.user)}</urn:userName>` +
    `<urn:password>${xesc(cfg.pass)}</urn:password></urn:Login>`
  );
}
async function logout(sessionManager) {
  await soap(`<urn:Logout><urn:_this type="SessionManager">${sessionManager}</urn:_this></urn:Logout>`);
}

async function findByUuid(searchIndex, uuid, instanceUuid) {
  const xml = await soap(
    `<urn:FindByUuid><urn:_this type="SearchIndex">${searchIndex}</urn:_this>` +
    `<urn:uuid>${xesc(uuid)}</urn:uuid><urn:vmSearch>true</urn:vmSearch>` +
    `<urn:instanceUuid>${instanceUuid ? "true" : "false"}</urn:instanceUuid></urn:FindByUuid>`
  );
  const m = xml.match(/<returnval[^>]*type="VirtualMachine"[^>]*>([^<]+)<\/returnval>/);
  return m ? m[1] : null;
}

async function listAllVms(viewManager, rootFolder) {
  const cv = await soap(
    `<urn:CreateContainerView><urn:_this type="ViewManager">${viewManager}</urn:_this>` +
    `<urn:container type="Folder">${rootFolder}</urn:container>` +
    `<urn:type>VirtualMachine</urn:type><urn:recursive>true</urn:recursive></urn:CreateContainerView>`
  );
  const view = (cv.match(/<returnval[^>]*type="ContainerView"[^>]*>([^<]+)<\/returnval>/) || [])[1];
  if (!view) return [];
  const xml = await soap(
    `<urn:RetrieveProperties><urn:_this type="PropertyCollector">propertyCollector</urn:_this><urn:specSet>` +
    `<urn:propSet><urn:type>VirtualMachine</urn:type><urn:pathSet>name</urn:pathSet>` +
    `<urn:pathSet>config.uuid</urn:pathSet><urn:pathSet>config.instanceUuid</urn:pathSet></urn:propSet>` +
    `<urn:objectSet><urn:obj type="ContainerView">${view}</urn:obj><urn:skip>true</urn:skip>` +
    `<urn:selectSet xsi:type="urn:TraversalSpec"><urn:name>vmView</urn:name>` +
    `<urn:type>ContainerView</urn:type><urn:path>view</urn:path><urn:skip>false</urn:skip></urn:selectSet>` +
    `</urn:objectSet></urn:specSet></urn:RetrieveProperties>`
  );
  const out = [];
  for (const block of matchAll(xml, /<returnval[^>]*>([\s\S]*?)<\/returnval>/g)) {
    const b = block[1];
    const mo = (b.match(/<obj[^>]*type="VirtualMachine"[^>]*>([^<]+)<\/obj>/) || [])[1];
    if (!mo) continue;
    const row = { moref: mo, name: "", uuid: "", instanceUuid: "" };
    for (const ps of matchAll(b, /<propSet>([\s\S]*?)<\/propSet>/g)) {
      const name = extractTag(ps[1], "name");
      const val = decode(extractTag(ps[1], "val") || "");
      if (name === "name") row.name = val;
      else if (name === "config.uuid") row.uuid = val.toLowerCase();
      else if (name === "config.instanceUuid") row.instanceUuid = val.toLowerCase();
    }
    out.push(row);
  }
  return out;
}

async function retrieveProps(type, mo, paths) {
  const xml = await soap(
    `<urn:RetrieveProperties><urn:_this type="PropertyCollector">propertyCollector</urn:_this><urn:specSet>` +
    `<urn:propSet><urn:type>${type}</urn:type>${paths.map((p) => `<urn:pathSet>${p}</urn:pathSet>`).join("")}</urn:propSet>` +
    `<urn:objectSet><urn:obj type="${type}">${mo}</urn:obj></urn:objectSet></urn:specSet></urn:RetrieveProperties>`
  );
  const res = {};
  for (const ps of matchAll(xml, /<propSet>([\s\S]*?)<\/propSet>/g)) {
    res[extractTag(ps[1], "name")] = decode(extractTag(ps[1], "val") || "");
  }
  return res;
}

async function createSnapshot(vm, name, desc, memory, quiesce) {
  const xml = await soap(
    `<urn:CreateSnapshot_Task><urn:_this type="VirtualMachine">${vm}</urn:_this>` +
    `<urn:name>${xesc(name)}</urn:name><urn:description>${xesc(desc)}</urn:description>` +
    `<urn:memory>${memory ? "true" : "false"}</urn:memory><urn:quiesce>${quiesce ? "true" : "false"}</urn:quiesce>` +
    `</urn:CreateSnapshot_Task>`
  );
  return taskRef(xml);
}
async function revertSnapshot(snap) {
  const xml = await soap(`<urn:RevertToSnapshot_Task><urn:_this type="VirtualMachineSnapshot">${snap}</urn:_this></urn:RevertToSnapshot_Task>`);
  return taskRef(xml);
}
async function removeSnapshot(snap, removeChildren) {
  const xml = await soap(
    `<urn:RemoveSnapshot_Task><urn:_this type="VirtualMachineSnapshot">${snap}</urn:_this>` +
    `<urn:removeChildren>${removeChildren ? "true" : "false"}</urn:removeChildren></urn:RemoveSnapshot_Task>`
  );
  return taskRef(xml);
}
async function currentSnapshotMoref(vm) {
  const p = await retrieveProps("VirtualMachine", vm, ["snapshot.currentSnapshot"]);
  return p["snapshot.currentSnapshot"] || null;
}

async function waitTask(task, timeoutMs = 15 * 60 * 1000) {
  const start = Date.now();
  for (;;) {
    // Only ask for info.state. Asking for info.error.localizedMessage up-front makes
    // vCenter fault when the task has no error (the optional nested path is unset).
    const p = await retrieveProps("Task", task, ["info.state"]);
    const state = p["info.state"];
    if (state === "success") return;
    if (state === "error") {
      let why = "unknown";
      try {
        const e = await retrieveProps("Task", task, ["info.error"]);
        why = e["info.error"] || "unknown";
      } catch { /* best effort */ }
      throw new Error(`Task ${task} failed: ${why}`);
    }
    if (Date.now() - start > timeoutMs) throw new Error(`Task ${task} timed out after ${timeoutMs}ms (last state: ${state})`);
    await sleep(1500);
  }
}

// List the VM's snapshot tree: [{moref, name, createTime}]
async function listSnapshots(vm) {
  const xml = await soap(
    `<urn:RetrieveProperties><urn:_this type="PropertyCollector">propertyCollector</urn:_this><urn:specSet>` +
    `<urn:propSet><urn:type>VirtualMachine</urn:type><urn:pathSet>snapshot.rootSnapshotList</urn:pathSet></urn:propSet>` +
    `<urn:objectSet><urn:obj type="VirtualMachine">${vm}</urn:obj></urn:objectSet></urn:specSet></urn:RetrieveProperties>`
  );
  const out = [];
  for (const m of matchAll(xml, /<snapshot[^>]*type="VirtualMachineSnapshot"[^>]*>([^<]+)<\/snapshot>/g)) {
    out.push({ moref: m[1] });
  }
  const names = [...matchAll(xml, /<name>([^<]*)<\/name>/g)].map((m) => decode(m[1]));
  const times = [...matchAll(xml, /<createTime>([^<]*)<\/createTime>/g)].map((m) => m[1]);
  out.forEach((s, i) => { s.name = names[i] ?? "?"; s.createTime = times[i] ?? "?"; });
  return out;
}

function taskRef(xml) {
  const m = xml.match(/<returnval[^>]*type="Task"[^>]*>([^<]+)<\/returnval>/);
  if (!m) throw new Error("no Task MoRef in response");
  return m[1];
}

// ============================================================================
// REST API probe — learn empirically whether this build has snapshot REST
// ============================================================================
async function restProbe(vmMoref) {
  try {
    const sess = await httpsRequest("POST", "/api/session", {
      Authorization: "Basic " + Buffer.from(`${cfg.user}:${cfg.pass}`).toString("base64"),
    }, "");
    if (sess.status !== 200 && sess.status !== 201) {
      record("REST /api/session", false, `HTTP ${sess.status}`);
      return;
    }
    const token = sess.body.replace(/^"|"$/g, "");
    record("REST /api/session", true, "session created");

    if (vmMoref) {
      const snap = await httpsRequest("GET", `/api/vcenter/vm/${encodeURIComponent(vmMoref)}/snapshots`, {
        "vmware-api-session-id": token,
      }, "");
      const has = snap.status === 200;
      record("REST snapshots probe", true,
        has ? `AVAILABLE (HTTP 200) — Inc1 can use REST`
            : `NOT available (HTTP ${snap.status}) — Inc1 uses SOAP for snapshots`);
      console.log(`\n🌐 REST GET /api/vcenter/vm/${vmMoref}/snapshots -> HTTP ${snap.status}`);
    } else {
      record("REST snapshots probe", false, "skipped (no target VM)");
    }
    await httpsRequest("DELETE", "/api/session", { "vmware-api-session-id": token }, "").catch(() => {});
  } catch (e) {
    record("REST probe", false, String(e?.message || e));
  }
}

// ============================================================================
// HTTPS / TLS primitives (built-in)
// ============================================================================
function httpsRequest(method, path, headers, body) {
  return new Promise((resolve, reject) => {
    const opts = {
      host: base.hostname,
      port: Number(base.port || 443),
      path,
      method,
      headers: { ...headers, ...(body ? { "Content-Length": Buffer.byteLength(body) } : {}) },
      servername: base.hostname,
      rejectUnauthorized: !(cfg.insecure || cfg.thumbprint), // thumbprint already verified out-of-band
    };
    const req = https.request(opts, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

function serverFingerprint(host, port) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      const cert = sock.getPeerCertificate();
      sock.end();
      if (!cert || !cert.raw) return reject(new Error("no peer certificate"));
      resolve(crypto.createHash("sha256").update(cert.raw).digest("hex").match(/../g).join(":").toUpperCase());
    });
    sock.on("error", reject);
    sock.setTimeout(10000, () => { sock.destroy(); reject(new Error("TLS connect timeout")); });
  });
}

// ============================================================================
// Helpers
// ============================================================================
function byteSwapUuid(u) {
  const h = u.replace(/-/g, "").toLowerCase();
  if (h.length !== 32) return u;
  const b = h.match(/../g);
  const f1 = [b[3], b[2], b[1], b[0]].join("");
  const f2 = [b[5], b[4]].join("");
  const f3 = [b[7], b[6]].join("");
  const f4 = [b[8], b[9]].join("");
  const f5 = b.slice(10).join("");
  return `${f1}-${f2}-${f3}-${f4}-${f5}`;
}
function moref(xml, tag) {
  const m = xml.match(new RegExp(`<${tag}[^>]*>([^<]+)</${tag}>`));
  return m ? m[1] : null;
}
function extractTag(xml, tag) {
  const m = xml.match(new RegExp(`<(?:\\w+:)?${tag}\\b[^>]*>([\\s\\S]*?)</(?:\\w+:)?${tag}>`));
  return m ? m[1] : null;
}
function* matchAll(s, re) { let m; while ((m = re.exec(s)) !== null) yield m; }
function decode(s) {
  return String(s).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}
function xesc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}
function normThumb(t) { return t ? t.replace(/[:\s]/g, "").toLowerCase() : null; }
function reqEnv(k) { const v = process.env[k]; if (!v) { console.error(`Missing required env ${k}. See README.md / .env.example`); process.exit(3); } return v; }
function record(name, ok, detail) { results.push({ name, ok, detail }); }
function printSummary() {
  banner("SUMMARY");
  for (const r of results) console.log(`  ${r.ok ? "✅" : "❌"} ${pad(r.name, 34)} ${r.detail || ""}`);
}
function banner(t) { console.log(`\n${"═".repeat(72)}\n  ${t}\n${"═".repeat(72)}`); }
function pad(s, n) { s = String(s); return s.length >= n ? s : s + " ".repeat(n - s.length); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function hrms() { return Number(process.hrtime.bigint() / 1000000n); }
function shortStamp() { return process.hrtime.bigint().toString(36).slice(-6); }
