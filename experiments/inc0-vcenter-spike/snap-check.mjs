#!/usr/bin/env node
// Safety utility for the Inc 0 spike: list (and optionally clean up) snapshots
// on a target VM. Used to guarantee the spike leaves nothing behind.
//
//   node snap-check.mjs                       # list snapshots on TARGET_VM_NAME
//   node snap-check.mjs --remove-spike        # ALSO remove snapshots whose name
//                                             # starts with "tracenium-prepatch-spike-"
//
// Only ever removes snapshots created by this spike (prefix-guarded).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import https from "node:https";
import process from "node:process";

const SPIKE_PREFIX = "tracenium-prepatch-spike-";
const doRemove = process.argv.includes("--remove-spike");

// --- .env loader (in-process; never via shell) -------------------------------
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
const VM_NAME = process.env.TARGET_VM_NAME || "";
let cookie = null;

main().then((c) => process.exit(c), (e) => { console.error("FATAL:", e.message || e); process.exit(2); });

async function main() {
  const svc = await soapCall(`<urn:RetrieveServiceContent><urn:_this type="ServiceInstance">ServiceInstance</urn:_this></urn:RetrieveServiceContent>`);
  const sm = tag(svc, "sessionManager"), vmgr = tag(svc, "viewManager"), root = tag(svc, "rootFolder");
  await soapCall(`<urn:Login><urn:_this type="SessionManager">${sm}</urn:_this><urn:userName>${esc(process.env.VC_USER)}</urn:userName><urn:password>${esc(process.env.VC_PASS)}</urn:password></urn:Login>`);

  const vms = await listVms(vmgr, root);
  const vm = vms.find((v) => v.name === VM_NAME);
  if (!vm) { console.error(`VM "${VM_NAME}" not found (set TARGET_VM_NAME)`); return 1; }
  console.log(`VM ${vm.moref}  ${vm.name}`);

  const snaps = await listSnapshots(vm.moref);
  if (!snaps.length) {
    console.log("✅ No snapshots on this VM — nothing left behind.");
    await soapCall(`<urn:Logout><urn:_this type="SessionManager">${sm}</urn:_this></urn:Logout>`).catch(() => {});
    return 0;
  }

  console.log(`\nSnapshots found: ${snaps.length}`);
  for (const s of snaps) {
    const mine = s.name.startsWith(SPIKE_PREFIX);
    console.log(`  ${mine ? "🔸 (spike)" : "  (pre-existing)"} ${s.moref}  "${s.name}"  created=${s.createTime}`);
  }

  const mine = snaps.filter((s) => s.name.startsWith(SPIKE_PREFIX));
  if (!mine.length) {
    console.log("\n✅ None of them were created by the spike. Leaving everything untouched.");
  } else if (!doRemove) {
    console.log(`\n⚠️  ${mine.length} spike snapshot(s) present. Re-run with --remove-spike to delete them.`);
  } else {
    for (const s of mine) {
      console.log(`\n🧹 Removing ${s.moref} "${s.name}" …`);
      const t = await soapCall(`<urn:RemoveSnapshot_Task><urn:_this type="VirtualMachineSnapshot">${s.moref}</urn:_this><urn:removeChildren>false</urn:removeChildren></urn:RemoveSnapshot_Task>`);
      await waitTask((t.match(/<returnval[^>]*type="Task"[^>]*>([^<]+)<\/returnval>/) || [])[1]);
      console.log("   ✓ removed");
    }
    const after = await listSnapshots(vm.moref);
    console.log(`\n✅ Cleanup done. Snapshots remaining on VM: ${after.length}`);
  }

  await soapCall(`<urn:Logout><urn:_this type="SessionManager">${sm}</urn:_this></urn:Logout>`).catch(() => {});
  return 0;
}

async function listVms(viewManager, rootFolder) {
  const cv = await soapCall(`<urn:CreateContainerView><urn:_this type="ViewManager">${viewManager}</urn:_this><urn:container type="Folder">${rootFolder}</urn:container><urn:type>VirtualMachine</urn:type><urn:recursive>true</urn:recursive></urn:CreateContainerView>`);
  const view = (cv.match(/<returnval[^>]*type="ContainerView"[^>]*>([^<]+)<\/returnval>/) || [])[1];
  const xml = await soapCall(
    `<urn:RetrieveProperties><urn:_this type="PropertyCollector">propertyCollector</urn:_this><urn:specSet>` +
    `<urn:propSet><urn:type>VirtualMachine</urn:type><urn:pathSet>name</urn:pathSet></urn:propSet>` +
    `<urn:objectSet><urn:obj type="ContainerView">${view}</urn:obj><urn:skip>true</urn:skip>` +
    `<urn:selectSet xsi:type="urn:TraversalSpec"><urn:name>v</urn:name><urn:type>ContainerView</urn:type><urn:path>view</urn:path><urn:skip>false</urn:skip></urn:selectSet>` +
    `</urn:objectSet></urn:specSet></urn:RetrieveProperties>`
  );
  const out = [];
  for (const b of matchAll(xml, /<returnval[^>]*>([\s\S]*?)<\/returnval>/g)) {
    const mo = (b[1].match(/<obj[^>]*type="VirtualMachine"[^>]*>([^<]+)<\/obj>/) || [])[1];
    const nm = (b[1].match(/<val[^>]*>([\s\S]*?)<\/val>/) || [])[1];
    if (mo) out.push({ moref: mo, name: dec(nm || "") });
  }
  return out;
}

async function listSnapshots(vm) {
  const xml = await soapCall(
    `<urn:RetrieveProperties><urn:_this type="PropertyCollector">propertyCollector</urn:_this><urn:specSet>` +
    `<urn:propSet><urn:type>VirtualMachine</urn:type><urn:pathSet>snapshot.rootSnapshotList</urn:pathSet></urn:propSet>` +
    `<urn:objectSet><urn:obj type="VirtualMachine">${vm}</urn:obj></urn:objectSet></urn:specSet></urn:RetrieveProperties>`
  );
  // vCenter returns snapshot entries INLINE under <rootSnapshotList>/<childSnapshotList>
  // (no <VirtualMachineSnapshotTree> wrapper). Anchor on each <snapshot type=...> element
  // and read the sibling <name>/<createTime> that follow it. A flat scan for <name> would
  // instead pick up the PropertySpec's own <name>snapshot</name> — a false negative that
  // once made this tool report "clean" while a snapshot was live. Never do that again.
  const out = [];
  const re = /<snapshot type="VirtualMachineSnapshot">([^<]+)<\/snapshot>\s*<vm[^>]*>[^<]*<\/vm>\s*<name>([\s\S]*?)<\/name>([\s\S]*?)<createTime>([^<]*)<\/createTime>/g;
  for (const m of matchAll(xml, re)) {
    out.push({
      moref: m[1],
      name: dec(m[2]),
      description: dec((m[3].match(/<description>([\s\S]*?)<\/description>/) || [])[1] || ""),
      createTime: m[4],
    });
  }
  return out;
}

async function waitTask(task, timeoutMs = 900000) {
  const start = Date.now();
  for (;;) {
    const xml = await soapCall(`<urn:RetrieveProperties><urn:_this type="PropertyCollector">propertyCollector</urn:_this><urn:specSet><urn:propSet><urn:type>Task</urn:type><urn:pathSet>info.state</urn:pathSet></urn:propSet><urn:objectSet><urn:obj type="Task">${task}</urn:obj></urn:objectSet></urn:specSet></urn:RetrieveProperties>`);
    const st = (xml.match(/<val[^>]*>([\s\S]*?)<\/val>/) || [])[1];
    if (st === "success") return;
    if (st === "error") throw new Error(`task ${task} error`);
    if (Date.now() - start > timeoutMs) throw new Error(`task ${task} timeout`);
    await new Promise((r) => setTimeout(r, 1500));
  }
}

function soapCall(inner) {
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
          const m = dec((d.match(/<localizedMessage>([\s\S]*?)<\/localizedMessage>/) || d.match(/<faultstring[^>]*>([\s\S]*?)<\/faultstring>/) || [])[1] || d.replace(/\s+/g, " ").slice(0, 300));
          return reject(new Error("SOAP fault: " + m.trim()));
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
