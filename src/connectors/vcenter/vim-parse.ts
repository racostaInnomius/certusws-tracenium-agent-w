/**
 * vim25 SOAP response parsing.
 *
 * PURE. Takes XML strings, returns data. No I/O, no client state.
 *
 * ⚠️ These parsers exist as a separate, individually tested module for a
 * reason. During the Inc 0 spike a naive flat scan for `<name>` inside a
 * RetrieveProperties response picked up the PropertySpec's OWN
 * `<name>snapshot</name>` element instead of the snapshot's name, and the
 * cleanup tool reported "no snapshots" while a snapshot was live on the VM.
 * That is the exact failure mode that silently fills a datastore with orphaned
 * snapshots. Every parser here anchors on a typed managed-object reference,
 * never on a bare tag name. See ADR-0001 "Lecciones adicionales para Inc 1".
 */

export interface SnapshotNode {
  /** MoRef, e.g. "snapshot-13889". */
  moref: string;
  name: string;
  description: string;
  createTime: string;
  /** Power state captured at snapshot time. */
  state: string;
  quiesced: boolean;
}

/** Decode the small set of XML entities vCenter emits. */
export function decodeXml(s: string): string {
  return String(s)
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

/** Escape a value for inclusion in a SOAP request body. */
export function escapeXml(s: unknown): string {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function* matchAll(s: string, re: RegExp): Generator<RegExpExecArray> {
  let m: RegExpExecArray | null;
  const r = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  while ((m = r.exec(s)) !== null) yield m;
}

/** First value of a simple element, e.g. <apiVersion>8.0.3.0</apiVersion>. */
export function firstTag(xml: string, tag: string): string | null {
  const m = xml.match(new RegExp(`<(?:\\w+:)?${tag}\\b[^>]*>([\\s\\S]*?)</(?:\\w+:)?${tag}>`));
  return m ? decodeXml(m[1]) : null;
}

/** A managed object reference of a given type, e.g. <returnval type="Task">task-1</returnval>. */
export function morefOfType(xml: string, moType: string, tag = "returnval"): string | null {
  const m = xml.match(new RegExp(`<${tag}[^>]*type="${moType}"[^>]*>([^<]+)</${tag}>`));
  return m ? m[1] : null;
}

/**
 * Human-readable fault text. vCenter puts the useful message in
 * <localizedMessage>; <faultstring> is the fallback.
 */
export function parseFault(xml: string): string | null {
  if (!/faultstring|<(?:\w+:)?Fault>/.test(xml)) return null;
  const msg =
    firstTag(xml, "localizedMessage") ??
    firstTag(xml, "faultstring") ??
    xml.replace(/\s+/g, " ").slice(0, 400);
  return decodeXml(msg).trim().replace(/\s+/g, " ");
}

/**
 * Snapshot tree from a `snapshot` / `snapshot.rootSnapshotList` property.
 *
 * vCenter serialises entries INLINE under <rootSnapshotList> / <childSnapshotList>
 * with NO <VirtualMachineSnapshotTree> wrapper, so we anchor on the typed
 * <snapshot type="VirtualMachineSnapshot"> element and read the siblings that
 * follow it. <currentSnapshot type="VirtualMachineSnapshot"> uses a different
 * tag name and is therefore not picked up as an entry.
 */
export function parseSnapshotTree(xml: string): SnapshotNode[] {
  const out: SnapshotNode[] = [];
  const re =
    /<snapshot type="VirtualMachineSnapshot">([^<]+)<\/snapshot>\s*<vm[^>]*>[^<]*<\/vm>\s*<name>([\s\S]*?)<\/name>([\s\S]*?)<createTime>([^<]*)<\/createTime>([\s\S]{0,400}?)(?=<snapshot type="VirtualMachineSnapshot">|$)/g;
  for (const m of matchAll(xml, re)) {
    const between = m[3];
    const after = m[5] ?? "";
    out.push({
      moref: m[1],
      name: decodeXml(m[2]),
      description: decodeXml((between.match(/<description>([\s\S]*?)<\/description>/) || [])[1] ?? ""),
      createTime: m[4],
      state: (after.match(/<state>([^<]*)<\/state>/) || [])[1] ?? "",
      quiesced: /<quiesced>true<\/quiesced>/.test(after),
    });
  }
  return out;
}

/** MoRef of the VM's current snapshot, or null when the VM has none. */
export function parseCurrentSnapshot(xml: string): string | null {
  const m = xml.match(/<currentSnapshot type="VirtualMachineSnapshot">([^<]+)<\/currentSnapshot>/);
  return m ? m[1] : null;
}

export interface VmSummary {
  moref: string;
  name: string;
  uuid: string;
  instanceUuid: string;
}

/** VM rows from a RetrieveProperties response over a ContainerView. */
export function parseVmSummaries(xml: string): VmSummary[] {
  const out: VmSummary[] = [];
  for (const block of matchAll(xml, /<returnval[^>]*>([\s\S]*?)<\/returnval>/g)) {
    const b = block[1];
    const moref = (b.match(/<obj[^>]*type="VirtualMachine"[^>]*>([^<]+)<\/obj>/) || [])[1];
    if (!moref) continue;
    const row: VmSummary = { moref, name: "", uuid: "", instanceUuid: "" };
    for (const ps of matchAll(b, /<propSet>([\s\S]*?)<\/propSet>/g)) {
      const name = (ps[1].match(/<name>([\s\S]*?)<\/name>/) || [])[1];
      const val = decodeXml((ps[1].match(/<val[^>]*>([\s\S]*?)<\/val>/) || [])[1] ?? "");
      if (name === "name") row.name = val;
      else if (name === "config.uuid") row.uuid = val.toLowerCase();
      else if (name === "config.instanceUuid") row.instanceUuid = val.toLowerCase();
    }
    out.push(row);
  }
  return out;
}

/** Single scalar property (`info.state`, …) from a RetrieveProperties response. */
export function parsePropertyValue(xml: string, propName: string): string | null {
  for (const ps of matchAll(xml, /<propSet>([\s\S]*?)<\/propSet>/g)) {
    const name = (ps[1].match(/<name>([\s\S]*?)<\/name>/) || [])[1];
    if (name !== propName) continue;
    const val = (ps[1].match(/<val[^>]*>([\s\S]*?)<\/val>/) || [])[1];
    return val === undefined ? null : decodeXml(val);
  }
  return null;
}

/**
 * Ordered booleans from HasPrivilegeOnEntity. vCenter returns one <returnval>
 * per requested privId, in request order.
 */
export function parsePrivilegeResults(xml: string): boolean[] {
  return [...matchAll(xml, /<returnval>([^<]*)<\/returnval>/g)].map((m) => m[1] === "true");
}

/** Every privilege id the server advertises (AuthorizationManager.privilegeList). */
export function parsePrivilegeList(xml: string): string[] {
  return [...matchAll(xml, /<privId>([^<]+)<\/privId>/g)].map((m) => m[1]);
}
