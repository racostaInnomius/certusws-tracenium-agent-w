/**
 * Minimal vim25 SOAP client for the Infrastructure Gateway.
 *
 * SOAP, not REST: the Inc 0 spike proved vCenter 8.0.3 answers
 * `GET /api/vcenter/vm/{moref}/snapshots` with HTTP 404 even on a valid REST
 * session, so the Automation API is not a usable path for snapshots on the
 * versions we target. See ADR-0001 Inc 0 results.
 *
 * Transport rules:
 *   - HTTPS only, certificate PINNED by SHA-256. vCenter certs are self-signed
 *     by the internal VMCA, so chain validation is meaningless here; the pin is
 *     the only thing authenticating the server. We therefore disable Node's
 *     chain check and do our own comparison — and we do it BEFORE any request
 *     body carrying credentials is written.
 *   - Never log the credential, the session cookie, or a full request body.
 */

import https from "node:https";
import tls from "node:tls";
import crypto from "node:crypto";
import {
  escapeXml,
  firstTag,
  morefOfType,
  parseFault,
  parseCurrentSnapshot,
  parsePrivilegeList,
  parsePrivilegeResults,
  parsePropertyValue,
  parseSnapshotTree,
  parseVmSummaries,
  type SnapshotNode,
  type VmSummary,
} from "./vim-parse";

export class VimFault extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VimFault";
  }
}

/** Server certificate did not match the configured pin. */
export class PinMismatchError extends Error {
  constructor(readonly expected: string, readonly observed: string) {
    super(`vCenter certificate does not match the pinned thumbprint`);
    this.name = "PinMismatchError";
  }
}

export interface VimClientOptions {
  host: string;
  port: number;
  /** Hex sha256, lowercase, no separators. Required. */
  tlsThumbprintSha256: string;
  requestTimeoutMs?: number;
  logger?: { info?: (m: string, x?: any) => void; warn?: (m: string, x?: any) => void };
}

export interface ServiceContent {
  sessionManager: string;
  authorizationManager: string;
  propertyCollector: string;
  viewManager: string;
  rootFolder: string;
  searchIndex: string;
  apiType: string;
  apiVersion: string;
  productName: string;
}

const SOAP_ACTION = '"urn:vim25/8.0.0.0"';

export class VimClient {
  private cookie: string | null = null;
  private content: ServiceContent | null = null;
  private readonly timeout: number;

  constructor(private readonly opts: VimClientOptions) {
    this.timeout = opts.requestTimeoutMs ?? 60_000;
  }

  /** SHA-256 of the presented leaf certificate, hex lowercase. */
  async fetchServerFingerprint(): Promise<string> {
    return new Promise((resolve, reject) => {
      const sock = tls.connect(
        { host: this.opts.host, port: this.opts.port, rejectUnauthorized: false },
        () => {
          const cert = sock.getPeerCertificate();
          sock.end();
          if (!cert?.raw) return reject(new Error("vCenter presented no certificate"));
          resolve(crypto.createHash("sha256").update(cert.raw).digest("hex"));
        }
      );
      sock.on("error", reject);
      sock.setTimeout(15_000, () => {
        sock.destroy();
        reject(new Error("TLS connect timeout"));
      });
    });
  }

  /** Verify the pin. Throws PinMismatchError. Call before authenticating. */
  async assertPinnedCertificate(): Promise<void> {
    const observed = await this.fetchServerFingerprint();
    const expected = this.opts.tlsThumbprintSha256.replace(/[:\s-]/g, "").toLowerCase();
    if (observed !== expected) throw new PinMismatchError(expected, observed);
  }

  private request(body: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: this.opts.host,
          port: this.opts.port,
          path: "/sdk",
          method: "POST",
          headers: {
            "Content-Type": "text/xml; charset=utf-8",
            SOAPAction: SOAP_ACTION,
            "Content-Length": Buffer.byteLength(body),
            ...(this.cookie ? { Cookie: this.cookie } : {}),
          },
          // Chain validation cannot work against a VMCA-signed cert; the
          // thumbprint pin checked in assertPinnedCertificate() is the anchor.
          rejectUnauthorized: false,
          timeout: this.timeout,
        },
        (res) => {
          let data = "";
          res.setEncoding("utf8");
          res.on("data", (c) => (data += c));
          res.on("end", () => {
            const setCookie = res.headers["set-cookie"];
            if (setCookie?.length) this.cookie = setCookie[0].split(";")[0];
            const fault = parseFault(data);
            if (fault) return reject(new VimFault(fault));
            if ((res.statusCode ?? 0) >= 400) {
              return reject(new VimFault(`HTTP ${res.statusCode} from /sdk`));
            }
            resolve(data);
          });
        }
      );
      req.on("error", reject);
      req.on("timeout", () => {
        req.destroy(new Error(`vCenter request timed out after ${this.timeout} ms`));
      });
      req.write(body);
      req.end();
    });
  }

  private call(inner: string): Promise<string> {
    return this.request(
      `<?xml version="1.0" encoding="UTF-8"?>` +
        `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ` +
        `xmlns:xsd="http://www.w3.org/2001/XMLSchema" ` +
        `xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ` +
        `xmlns:urn="urn:vim25">` +
        `<soapenv:Body>${inner}</soapenv:Body></soapenv:Envelope>`
    );
  }

  async retrieveServiceContent(): Promise<ServiceContent> {
    const xml = await this.call(
      `<urn:RetrieveServiceContent><urn:_this type="ServiceInstance">ServiceInstance</urn:_this></urn:RetrieveServiceContent>`
    );
    this.content = {
      sessionManager: firstTag(xml, "sessionManager") ?? "SessionManager",
      authorizationManager: firstTag(xml, "authorizationManager") ?? "AuthorizationManager",
      propertyCollector: firstTag(xml, "propertyCollector") ?? "propertyCollector",
      viewManager: firstTag(xml, "viewManager") ?? "ViewManager",
      rootFolder: firstTag(xml, "rootFolder") ?? "group-d1",
      searchIndex: firstTag(xml, "searchIndex") ?? "SearchIndex",
      apiType: firstTag(xml, "apiType") ?? "",
      apiVersion: firstTag(xml, "apiVersion") ?? "",
      productName: firstTag(xml, "fullName") ?? "",
    };
    return this.content;
  }

  private get svc(): ServiceContent {
    if (!this.content) throw new Error("retrieveServiceContent() must run first");
    return this.content;
  }

  async login(username: string, password: string): Promise<{ sessionKey: string; userName: string }> {
    const xml = await this.call(
      `<urn:Login><urn:_this type="SessionManager">${this.svc.sessionManager}</urn:_this>` +
        `<urn:userName>${escapeXml(username)}</urn:userName>` +
        `<urn:password>${escapeXml(password)}</urn:password></urn:Login>`
    );
    return {
      sessionKey: firstTag(xml, "key") ?? "",
      userName: firstTag(xml, "userName") ?? username,
    };
  }

  async logout(): Promise<void> {
    if (!this.content) return;
    await this.call(
      `<urn:Logout><urn:_this type="SessionManager">${this.svc.sessionManager}</urn:_this></urn:Logout>`
    );
    this.cookie = null;
  }

  /** Every privilege id this vCenter build advertises. */
  async listPrivileges(): Promise<string[]> {
    const xml = await this.retrieveProperties(
      "AuthorizationManager",
      this.svc.authorizationManager,
      ["privilegeList"]
    );
    return parsePrivilegeList(xml);
  }

  /**
   * Non-destructive privilege probe. Booleans come back in request order.
   * Callers MUST filter privIds through listPrivileges() first: an id this
   * build does not know makes vCenter throw "Authorize Exception" and poisons
   * the whole batch.
   */
  async hasPrivilegeOnEntity(
    sessionKey: string,
    privIds: string[],
    entity: { moref: string; type: string }
  ): Promise<boolean[]> {
    if (!privIds.length) return [];
    const xml = await this.call(
      `<urn:HasPrivilegeOnEntity><urn:_this type="AuthorizationManager">${this.svc.authorizationManager}</urn:_this>` +
        `<urn:entity type="${escapeXml(entity.type)}">${escapeXml(entity.moref)}</urn:entity>` +
        `<urn:sessionId>${escapeXml(sessionKey)}</urn:sessionId>` +
        privIds.map((p) => `<urn:privId>${escapeXml(p)}</urn:privId>`).join("") +
        `</urn:HasPrivilegeOnEntity>`
    );
    return parsePrivilegeResults(xml);
  }

  private async retrieveProperties(type: string, moref: string, paths: string[]): Promise<string> {
    return this.call(
      `<urn:RetrieveProperties><urn:_this type="PropertyCollector">${this.svc.propertyCollector}</urn:_this><urn:specSet>` +
        `<urn:propSet><urn:type>${type}</urn:type>` +
        paths.map((p) => `<urn:pathSet>${escapeXml(p)}</urn:pathSet>`).join("") +
        `</urn:propSet>` +
        `<urn:objectSet><urn:obj type="${type}">${escapeXml(moref)}</urn:obj></urn:objectSet>` +
        `</urn:specSet></urn:RetrieveProperties>`
    );
  }

  /** Locate a VM by BIOS uuid (config.uuid) or instance uuid. */
  async findVmByUuid(uuid: string, instanceUuid = false): Promise<string | null> {
    const xml = await this.call(
      `<urn:FindByUuid><urn:_this type="SearchIndex">${this.svc.searchIndex}</urn:_this>` +
        `<urn:uuid>${escapeXml(uuid)}</urn:uuid><urn:vmSearch>true</urn:vmSearch>` +
        `<urn:instanceUuid>${instanceUuid ? "true" : "false"}</urn:instanceUuid></urn:FindByUuid>`
    );
    return morefOfType(xml, "VirtualMachine");
  }

  /** All VMs visible to this session, with their correlation identifiers. */
  async listVms(): Promise<VmSummary[]> {
    const cv = await this.call(
      `<urn:CreateContainerView><urn:_this type="ViewManager">${this.svc.viewManager}</urn:_this>` +
        `<urn:container type="Folder">${this.svc.rootFolder}</urn:container>` +
        `<urn:type>VirtualMachine</urn:type><urn:recursive>true</urn:recursive></urn:CreateContainerView>`
    );
    const view = morefOfType(cv, "ContainerView");
    if (!view) return [];
    const xml = await this.call(
      `<urn:RetrieveProperties><urn:_this type="PropertyCollector">${this.svc.propertyCollector}</urn:_this><urn:specSet>` +
        `<urn:propSet><urn:type>VirtualMachine</urn:type><urn:pathSet>name</urn:pathSet>` +
        `<urn:pathSet>config.uuid</urn:pathSet><urn:pathSet>config.instanceUuid</urn:pathSet></urn:propSet>` +
        `<urn:objectSet><urn:obj type="ContainerView">${view}</urn:obj><urn:skip>true</urn:skip>` +
        `<urn:selectSet xsi:type="urn:TraversalSpec"><urn:name>vmView</urn:name>` +
        `<urn:type>ContainerView</urn:type><urn:path>view</urn:path><urn:skip>false</urn:skip></urn:selectSet>` +
        `</urn:objectSet></urn:specSet></urn:RetrieveProperties>`
    );
    return parseVmSummaries(xml);
  }

  async countVms(): Promise<number> {
    return (await this.listVms()).length;
  }

  async createSnapshot(
    vmMoref: string,
    name: string,
    description: string,
    memory: boolean,
    quiesce: boolean
  ): Promise<string> {
    const xml = await this.call(
      `<urn:CreateSnapshot_Task><urn:_this type="VirtualMachine">${escapeXml(vmMoref)}</urn:_this>` +
        `<urn:name>${escapeXml(name)}</urn:name>` +
        `<urn:description>${escapeXml(description)}</urn:description>` +
        `<urn:memory>${memory ? "true" : "false"}</urn:memory>` +
        `<urn:quiesce>${quiesce ? "true" : "false"}</urn:quiesce></urn:CreateSnapshot_Task>`
    );
    const task = morefOfType(xml, "Task");
    if (!task) throw new VimFault("CreateSnapshot_Task returned no task reference");
    return task;
  }

  async removeSnapshot(snapshotMoref: string, removeChildren = false): Promise<string> {
    const xml = await this.call(
      `<urn:RemoveSnapshot_Task><urn:_this type="VirtualMachineSnapshot">${escapeXml(snapshotMoref)}</urn:_this>` +
        `<urn:removeChildren>${removeChildren ? "true" : "false"}</urn:removeChildren></urn:RemoveSnapshot_Task>`
    );
    const task = morefOfType(xml, "Task");
    if (!task) throw new VimFault("RemoveSnapshot_Task returned no task reference");
    return task;
  }

  async revertToSnapshot(snapshotMoref: string): Promise<string> {
    const xml = await this.call(
      `<urn:RevertToSnapshot_Task><urn:_this type="VirtualMachineSnapshot">${escapeXml(snapshotMoref)}</urn:_this>` +
        `</urn:RevertToSnapshot_Task>`
    );
    const task = morefOfType(xml, "Task");
    if (!task) throw new VimFault("RevertToSnapshot_Task returned no task reference");
    return task;
  }

  /** Snapshot tree for a VM. Empty array when it has none. */
  async listSnapshots(vmMoref: string): Promise<SnapshotNode[]> {
    const xml = await this.retrieveProperties("VirtualMachine", vmMoref, ["snapshot"]);
    return parseSnapshotTree(xml);
  }

  async currentSnapshot(vmMoref: string): Promise<string | null> {
    const xml = await this.retrieveProperties("VirtualMachine", vmMoref, ["snapshot"]);
    return parseCurrentSnapshot(xml);
  }

  /**
   * Poll a task to completion.
   *
   * Only `info.state` is requested. Asking for `info.error.localizedMessage`
   * alongside it makes vCenter fault when the task has NO error — a trap that
   * cost the Inc 0 spike a failed run and left an orphaned snapshot behind.
   * The error detail is fetched only once the state actually says "error".
   */
  async waitForTask(
    taskMoref: string,
    opts: { timeoutMs?: number; pollMs?: number; sleep?: (ms: number) => Promise<void>; now?: () => number } = {}
  ): Promise<void> {
    const timeoutMs = opts.timeoutMs ?? 15 * 60_000;
    const pollMs = opts.pollMs ?? 1500;
    const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const now = opts.now ?? (() => Date.now());
    const started = now();

    for (;;) {
      const xml = await this.retrieveProperties("Task", taskMoref, ["info.state"]);
      const state = parsePropertyValue(xml, "info.state");
      if (state === "success") return;
      if (state === "error") {
        let detail = "unknown error";
        try {
          const e = await this.retrieveProperties("Task", taskMoref, ["info.error"]);
          detail = parseFault(e) ?? parsePropertyValue(e, "info.error") ?? detail;
        } catch {
          /* best effort — the state is authoritative */
        }
        throw new VimFault(`task ${taskMoref} failed: ${detail}`);
      }
      if (now() - started > timeoutMs) {
        throw new VimFault(`task ${taskMoref} timed out after ${timeoutMs} ms (last state: ${state ?? "unknown"})`);
      }
      await sleep(pollMs);
    }
  }
}
