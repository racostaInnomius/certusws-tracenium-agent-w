import { execFile } from "child_process";
import { promisify } from "util";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { success } from "./protocol";

const execFileAsync = promisify(execFile);

async function run(command: string, args: string[], timeout = 5000): Promise<string> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, { timeout });
    return `${stdout || ""}${stderr || ""}`.trim();
  } catch (err: any) {
    return String(err?.stdout || err?.stderr || err?.message || err || "").trim();
  }
}

async function collectFileVault() {
  const output = await run("/usr/bin/fdesetup", ["status"]);
  const enabled = /FileVault is On/i.test(output);
  const disabled = /FileVault is Off/i.test(output);

  return {
    status: enabled ? "enabled" : disabled ? "disabled" : "unknown",
    raw: output || undefined
  };
}

async function collectFirewall() {
  const output = await run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]);
  const enabled = /enabled/i.test(output);
  const disabled = /disabled/i.test(output);

  return {
    status: enabled ? "enabled" : disabled ? "disabled" : "unknown",
    raw: output || undefined
  };
}

async function collectGatekeeper() {
  const output = await run("/usr/sbin/spctl", ["--status"]);
  const enabled = /assessments enabled/i.test(output);
  const disabled = /assessments disabled/i.test(output);

  return {
    status: enabled ? "enabled" : disabled ? "disabled" : "unknown",
    raw: output || undefined
  };
}

async function collectSip() {
  const output = await run("/usr/bin/csrutil", ["status"]);
  const enabled = /enabled/i.test(output);
  const disabled = /disabled/i.test(output);

  return {
    status: enabled ? "enabled" : disabled ? "disabled" : "unknown",
    raw: output || undefined
  };
}

export async function handleSecurityPosture(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const [filevault, firewall, gatekeeper, sip] = await Promise.all([
    collectFileVault(),
    collectFirewall(),
    collectGatekeeper(),
    collectSip()
  ]);

  return success(req.id, {
    filevault,
    firewall,
    gatekeeper,
    sip,
    collectedAtUtc: new Date().toISOString()
  });
}
