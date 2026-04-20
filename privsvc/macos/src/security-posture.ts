import { execFile } from "child_process";
import { promisify } from "util";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { success } from "./protocol";

const execFileAsync = promisify(execFile);

type CommandResult = {
  output: string;
  ok: boolean;
};

async function run(command: string, args: string[], timeout = 5000): Promise<CommandResult> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, { timeout, maxBuffer: 8 * 1024 * 1024 });
    return {
      output: `${stdout || ""}${stderr || ""}`.trim(),
      ok: true
    };
  } catch (err: any) {
    return {
      output: String(err?.stdout || err?.stderr || err?.message || err || "").trim(),
      ok: false
    };
  }
}

async function runJson<T>(command: string, args: string[], timeout = 10000): Promise<T | null> {
  const result = await run(command, args, timeout);
  if (!result.output) return null;

  try {
    return JSON.parse(result.output) as T;
  } catch {
    return null;
  }
}

function parseDate(value: unknown): string | undefined {
  if (typeof value !== "string" || !value.trim()) return undefined;
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return undefined;
  return dt.toISOString();
}

async function collectFileVault() {
  const result = await run("/usr/bin/fdesetup", ["status"]);
  const output = result.output;
  const enabled = /FileVault is On/i.test(output);
  const disabled = /FileVault is Off/i.test(output);

  return {
    status: enabled ? "enabled" : disabled ? "disabled" : "unknown",
    raw: output || undefined
  };
}

async function collectFirewall() {
  const result = await run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]);
  const output = result.output;
  const enabled = /enabled/i.test(output);
  const disabled = /disabled/i.test(output);

  return {
    status: enabled ? "enabled" : disabled ? "disabled" : "unknown",
    raw: output || undefined
  };
}

async function collectGatekeeper() {
  const result = await run("/usr/sbin/spctl", ["--status"]);
  const output = result.output;
  const enabled = /assessments enabled/i.test(output);
  const disabled = /assessments disabled/i.test(output);

  return {
    status: enabled ? "enabled" : disabled ? "disabled" : "unknown",
    raw: output || undefined
  };
}

async function collectSip() {
  const result = await run("/usr/bin/csrutil", ["status"]);
  const output = result.output;
  const enabled = /enabled/i.test(output);
  const disabled = /disabled/i.test(output);

  return {
    status: enabled ? "enabled" : disabled ? "disabled" : "unknown",
    raw: output || undefined
  };
}

type InstallHistoryItem = {
  _name?: string;
  install_date?: string;
  version?: string;
  packageIdentifiers?: string[];
};

async function collectPatches() {
  const profiler = await runJson<{ SPInstallHistoryDataType?: InstallHistoryItem[] }>(
    "/usr/sbin/system_profiler",
    ["SPInstallHistoryDataType", "-json"],
    25000
  );

  const items = Array.isArray(profiler?.SPInstallHistoryDataType) ? profiler!.SPInstallHistoryDataType! : [];
  const normalized = items.map((item) => ({
    name: item?._name || "unknown",
    version: item?.version || undefined,
    installedAtUtc: parseDate(item?.install_date),
    packageIdentifiers: Array.isArray(item?.packageIdentifiers) ? item.packageIdentifiers : []
  }));

  const securityItems = normalized.filter((item) =>
    /security|rapid security response|xprotect|gatekeeper|mrt|malware/i.test(String(item.name))
  );

  return {
    status: normalized.length > 0 ? "available" : "unknown",
    count: normalized.length,
    securityCount: securityItems.length,
    lastScanUtc: new Date().toISOString(),
    lastSecurityInstallUtc: (() => {
      const installs = securityItems
        .map((item) => item.installedAtUtc)
        .filter((item): item is string => Boolean(item))
        .sort();
      return installs.length > 0 ? installs[installs.length - 1] : undefined;
    })(),
    items: securityItems,
    rawCount: normalized.length
  };
}

async function readPkgInfo(packageId: string) {
  const result = await run("/usr/sbin/pkgutil", ["--pkg-info", packageId], 8000);
  const output = result.output;
  if (!output) {
    return {
      packageId,
      installed: false
    };
  }

  const version = output.match(/^version:\s*(.+)$/im)?.[1]?.trim();
  const installTime = output.match(/^install-time:\s*(.+)$/im)?.[1]?.trim();

  return {
    packageId,
    installed: result.ok,
    version: version || undefined,
    installTimeEpoch: installTime ? Number(installTime) : undefined,
    installedAtUtc: installTime && Number.isFinite(Number(installTime))
      ? new Date(Number(installTime) * 1000).toISOString()
      : undefined,
    raw: output || undefined
  };
}

async function collectAntivirus() {
  const [xprotectConfig, xprotectPayloads, mrtConfig] = await Promise.all([
    readPkgInfo("com.apple.pkg.XProtectPlistConfigData"),
    readPkgInfo("com.apple.pkg.XProtectPayloads"),
    readPkgInfo("com.apple.pkg.MRTConfigData")
  ]);

  const receipts = [xprotectConfig, xprotectPayloads, mrtConfig];
  const installedCount = receipts.filter((item) => item.installed).length;
  const latestUpdate = receipts
    .map((item) => item.installedAtUtc)
    .filter((item): item is string => Boolean(item))
    .sort();

  return {
    status: installedCount > 0 ? "enabled" : "unknown",
    provider: installedCount > 0 ? "apple_builtin" : "unknown",
    installedCount,
    lastUpdateUtc: latestUpdate.length > 0 ? latestUpdate[latestUpdate.length - 1] : undefined,
    xprotect: {
      config: xprotectConfig,
      payloads: xprotectPayloads
    },
    mrt: mrtConfig,
    receipts
  };
}

function parseSharingBlocks(output: string) {
  const lines = output.split(/\r?\n/);
  const items: Array<Record<string, unknown>> = [];
  let current: Record<string, unknown> | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    const nameMatch = line.match(/^name:\s*(.+)$/i);
    if (nameMatch) {
      if (current) items.push(current);
      current = { name: nameMatch[1].trim() };
      continue;
    }

    const pathMatch = line.match(/^path:\s*(.+)$/i);
    if (pathMatch) {
      current = current || {};
      current.path = pathMatch[1].trim();
      continue;
    }

    const smbMatch = line.match(/^smb:\s*(.+)$/i);
    if (smbMatch) {
      current = current || {};
      current.smb = smbMatch[1].trim();
      continue;
    }

    const afpMatch = line.match(/^afp:\s*(.+)$/i);
    if (afpMatch) {
      current = current || {};
      current.afp = afpMatch[1].trim();
      continue;
    }

    const ftpMatch = line.match(/^ftp:\s*(.+)$/i);
    if (ftpMatch) {
      current = current || {};
      current.ftp = ftpMatch[1].trim();
      continue;
    }

    const permissionMatch = line.match(/^users?:\s*(.+)$/i) || line.match(/^groups?:\s*(.+)$/i);
    if (permissionMatch) {
      current = current || {};
      const permissions = Array.isArray(current.permissions) ? current.permissions as string[] : [];
      permissions.push(permissionMatch[1].trim());
      current.permissions = permissions;
    }
  }

  if (current) items.push(current);
  return items;
}

async function inspectShareRisk(path: string) {
  const result = await run("/bin/ls", ["-lde", path], 8000);
  const output = result.output;
  const hasEveryoneWriteAcl = /everyone allow .*?(write|delete|add_file|add_subdirectory|writeattr|writeextattr|chown)/i.test(output);
  const worldWritable = /^[\-d].{7}w/.test(output);

  return {
    path,
    hasEveryoneWriteAcl,
    worldWritable,
    raw: output || undefined
  };
}

async function collectShares() {
  const result = await run("/usr/sbin/sharing", ["-l"], 12000);
  const items = parseSharingBlocks(result.output);
  const detailed: Array<Record<string, unknown>> = await Promise.all(items.map(async (item) => {
    const path = typeof item.path === "string" ? item.path : undefined;
    const risk = path ? await inspectShareRisk(path) : null;
    const risky = Boolean(risk?.hasEveryoneWriteAcl || risk?.worldWritable);

    return {
      ...item,
      risky,
      risk: risk || undefined
    };
  }));

  const riskyItems = detailed.filter((item) => item.risky);
  const smbEnabled = detailed.some((item) => String((item as any).smb || "").toLowerCase() === "yes");

  return {
    status: detailed.length > 0 ? "available" : "unknown",
    count: detailed.length,
    riskyCount: riskyItems.length,
    items: detailed,
    raw: result.output || undefined,
    smbEnabled
  };
}

async function collectSmb(shares: { smbEnabled?: boolean; raw?: string }) {
  const launchctl = await run("/bin/launchctl", ["print", "system/com.apple.smbd"], 8000);
  const running = /state = running/i.test(launchctl.output) || /active count = [1-9]/i.test(launchctl.output);
  const disabled = /Could not find service|not found/i.test(launchctl.output);

  return {
    status: shares.smbEnabled || running ? "enabled" : disabled ? "disabled" : "unknown",
    running,
    raw: launchctl.output || shares.raw
  };
}

async function collectProfiles() {
  const [enrollmentResult, listResult] = await Promise.all([
    run("/usr/bin/profiles", ["status", "-type", "enrollment"], 12000),
    run("/usr/bin/profiles", ["list", "-all"], 15000)
  ]);

  const enrollmentOutput = enrollmentResult.output;
  const listOutput = listResult.output;
  const enrolled = /mdm enrollment:\s*yes|enrolled via dep:\s*yes|enrollment state:\s*enrolled/i.test(enrollmentOutput);
  const profileLines = listOutput
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^attribute:/i.test(line) || /^profile:/i.test(line) || /^identifier:/i.test(line));

  return {
    status: enrollmentOutput || listOutput ? "available" : "unknown",
    mdmEnrolled: enrolled,
    profileLineCount: profileLines.length,
    enrollmentRaw: enrollmentOutput || undefined,
    listRaw: listOutput || undefined
  };
}

async function collectDirectoryBinding() {
  const result = await run("/usr/sbin/dsconfigad", ["-show"], 10000);
  const output = result.output;
  const bound = result.ok && /Active Directory Domain/i.test(output);
  const domainName = output.match(/Active Directory Domain\s*=\s*(.+)$/im)?.[1]?.trim();
  const computerAccount = output.match(/Computer Account\s*=\s*(.+)$/im)?.[1]?.trim();

  return {
    status: bound ? "bound" : output ? "unbound" : "unknown",
    bound,
    domainName: domainName || undefined,
    computerAccount: computerAccount || undefined,
    raw: output || undefined
  };
}

async function collectDomain() {
  const [profiles, directoryBinding] = await Promise.all([
    collectProfiles(),
    collectDirectoryBinding()
  ]);

  return {
    status: profiles.status === "available" || directoryBinding.status !== "unknown" ? "available" : "unknown",
    profiles,
    directoryBinding
  };
}

export async function handleSecurityPosture(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  const [filevault, firewall, gatekeeper, sip, patches, antivirus, shares, domain] = await Promise.all([
    collectFileVault(),
    collectFirewall(),
    collectGatekeeper(),
    collectSip(),
    collectPatches(),
    collectAntivirus(),
    collectShares(),
    collectDomain()
  ]);

  const smb = await collectSmb(shares);

  return success(req.id, {
    filevault,
    firewall,
    gatekeeper,
    sip,
    patches,
    antivirus,
    shares,
    smb,
    domain,
    crypto: {
      status: "unknown",
      source: "phase_2_pending_model_definition"
    },
    collectedAtUtc: new Date().toISOString()
  });
}
