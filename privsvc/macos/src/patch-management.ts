import { execFile } from "child_process";
import { promisify } from "util";
import type { PrivSvcRequest, PrivSvcResponse } from "./protocol";
import { fail, success } from "./protocol";
import { logger } from "./logger";

const execFileAsync = promisify(execFile);

type CommandResult = {
  stdout: string;
  stderr: string;
  output: string;
  ok: boolean;
  code?: number;
  signal?: string;
};

export type MacPatchItem = {
  label: string;
  title?: string;
  version?: string;
  size?: string;
  recommended?: boolean;
  action?: string;
  requiresRestart?: boolean;
};

async function run(command: string, args: string[], timeout = 30000): Promise<CommandResult> {
  logger.info("patch.command.start", { command, args, timeout });
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout,
      maxBuffer: 8 * 1024 * 1024
    });
    const result = {
      stdout: stdout || "",
      stderr: stderr || "",
      // Joined on a newline, not concatenated: softwareupdate splits its
      // reporting across both streams, and gluing the last stdout line to
      // the first stderr line would fuse an update title onto an error and
      // hide both from a line-oriented reader.
      output: [stdout || "", stderr || ""].filter((s) => s.trim()).join("\n").trim(),
      ok: true,
      code: 0
    };
    logger.info("patch.command.finish", {
      command,
      args,
      ok: true,
      code: 0,
      stdoutPreview: preview(result.stdout),
      stderrPreview: preview(result.stderr)
    });
    return result;
  } catch (err: any) {
    const result = {
      stdout: String(err?.stdout || ""),
      stderr: String(err?.stderr || ""),
      output: String(err?.stdout || err?.stderr || err?.message || err || "").trim(),
      ok: false,
      code: Number.isFinite(Number(err?.code)) ? Number(err.code) : undefined,
      signal: err?.signal ? String(err.signal) : undefined
    };
    logger.warn("patch.command.finish", {
      command,
      args,
      ok: false,
      code: result.code,
      signal: result.signal,
      stdoutPreview: preview(result.stdout),
      stderrPreview: preview(result.stderr),
      outputPreview: preview(result.output)
    });
    return result;
  }
}

function preview(value: string | undefined, max = 1200) {
  const text = String(value || "").trim();
  if (!text) return undefined;
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function parseAction(raw: string | undefined) {
  const value = String(raw || "").trim().toLowerCase();
  if (!value) return undefined;
  if (value.includes("restart")) return "restart";
  if (value.includes("shut")) return "shutdown";
  return value;
}

// Which pending updates count as SECURITY updates — this number feeds
// the macos.updates.no_pending_security_updates compliance check, so a
// miss here is a false PASS.
//
// Field finding 2026-08-23: every Mac in the fleet had exactly one
// pending item, "macOS Tahoe 26.6.2", and all four reported
// securityUpdateCount=0 → the check passed with an OS update pending.
// On modern macOS the OS point release IS the security update: Apple
// stopped shipping standalone "Security Update" packages for the
// current OS (Ventura+) and Rapid Security Responses were all but
// retired, so CVE fixes ride exclusively on "macOS <name> x.y.z". Any
// pending OS update is therefore security-relevant. Command Line
// Tools, Xcode, fonts etc. stay non-security.
export function isSecurityLike(item: MacPatchItem): boolean {
  const value = `${item.label} ${item.title || ""}`.toLowerCase();
  if (/security|rapid security response|xprotect|gatekeeper|mrt/.test(value)) return true;
  // "macOS Tahoe 26.6.2" / label "macOS Tahoe 26.6.2-26G5049" /
  // older "macOS Ventura 13.6.7". Anchored on the word so "Command Line
  // Tools for Xcode" and third-party titles containing "macOS" as a
  // platform tag don't match.
  return /^macos\s+[a-z]+\s+\d+(\.\d+)*/.test(value) || /^macos\s+\d+(\.\d+)*/.test(value);
}

function parseYesNo(value: string | undefined): boolean | undefined {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "yes") return true;
  if (normalized === "no") return false;
  return undefined;
}

function extractField(block: string, field: string) {
  const match = block.match(new RegExp(`${field}:\\s*([^\\n,]+?)(?=,\\s*[A-Za-z][A-Za-z ]*:|\\n\\s*[A-Za-z][A-Za-z ]*:|$)`, "i"));
  return match?.[1]?.trim();
}

function finalizeItem(current: (MacPatchItem & { rawLines?: string[] }) | null, items: MacPatchItem[]) {
  if (!current?.label) {
    return;
  }

  const block = (current.rawLines || []).join("\n");
  const title = extractField(block, "Title");
  const version = extractField(block, "Version");
  const size = extractField(block, "Size");
  const recommended = parseYesNo(extractField(block, "Recommended"));
  const action = parseAction(extractField(block, "Action"));

  items.push({
    label: current.label,
    title: title || current.title,
    version: version || current.version,
    size: size || current.size,
    recommended: recommended ?? current.recommended,
    action: action || current.action,
    requiresRestart: action === "restart" || action === "shutdown" || current.requiresRestart === true
  });
}

function parseSoftwareUpdateList(output: string): MacPatchItem[] {
  const lines = output.split(/\r?\n/);
  const items: MacPatchItem[] = [];
  let current: (MacPatchItem & { rawLines?: string[] }) | null = null;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;

    const labelMatch = trimmed.match(/^\*?\s*Label:\s*(.+)$/i);
    if (labelMatch) {
      finalizeItem(current, items);
      current = { label: labelMatch[1].trim(), rawLines: [] };
      continue;
    }

    if (current) {
      current.rawLines = current.rawLines || [];
      current.rawLines.push(trimmed);
    }
  }

  finalizeItem(current, items);
  return items;
}

/**
 * Works out what softwareupdate actually did to each selected update.
 *
 * The previous implementation matched `verb.*title` against the whole output
 * blob. In JavaScript `.` does not cross a newline, so it only ever saw the
 * one shape where the verb and the title share a line — and softwareupdate
 * mostly does the opposite: it names the update, then reports progress or the
 * error on the lines below it. Every macOS install in production therefore
 * scored every update "skipped" and returned `installed=0; failed=0`, a
 * result that looks harmless and says nothing.
 *
 * So this reads line by line and keeps track of which update the tool is
 * currently talking about, the way a person reading the log would.
 */
export function parseInstallOutput(items: MacPatchItem[], output: string) {
  type Outcome = "installed" | "downloaded" | "failed" | "skipped";

  // Ranked: a failure anywhere about an update outranks a download line that
  // came before it. Never let a later, weaker signal overwrite a stronger one.
  const RANK: Record<Outcome, number> = { skipped: 0, downloaded: 1, installed: 2, failed: 3 };

  const FAILED = /\b(error|errors|failed|failure|unable to|cannot|could not|not authorized)\b/i;
  const INSTALLED = /\b(installed|installing|done with|done\.)\b/i;
  const DOWNLOADED = /\b(downloaded|downloading)\b/i;

  const outcomes: Outcome[] = items.map(() => "skipped");
  const messages: (string | undefined)[] = items.map(() => undefined);

  const needles = items.map((item) =>
    [item.title, item.label].filter((v): v is string => Boolean(v && v.trim())).map((v) => v.toLowerCase())
  );

  const record = (idx: number, outcome: Outcome, line: string) => {
    if (RANK[outcome] < RANK[outcomes[idx]]) return;
    outcomes[idx] = outcome;
    // Keep the operator's evidence verbatim; a paraphrase of an error is
    // worth less than the error.
    if (outcome === "failed") messages[idx] = line.trim();
  };

  // Which update the tool is currently reporting on. softwareupdate prints a
  // heading and then indented progress underneath it.
  let current = -1;

  for (const rawLine of output.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const lower = line.toLowerCase();

    const named = needles.findIndex((forms) => forms.some((form) => lower.includes(form)));
    if (named !== -1) current = named;

    const target = named !== -1 ? named : current;
    if (target === -1) continue;

    if (FAILED.test(line)) record(target, "failed", line);
    else if (INSTALLED.test(line)) record(target, "installed", line);
    else if (DOWNLOADED.test(line)) record(target, "downloaded", line);
  }

  // An update we were asked to install must land in a bucket someone can act
  // on. "We tried and can tell you nothing" is the outcome that hid every
  // macOS failure so far, so it is reported as a failure carrying the raw
  // tail rather than as a silent skip.
  const tail = output.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(-4).join(" | ");
  outcomes.forEach((outcome, idx) => {
    if (outcome !== "skipped") return;
    outcomes[idx] = "failed";
    messages[idx] =
      "could not confirm any outcome for this update in softwareupdate output" +
      (tail ? `; output tail: ${tail}` : "; softwareupdate produced no output");
  });

  const results = items.map((item, idx) => ({
    updateId: item.label,
    kb: item.label,
    title: item.title || item.label,
    result: outcomes[idx],
    message: messages[idx]
  }));

  const installedCount = results.filter((r) => r.result === "installed" || r.result === "downloaded").length;
  const failedCount = results.filter((r) => r.result === "failed").length;
  const rebootRequired = items.some((item) => item.requiresRestart) || /restart/i.test(output.toLowerCase());

  let status: "success" | "partial" | "failed" | "no_updates" = "success";
  if (items.length === 0) {
    status = "no_updates";
  } else if (installedCount === 0) {
    status = "failed";
  } else if (failedCount > 0 || installedCount < items.length) {
    status = "partial";
  }

  return {
    status,
    installedCount,
    failedCount,
    rebootRequired,
    results
  };
}

async function listAvailableUpdates() {
  const result = await run("/usr/sbin/softwareupdate", ["--list"], 120000);
  const output = result.output;

  if (!output) {
    logger.info("patch.scan.empty_output", {});
    return {
      status: "healthy",
      scannedAtUtc: new Date().toISOString(),
      updateCount: 0,
      securityUpdateCount: 0,
      items: [] as MacPatchItem[]
    };
  }

  if (!result.ok && !/No new software available/i.test(output)) {
    throw new Error(output || "softwareupdate --list failed");
  }

  const items = parseSoftwareUpdateList(output);
  logger.info("patch.scan.parsed", {
    status: items.length > 0 ? "updates_available" : "healthy",
    itemCount: items.length,
    labels: items.map((item) => item.label).slice(0, 20),
    rawOutputPreview: preview(output)
  });
  return {
    status: items.length > 0 ? "updates_available" : "healthy",
    scannedAtUtc: new Date().toISOString(),
    updateCount: items.length,
    securityUpdateCount: items.filter(isSecurityLike).length,
    items
  };
}

export async function handlePatchScan(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    logger.info("patch.scan.request", {
      id: req.id,
      tenantId: req.meta?.tenantId,
      deviceId: req.meta?.deviceId
    });
    const scan = await listAvailableUpdates();
    return success(req.id, scan);
  } catch (err: any) {
    logger.error("patch.scan.failed", {
      id: req.id,
      error: err?.message || String(err)
    });
    return fail(req.id, "patch_scan_failed", err?.message || String(err));
  }
}

export async function handlePatchInstall(req: PrivSvcRequest): Promise<PrivSvcResponse> {
  try {
    const mode = String(req.params?.mode || "install").trim().toLowerCase();
    if (mode !== "install" && mode !== "download") {
      return fail(req.id, "bad_request", "patch.install mode must be install or download");
    }

    const kbArticleIds = Array.isArray(req.params?.kbArticleIds)
      ? req.params!.kbArticleIds.map((item: unknown) => String(item || "").trim()).filter(Boolean)
      : [];

    logger.info("patch.install.request", {
      id: req.id,
      tenantId: req.meta?.tenantId,
      deviceId: req.meta?.deviceId,
      mode,
      requestedLabels: kbArticleIds
    });

    const available = await listAvailableUpdates();
    const selectedItems = kbArticleIds.length > 0
      ? available.items.filter((item) => kbArticleIds.includes(item.label))
      : available.items;

    logger.info("patch.install.selection", {
      id: req.id,
      availableCount: available.items.length,
      selectedCount: selectedItems.length,
      selectedLabels: selectedItems.map((item) => item.label).slice(0, 20)
    });

    if (selectedItems.length === 0) {
      return success(req.id, {
        status: "no_updates",
        mode,
        selectedCount: 0,
        installedCount: 0,
        failedCount: 0,
        rebootRequired: false,
        results: []
      });
    }

    const args = mode === "download" ? ["--download"] : ["--install"];
    if (kbArticleIds.length > 0) {
      args.push(...selectedItems.map((item) => item.label));
    } else {
      args.push("--all");
    }

    const install = await run("/usr/sbin/softwareupdate", args, 60 * 60 * 1000);
    if (!install.ok && !install.output) {
      return fail(req.id, "patch_install_failed", "softwareupdate returned no output");
    }

    const parsed = parseInstallOutput(selectedItems, install.output);
    logger.info("patch.install.parsed", {
      id: req.id,
      mode,
      status: parsed.status,
      installedCount: parsed.installedCount,
      failedCount: parsed.failedCount,
      rebootRequired: parsed.rebootRequired,
      rawOutputPreview: preview(install.output)
    });
    return success(req.id, {
      status: parsed.status,
      mode,
      selectedCount: selectedItems.length,
      installedCount: parsed.installedCount,
      failedCount: parsed.failedCount,
      rebootRequired: parsed.rebootRequired,
      results: parsed.results
    });
  } catch (err: any) {
    logger.error("patch.install.failed", {
      id: req.id,
      error: err?.message || String(err)
    });
    return fail(req.id, "patch_install_failed", err?.message || String(err));
  }
}
