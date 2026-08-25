// test/privsvc/macos-patch-install-parse.test.ts
//
// Every macOS patch_install job ever run in production came back with the
// same shape: `patch_install partial; installed=0; failed=0`. Zero installed
// AND zero failed means the parser classified every update as "skipped" —
// it could not tell what softwareupdate had done, so the job reported a
// vague "partial" instead of either a success or the real error.
//
// The item titles are matched against the tool's human output with regexes
// built as `verb.*title`. In JavaScript `.` does NOT cross a newline, so any
// output that puts the verb and the title on separate lines — which is what
// softwareupdate actually does for progress and errors — matches nothing.
//
// Fixture titles come from a real `softwareupdate --list` on macOS 26:
//   * Label: macOS Tahoe 26.6.2-25G83
//     Title: macOS Tahoe 26.6.2, Version: 26.6.2, Action: restart

import { describe, it, expect } from "vitest";
import { parseInstallOutput, type MacPatchItem } from "../../privsvc/macos/src/patch-management";

const ITEM: MacPatchItem = {
  label: "macOS Tahoe 26.6.2-25G83",
  title: "macOS Tahoe 26.6.2",
  version: "26.6.2",
  action: "restart",
  requiresRestart: true,
};

describe("parseInstallOutput", () => {
  it("sees an install when the verb and the title share a line", () => {
    // The one shape the original regexes could handle.
    const out = [
      "Software Update Tool",
      "",
      "Downloading macOS Tahoe 26.6.2",
      "Installed macOS Tahoe 26.6.2",
    ].join("\n");

    const parsed = parseInstallOutput([ITEM], out);
    expect(parsed.installedCount).toBe(1);
    expect(parsed.failedCount).toBe(0);
    expect(parsed.status).toBe("success");
  });

  it("sees an install when the verb and the title are on separate lines", () => {
    // softwareupdate names the update, then reports progress underneath it.
    // This is the common real shape and the original regexes scored it
    // "skipped", which is how production got installed=0 on a run that had
    // actually done work.
    const out = [
      "Software Update Tool",
      "",
      "macOS Tahoe 26.6.2",
      "Downloading: 100%",
      "Installing: 100%",
      "Done.",
    ].join("\n");

    const parsed = parseInstallOutput([ITEM], out);
    expect(parsed.installedCount).toBe(1);
    expect(parsed.results[0].result).not.toBe("skipped");
  });

  it("reports a failure as failed, never as skipped", () => {
    // The production signature. On Apple Silicon an OS update refused for
    // lack of a volume-owner credential prints the reason on its own line,
    // away from the title. Scoring that "skipped" turned a hard, explainable
    // failure into a shrug.
    const out = [
      "Software Update Tool",
      "",
      "macOS Tahoe 26.6.2",
      "Error: Unable to authenticate as a volume owner.",
    ].join("\n");

    const parsed = parseInstallOutput([ITEM], out);
    expect(parsed.failedCount).toBe(1);
    expect(parsed.installedCount).toBe(0);
    expect(parsed.status).toBe("failed");
    expect(parsed.results[0].result).toBe("failed");
  });

  it("never reports installed=0 and failed=0 for a non-empty selection", () => {
    // The invariant the field data violated. Whatever the output says, an
    // update we tried to install must end up in some bucket we can act on —
    // "we asked for one update and can tell you nothing about it" is not an
    // acceptable outcome.
    const outputs = [
      "Software Update Tool\n\nNo updates are available.",
      "Software Update Tool\n\nmacOS Tahoe 26.6.2\nDownloading: 4%\n",
      "some entirely unexpected output",
      "",
    ];

    for (const out of outputs) {
      const parsed = parseInstallOutput([ITEM], out);
      const accounted = parsed.installedCount + parsed.failedCount;
      expect(
        accounted,
        `output ${JSON.stringify(out.slice(0, 40))} left the update unaccounted for`
      ).toBeGreaterThan(0);
    }
  });

  it("keeps the raw reason so an operator can act on it", () => {
    const out = "macOS Tahoe 26.6.2\nError: Unable to authenticate as a volume owner.";
    const parsed = parseInstallOutput([ITEM], out);
    expect(parsed.results[0].message).toMatch(/volume owner/i);
  });

  it("matches on the label when the title is absent", () => {
    const labelOnly: MacPatchItem = { label: "Safari18.6-26.6.2" };
    const out = "Safari18.6-26.6.2\nInstalling: 100%\nDone.";
    const parsed = parseInstallOutput([labelOnly], out);
    expect(parsed.installedCount).toBe(1);
  });

  it("reports no_updates only when nothing was selected", () => {
    expect(parseInstallOutput([], "Software Update Tool").status).toBe("no_updates");
  });
});
