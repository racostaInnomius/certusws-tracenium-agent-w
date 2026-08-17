// test/plugins/sdp-download-budget.test.ts
//
// The download budget has to satisfy TWO things at once, and the second one is
// what bit us:
//
//   1. The IPC client must outwait the handler (the invariant already pinned by
//      test/priv/ipc-timeouts.test.ts).
//   2. The handler's budget is for the WHOLE operation, not for each source.
//
// (2) was violated silently. `timeoutSeconds` was handed intact to every
// candidate in the loop, so two sources meant up to 1200s of work behind a
// client that waits 700s. A distribution point that accepted the TCP connection
// but never answered would eat the full 600s on its own, and the fallback to
// origin could not finish before the client hung up — surfacing as a bare
// "PrivSvc timeout" with no hint of which tier was at fault.
//
// These assertions are structural on purpose: the split lives in three privsvc
// implementations (C#, macOS TS, Linux TS) and the only thing that keeps them
// honest is that all three divide the remaining budget rather than reusing the
// total.

import { describe, expect, it } from "vitest";
import fs from "fs";
import path from "path";
import { DOWNLOAD_BUDGET_SECONDS } from "../../src/plugins/sdp";

const repoRoot = path.join(__dirname, "..", "..");
const read = (rel: string) => fs.readFileSync(path.join(repoRoot, rel), "utf8");

/** Client-side ceiling for sdp.download, in ms, as the IPC client declares it. */
function clientCeilingMs(platform: string): number {
  const src = read(`src/priv/privsvc-client-${platform}.ts`);
  const fn = src.slice(
    src.indexOf("function getTimeoutForMethod"),
    src.indexOf("const CONNECT_TIMEOUT_MS")
  );
  const at = fn.indexOf('case "sdp.download":');
  expect(at, `${platform}: no explicit sdp.download budget`).toBeGreaterThan(-1);
  const ret = fn.slice(at).match(/return\s+([0-9*\s]+);/);
  expect(ret, `${platform}: could not read the sdp.download budget`).toBeTruthy();
  // eslint-disable-next-line no-eval
  return eval(ret![1]) as number;
}

describe("sdp.download budget", () => {
  it("the agent asks for a budget the IPC client will actually wait out", () => {
    for (const platform of ["windows", "macos", "linux"]) {
      expect(
        DOWNLOAD_BUDGET_SECONDS * 1000,
        `${platform}: agent asks privsvc for ${DOWNLOAD_BUDGET_SECONDS}s but the ` +
          `client gives up at ${clientCeilingMs(platform) / 1000}s`
      ).toBeLessThan(clientCeilingMs(platform));
    }
  });

  it("the agent sends the budget instead of relying on the privsvc default", () => {
    // Leaving it implicit is how the two numbers drifted apart in the first
    // place: privsvc defaulted to 600s PER SOURCE with nobody asserting it.
    const src = read("src/plugins/sdp/index.ts");
    const call = src.slice(src.indexOf('method: "sdp.download"'));
    expect(call.slice(0, 800)).toMatch(/timeoutSeconds:\s*DOWNLOAD_BUDGET_SECONDS/);
  });
});

describe("every privsvc splits the budget across sources", () => {
  const impls = [
    { name: "windows", file: "privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/Sdp.cs" },
    { name: "macos", file: "privsvc/macos/src/sdp.ts" },
    { name: "linux", file: "privsvc/linux/src/sdp.ts" },
  ];

  it.each(impls)("$name derives a per-source slice from what is left", ({ file }) => {
    const src = read(file);
    // The slice must come from dividing the remainder by the sources still to
    // try — anything else either reuses the total or hardcodes a share.
    expect(src).toMatch(/perSourceTimeout/i);
    expect(src).toMatch(/sourcesLeft/i);
  });

  it.each(impls)("$name gives up when the shared budget runs out", ({ file }) => {
    // Without this the loop keeps starting attempts it cannot finish, and the
    // last one is the one the client kills — losing the real error.
    const src = read(file);
    expect(src).toMatch(/MinPerSourceTimeoutSeconds|MIN_PER_SOURCE_TIMEOUT_S/);
    expect(src.toLowerCase()).toMatch(/budget.*exhausted/);
  });

  it.each(impls)("$name no longer passes the whole budget to one attempt", ({ file, name }) => {
    const src = read(file);
    if (name === "windows") {
      // Scoped to the multi-source loop on purpose. The DP prefetch path
      // (DownloadForDpAsync) fetches exactly one URL, so handing it the full
      // budget is right — it has nothing to share with.
      expect(src).toMatch(
        /DownloadOneAsync\(client,\s*candidateUrl,\s*stagingPath,\s*expectedSha256,\s*perSourceTimeout/
      );
    } else {
      // curl's own transfer cap must be the per-source slice.
      expect(src).not.toMatch(/"--max-time",\s*String\(timeoutSeconds\)/);
      expect(src).toMatch(/"--max-time",\s*String\(perSourceTimeout\)/);
    }
  });
});
