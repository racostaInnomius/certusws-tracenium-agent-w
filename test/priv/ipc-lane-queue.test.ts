// test/priv/ipc-lane-queue.test.ts
//
// The IPC lane: one request at a time, and a budget that starts when the
// request is DISPATCHED rather than when it is written.
//
// PRODUCTION FAILURE THIS REPRODUCES (2026-08-13, tenants 111/1/113):
//   [gRPC][CDP] collector error — keeping last good projection
//     message: 'PrivSvc timeout: cdp.certs.read did not answer within 8000ms'
// 4 of 16 CDP scans on the pilot fleet. Every one landed within ~40s of a
// gRPC reconnect and on an agent whose event sequence was still in the
// double digits; agents at sequence 3600+ never failed. Same hosts, same
// certificate stores — the difference was an empty lane.
//
// The cert store enumeration was never the problem. `startPipelines` fires
// inventory + compliance + cdp + patch with no await between them, and
// `NamedPipeServer.HandleClientAsync` does not even READ the next request
// until the current handler returns. CDP held the smallest budget in the
// agent (the 8s default it had never been given deliberately), so it was
// the one that expired while queued behind `software.inventory`.
//
// The old client made that invisible: it wrote every request immediately
// and started the timer at write. These tests pin the two properties that
// make the documented invariant (job > client > handler) actually hold:
// a request cannot lose its budget to somebody else's handler, and it
// cannot wait for the lane forever either.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SerialPipe } from "./serial-pipe";

let pipes: SerialPipe[];
let handlerMs: Record<string, number>;
let freeLaneAfterMs: number | null;
const pipe = () => {
  expect(pipes).toHaveLength(1);
  return pipes[0];
};

vi.mock("net", () => ({
  default: {
    Socket: class {
      constructor() {
        const p = new SerialPipe();
        p.handlerMs = { ...handlerMs };
        p.freeLaneAfterMs = freeLaneAfterMs;
        pipes.push(p);
        return p as any;
      }
    }
  }
}));

// Imported after the mock is registered.
const { PrivSvcClient } = await import("../../src/priv/privsvc-client-windows");

const call = (client: any, method: string) =>
  client.call({ v: 1, id: `${method}-1`, method, params: {} });

describe("PrivSvc IPC lane (Windows)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    pipes = [];
    handlerMs = {};
    freeLaneAfterMs = null;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not spend a request's budget on the handler ahead of it", async () => {
    // The production shape, scaled down: compliance occupies the lane for
    // longer than the next request's entire budget. Before the queue, that
    // request's timer was already running and it was rejected without ever
    // being executed. (Both ride the slow lane; CDP, the original victim,
    // now rides the control lane and never meets compliance at all.)
    handlerMs["security.compliance"] = 30_000;
    handlerMs["patch.scan"] = 100;

    const client = new PrivSvcClient();
    const compliance = call(client, "security.compliance");
    const scan = call(client, "patch.scan");

    await vi.advanceTimersByTimeAsync(60_000);

    await expect(compliance).resolves.toMatchObject({ ok: true });
    await expect(scan).resolves.toMatchObject({ ok: true });
    expect(pipe().dispatched).toEqual(["security.compliance", "patch.scan"]);
  });

  it("serves one request at a time, in order", async () => {
    handlerMs = { "software.inventory": 5_000, "cdp.certs.read": 5_000, ping: 5_000 };

    const client = new PrivSvcClient();
    const all = Promise.all([
      call(client, "software.inventory"),
      call(client, "cdp.certs.read"),
      call(client, "ping")
    ]);

    // Only the head can be in the lane while the first handler runs.
    await vi.advanceTimersByTimeAsync(1_000);
    expect(pipe().dispatched).toEqual(["software.inventory"]);

    await vi.advanceTimersByTimeAsync(30_000);
    await expect(all).resolves.toHaveLength(3);
    expect(pipe().dispatched).toEqual(["software.inventory", "cdp.certs.read", "ping"]);
  });

  it("still times out on its own slow handler, naming the method and budget", async () => {
    // The queue must not turn a genuinely wedged handler into an
    // indefinite wait — that was the whole value of the old timeout.
    handlerMs["cdp.certs.read"] = 10 * 60_000;

    const client = new PrivSvcClient();
    const cdp = call(client, "cdp.certs.read");
    cdp.catch(() => {}); // asserted below

    await vi.advanceTimersByTimeAsync(120_000);
    await expect(cdp).rejects.toThrow(
      /cdp\.certs\.read did not answer within 60000ms/
    );
  });

  it("bounds the wait without a queue deadline: the head leaves at its own budget", async () => {
    // Why there is no separate queue timer. `security.compliance` never
    // answers, but its 270s budget still frees the lane, so the queued
    // request's wait is bounded by construction. A queue deadline derived
    // from that same 270s could only ever fire after this — it would be a
    // safety net that cannot catch anything.
    handlerMs["security.compliance"] = 60 * 60_000; // wedged
    handlerMs["patch.scan"] = 10;
    freeLaneAfterMs = 270_000; // privsvc gives up around when we do

    const client = new PrivSvcClient();
    const compliance = call(client, "security.compliance");
    compliance.catch(() => {}); // asserted below
    const scan = call(client, "patch.scan");

    await vi.advanceTimersByTimeAsync(200_000);
    expect(pipe().dispatched).toEqual(["security.compliance"]); // still waiting

    await vi.advanceTimersByTimeAsync(120_000);
    await expect(compliance).rejects.toThrow(/security\.compliance did not answer/);
    await expect(scan).resolves.toMatchObject({ ok: true });
  });

  it("reports the lane it waited on, so a busy pipe is not misread as a slow handler", async () => {
    // The diagnostic that was missing. "cdp.certs.read did not answer
    // within 8000ms" was true and useless: it pointed the investigation at
    // the certificate scan, which was never the problem.
    handlerMs["security.compliance"] = 60 * 60_000; // never answers
    handlerMs["patch.scan"] = 60 * 60_000; // nor does the pipe after it

    const client = new PrivSvcClient();
    const compliance = call(client, "security.compliance");
    compliance.catch(() => {}); // asserted below; silence the unhandled warning
    const scan = call(client, "patch.scan");
    scan.catch(() => {}); // asserted below

    // compliance holds the lane for its 270s budget, then patch.scan gets
    // its own 240s: both must have expired for the message to exist.
    await vi.advanceTimersByTimeAsync(600_000);

    await expect(scan).rejects.toThrow(/patch\.scan did not answer within 240000ms/);
    await expect(scan).rejects.toThrow(/waited \d+ms for the IPC slow lane behind security\.compliance/);
  });

  it("rejects queued callers when the pipe drops instead of leaving them hanging", async () => {
    handlerMs["security.compliance"] = 60_000;

    const client = new PrivSvcClient();
    const compliance = call(client, "security.compliance");
    compliance.catch(() => {}); // the drop rejects it too; only scan is asserted
    const scan = call(client, "patch.scan");
    scan.catch(() => {}); // asserted below

    await vi.advanceTimersByTimeAsync(100);
    pipe().destroy();
    await vi.advanceTimersByTimeAsync(100);

    await expect(scan).rejects.toThrow(/closed/i);
  });
});
