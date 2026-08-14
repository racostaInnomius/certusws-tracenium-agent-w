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
import { EventEmitter } from "events";

/**
 * A stand-in for the Windows named pipe that reproduces the property that
 * matters: strictly serial service. One request is handled at a time and
 * the next is not even looked at until the previous answer is written.
 */
class SerialPipe extends EventEmitter {
  destroyed = false;
  writable = true;
  /** method -> how long its "handler" takes. */
  handlerMs: Record<string, number> = {};
  /**
   * Optional: privsvc abandons a wedged handler and starts serving again
   * after this long, without ever answering the request it dropped.
   */
  freeLaneAfterMs: number | null = null;
  /** Methods in arrival order — what the server actually got to execute. */
  dispatched: string[] = [];

  private inbox: any[] = [];
  private busy = false;

  connect(_path: string) {
    queueMicrotask(() => this.emit("connect"));
    return this;
  }

  write(payload: string) {
    for (const line of payload.split("\n")) {
      if (line.trim()) this.inbox.push(JSON.parse(line));
    }
    this.serve();
    return true;
  }

  private serve() {
    if (this.busy) return;
    const req = this.inbox.shift();
    if (!req) return;

    this.busy = true;
    this.dispatched.push(req.method);

    const handlerMs = this.handlerMs[req.method] ?? 10;

    if (this.freeLaneAfterMs !== null && this.freeLaneAfterMs < handlerMs) {
      setTimeout(() => {
        this.busy = false;
        this.serve(); // lane freed, answer never sent
      }, this.freeLaneAfterMs);
      return;
    }

    setTimeout(() => {
      this.busy = false;
      if (!this.destroyed) {
        this.emit("data", JSON.stringify({ v: 1, id: req.id, ok: true, result: {} }) + "\n");
      }
      this.serve();
    }, handlerMs);
  }

  destroy() {
    this.destroyed = true;
    this.writable = false;
    this.emit("close");
  }

  once(event: string, cb: any) {
    return super.once(event, cb);
  }
}

let pipe: SerialPipe;

vi.mock("net", () => ({
  default: {
    Socket: class {
      constructor() {
        return pipe as any;
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
    pipe = new SerialPipe();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not spend a request's budget on the handler ahead of it", async () => {
    // The production shape, scaled down: compliance occupies the lane for
    // longer than CDP's entire budget. Before the queue, CDP's timer was
    // already running and it was rejected without ever being executed.
    pipe.handlerMs["security.compliance"] = 30_000;
    pipe.handlerMs["cdp.certs.read"] = 100;

    const client = new PrivSvcClient();
    const compliance = call(client, "security.compliance");
    const cdp = call(client, "cdp.certs.read");

    await vi.advanceTimersByTimeAsync(60_000);

    await expect(compliance).resolves.toMatchObject({ ok: true });
    await expect(cdp).resolves.toMatchObject({ ok: true });
    expect(pipe.dispatched).toEqual(["security.compliance", "cdp.certs.read"]);
  });

  it("serves one request at a time, in order", async () => {
    pipe.handlerMs = { "software.inventory": 5_000, "cdp.certs.read": 5_000, ping: 5_000 };

    const client = new PrivSvcClient();
    const all = Promise.all([
      call(client, "software.inventory"),
      call(client, "cdp.certs.read"),
      call(client, "ping")
    ]);

    // Only the head can be in the lane while the first handler runs.
    await vi.advanceTimersByTimeAsync(1_000);
    expect(pipe.dispatched).toEqual(["software.inventory"]);

    await vi.advanceTimersByTimeAsync(30_000);
    await expect(all).resolves.toHaveLength(3);
    expect(pipe.dispatched).toEqual(["software.inventory", "cdp.certs.read", "ping"]);
  });

  it("still times out on its own slow handler, naming the method and budget", async () => {
    // The queue must not turn a genuinely wedged handler into an
    // indefinite wait — that was the whole value of the old timeout.
    pipe.handlerMs["cdp.certs.read"] = 10 * 60_000;

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
    pipe.handlerMs["security.compliance"] = 60 * 60_000; // wedged
    pipe.handlerMs.ping = 10;
    pipe.freeLaneAfterMs = 270_000; // privsvc gives up around when we do

    const client = new PrivSvcClient();
    const compliance = call(client, "security.compliance");
    compliance.catch(() => {}); // asserted below
    const ping = call(client, "ping");

    await vi.advanceTimersByTimeAsync(200_000);
    expect(pipe.dispatched).toEqual(["security.compliance"]); // still waiting

    await vi.advanceTimersByTimeAsync(120_000);
    await expect(compliance).rejects.toThrow(/security\.compliance did not answer/);
    await expect(ping).resolves.toMatchObject({ ok: true });
  });

  it("reports the lane it waited on, so a busy pipe is not misread as a slow handler", async () => {
    // The diagnostic that was missing. "cdp.certs.read did not answer
    // within 8000ms" was true and useless: it pointed the investigation at
    // the certificate scan, which was never the problem.
    pipe.handlerMs["security.compliance"] = 60 * 60_000; // never answers
    pipe.handlerMs["cdp.certs.read"] = 60 * 60_000; // nor does the pipe after it

    const client = new PrivSvcClient();
    const compliance = call(client, "security.compliance");
    compliance.catch(() => {}); // asserted below; silence the unhandled warning
    const cdp = call(client, "cdp.certs.read");
    cdp.catch(() => {}); // asserted below

    await vi.advanceTimersByTimeAsync(400_000);

    await expect(cdp).rejects.toThrow(/cdp\.certs\.read did not answer within 60000ms/);
    await expect(cdp).rejects.toThrow(/waited \d+ms for the IPC lane behind security\.compliance/);
  });

  it("rejects queued callers when the pipe drops instead of leaving them hanging", async () => {
    pipe.handlerMs["security.compliance"] = 60_000;

    const client = new PrivSvcClient();
    const compliance = call(client, "security.compliance");
    compliance.catch(() => {}); // the drop rejects it too; only cdp is asserted
    const cdp = call(client, "cdp.certs.read");
    cdp.catch(() => {}); // asserted below

    await vi.advanceTimersByTimeAsync(100);
    pipe.destroy();
    await vi.advanceTimersByTimeAsync(100);

    await expect(cdp).rejects.toThrow(/closed/i);
  });
});
