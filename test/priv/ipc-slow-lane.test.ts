// test/priv/ipc-slow-lane.test.ts
//
// Two connections to the privsvc pipe: control traffic must never wait
// behind a long privileged operation.
//
// PRODUCTION FAILURE THIS REPRODUCES (Msig13, tenant 111, 2026-09-04 — the
// first real Windows patch_install, job ac9a56aa, twice):
//
//   15:49:31  runJob patch_install → privsvc starts Windows Update (22 min)
//   ~15:55    "gRPC stream: heartbeat tick saw stale connection, forcing
//             reconnect" — every grpc.heartbeat was queued behind the
//             install on the one serial lane and never dispatched, so after
//             SILENCE_THRESHOLD_MS (270s) the stream looked dead
//   ~15:55    the reconnect's grpc.connect went into the same queue, so
//             reconnectCount froze
//   16:06:19  "gRPC stream: reconnect loop stalled for 600s (no attempt
//             progressed; offline 660s) — exiting so WinSW can recycle the
//             process"
//   16:12:06  privsvc: "<-- patch.install ok (1354575ms)" — written to a
//             pipe whose reader had been dead for six minutes
//
// The backend kept the job in `sent` until its 100-minute timeout and then
// re-dispatched it, i.e. ran the install again. Windows had never completed
// a patch_install in the field; this is why.
//
// The privsvc serves each CONNECTION serially, not the process: the fresh
// AgentCore that WinSW started at 16:06 got its tray.ensure and grpc.connect
// answered in under 400ms while the orphaned install was still running on
// the old connection. So the fix is a second connection for the long
// methods — and nothing on the privsvc side changes, which matters because
// privsvc changes need a new MSI while the agent self-updates.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SerialPipe } from "./serial-pipe";

/** Every `new net.Socket()` is its own connection, in creation order. */
let pipes: SerialPipe[];
let handlerMs: Record<string, number>;

vi.mock("net", () => ({
  default: {
    Socket: class {
      constructor() {
        const p = new SerialPipe();
        p.handlerMs = { ...handlerMs };
        pipes.push(p);
        return p as any;
      }
    }
  }
}));

// Imported after the mock is registered.
const { PrivSvcClient, laneForMethod, SLOW_LANE_THRESHOLD_MS, getTimeoutForMethod } =
  await import("../../src/priv/privsvc-client-windows");

let seq = 0;
const call = (client: any, method: string) =>
  client.call({ v: 1, id: `${method}-${++seq}`, method, params: {} });

/** Issue a call and let the fake clock run long enough for a short handler. */
const settled = async (client: any, method: string) => {
  const p = call(client, method);
  await vi.advanceTimersByTimeAsync(1_000);
  return p;
};

describe("lane membership is derived from the budget", () => {
  // Pinned so that a budget change which silently moves a method between
  // lanes shows up as a failing test, not as a surprise in the field.
  const SLOW = [
    "security.compliance",
    "patch.install",
    "patch.scan",
    "sdp.download",
    "sdp.install",
    "sdp.uninstall",
    "sdp.dp.prefetch",
    "agent.install",
    "rcp.consent.request"
  ];
  const CONTROL = [
    "grpc.connect",
    "grpc.heartbeat",
    "grpc.ack",
    "grpc.facts.send",
    "grpc.facts.chunk",
    "grpc.send.remoteSessionIce",
    "software.inventory",
    "sdp.verifySignature",
    "sdp.detect",
    "cdp.certs.read",
    "cdp.certs.readUser",
    "cdp.anchor.distrust",
    "tray.ensure",
    "crypto.gwkey.ensure",
    "some.future.method.with.the.8s.default"
  ];

  it.each(SLOW)("%s rides the slow lane", (method) => {
    expect(getTimeoutForMethod(method)).toBeGreaterThan(SLOW_LANE_THRESHOLD_MS);
    expect(laneForMethod(method)).toBe("slow");
  });

  it.each(CONTROL)("%s rides the control lane", (method) => {
    expect(getTimeoutForMethod(method)).toBeLessThanOrEqual(SLOW_LANE_THRESHOLD_MS);
    expect(laneForMethod(method)).toBe("control");
  });

  it("the threshold sits well under the stream's silence limit", () => {
    // grpc-stream declares the connection stale after 270s of silence.
    // The longest a control-lane request may hold its lane must leave
    // room for a heartbeat to get through before that.
    expect(SLOW_LANE_THRESHOLD_MS).toBeLessThan(270_000);
    expect(getTimeoutForMethod("grpc.connect")).toBeLessThanOrEqual(SLOW_LANE_THRESHOLD_MS);
  });
});

describe("PrivSvc IPC slow lane (Windows)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    pipes = [];
    handlerMs = {};
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("⭐ heartbeats keep flowing during a 22-minute patch.install (Msig13)", async () => {
    handlerMs["patch.install"] = 22 * 60_000;
    handlerMs["grpc.heartbeat"] = 10;

    const client = new PrivSvcClient();
    const install = call(client, "patch.install");

    // One heartbeat per minute for the whole install, each with its 5s
    // budget. On the single lane every one of these sat behind the
    // install and expired; that silence is what killed the process.
    const heartbeats: Promise<any>[] = [];
    for (let minute = 1; minute <= 21; minute++) {
      await vi.advanceTimersByTimeAsync(60_000);
      heartbeats.push(call(client, "grpc.heartbeat"));
    }
    await vi.advanceTimersByTimeAsync(5_000);

    for (const hb of heartbeats) {
      await expect(hb).resolves.toMatchObject({ ok: true });
    }
    await vi.advanceTimersByTimeAsync(2 * 60_000);
    await expect(install).resolves.toMatchObject({ ok: true });

    // Two connections: the install on one, every heartbeat on the other.
    expect(pipes).toHaveLength(2);
    expect(pipes[0].dispatched).toEqual(["patch.install"]);
    expect(pipes[1].dispatched.every((m) => m === "grpc.heartbeat")).toBe(true);
    expect(pipes[1].dispatched).toHaveLength(21);
  });

  it("a forced reconnect's grpc.connect is served while the install is still running", async () => {
    // The second half of the death: even after the stream gave up, the
    // reconnect could not progress because grpc.connect was queued behind
    // the install too. Now it is answered within its own 60s budget.
    handlerMs["patch.install"] = 22 * 60_000;
    handlerMs["grpc.connect"] = 500;

    const client = new PrivSvcClient();
    const install = call(client, "patch.install");
    install.catch(() => {});

    await vi.advanceTimersByTimeAsync(6 * 60_000);
    const connect = call(client, "grpc.connect");
    await vi.advanceTimersByTimeAsync(1_000);

    await expect(connect).resolves.toMatchObject({ ok: true });
    expect(pipes[0].dispatched).toEqual(["patch.install"]); // still in flight
  });

  it("opens the slow connection lazily — control-only agents keep one pipe", async () => {
    const client = new PrivSvcClient();
    await settled(client, "grpc.connect");
    await settled(client, "grpc.heartbeat");
    await settled(client, "cdp.certs.read");

    expect(pipes).toHaveLength(1);
    expect(client.isSlowLaneOpen()).toBe(false);

    await settled(client, "security.compliance");
    expect(pipes).toHaveLength(2);
    expect(client.isSlowLaneOpen()).toBe(true);
  });

  it("slow calls still serialise among themselves", async () => {
    // A compliance scan issued mid-install waits for the install, exactly
    // as before: that is a scheduling delay, not a liveness problem.
    handlerMs["patch.install"] = 10 * 60_000;
    handlerMs["security.compliance"] = 100;

    const client = new PrivSvcClient();
    const install = call(client, "patch.install");
    const compliance = call(client, "security.compliance");

    await vi.advanceTimersByTimeAsync(60_000);
    expect(pipes[0].dispatched).toEqual(["patch.install"]);

    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await expect(install).resolves.toMatchObject({ ok: true });
    await expect(compliance).resolves.toMatchObject({ ok: true });
    expect(pipes[0].dispatched).toEqual(["patch.install", "security.compliance"]);
  });

  it("losing the slow connection fails its call and nothing else — no grpc.disconnected", async () => {
    // The gRPC bridge is bound to the control connection (grpc.connect
    // registers the push sink for THAT pipe). A slow-lane drop must not
    // be mistaken for the stream going away, or a broken install would
    // trigger a reconnect storm.
    handlerMs["patch.install"] = 10 * 60_000;

    const client = new PrivSvcClient();
    const pushes: string[] = [];
    client.onPush((m: any) => pushes.push(m.method));

    await settled(client, "grpc.connect");
    const install = call(client, "patch.install");
    install.catch(() => {});
    await vi.advanceTimersByTimeAsync(100);

    pipes[1].destroy(); // the slow connection
    await vi.advanceTimersByTimeAsync(100);

    await expect(install).rejects.toThrow(/closed/i);
    expect(pushes).toEqual([]);

    // The control lane is untouched: a heartbeat goes through on the
    // original connection, no reconnect needed.
    await expect(settled(client, "grpc.heartbeat")).resolves.toMatchObject({ ok: true });
    expect(pipes).toHaveLength(2);
  });

  it("losing the control connection still announces grpc.disconnected", async () => {
    const client = new PrivSvcClient();
    const pushes: string[] = [];
    client.onPush((m: any) => pushes.push(m.method));

    await settled(client, "grpc.connect");
    pipes[0].destroy();
    await vi.advanceTimersByTimeAsync(10);

    expect(pushes).toEqual(["grpc.disconnected"]);
  });

  it("a push that arrives on the slow connection is still delivered", async () => {
    // privsvc only binds pushes to the connection that called grpc.connect,
    // so this should not happen — but framing must not depend on it.
    const client = new PrivSvcClient();
    const pushes: string[] = [];
    client.onPush((m: any) => pushes.push(m.method));

    await settled(client, "security.compliance");
    pipes[0].emit("data", JSON.stringify({ v: 1, method: "grpc.ack", params: {} }) + "\n");

    expect(pushes).toEqual(["grpc.ack"]);
  });

  it("pending diagnostics cover both lanes", async () => {
    handlerMs["patch.install"] = 10 * 60_000;
    handlerMs["cdp.certs.read"] = 30_000;

    const client = new PrivSvcClient();
    const install = call(client, "patch.install");
    install.catch(() => {});
    const cdp = call(client, "cdp.certs.read");
    cdp.catch(() => {});
    await vi.advanceTimersByTimeAsync(100);

    expect(client.getPendingCount()).toBe(2);
    expect(client.getPendingMethods().sort()).toEqual(["cdp.certs.read", "patch.install"]);

    client.close();
    await vi.advanceTimersByTimeAsync(10);
    expect(client.getPendingCount()).toBe(0);
  });
});
