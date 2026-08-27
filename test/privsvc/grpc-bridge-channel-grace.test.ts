// test/privsvc/grpc-bridge-channel-grace.test.ts
//
// Patch N — the bridge must not tear itself down on the first
// TRANSIENT_FAILURE.
//
// WHAT WENT WRONG (measured on JPR-MacBookPro, 2026-08-27). The old
// watchChannelState tore the whole bridge down the moment the channel
// reported TRANSIENT_FAILURE, on the premise that the state means "gRPC
// tried to keep the connection alive and failed". It does not: it is also
// the state of a first connection attempt that failed, and it is transient
// by contract — the channel retries on its own with exponential backoff.
//
// Tearing down destroyed the channel just before gRPC would have recovered
// it, and rebuilt a fresh one whose backoff started from zero. In that
// machine's privsvc log: 540 of 703 teardowns were channel_transient_failure
// with a median session life of 0.0 s, and the worst burst was 162 reconnect
// attempts over 826 s with intervals of 0.5–11 s that never grew. The control
// plane saw ONE event across that whole half hour, because a teardown at t≈0
// never reaches HELLO.
//
// The state machine has more paths than it looks like, which is why this is
// tested rather than reviewed: the first draft of the patch treated CONNECTING
// as recovery. Since gRPC's own retry cycle is
// TRANSIENT_FAILURE → CONNECTING → TRANSIENT_FAILURE, that would have reset
// the grace window on every attempt and produced a bridge that never tore
// down at all — the opposite failure, equally invisible.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const logged: Array<{ level: string; msg: string; details: any }> = [];
vi.mock("../../privsvc/macos/src/logger", () => ({
  logger: {
    info: (msg: string, details?: any) => logged.push({ level: "info", msg, details }),
    warn: (msg: string, details?: any) => logged.push({ level: "warn", msg, details }),
    error: (msg: string, details?: any) => logged.push({ level: "error", msg, details })
  }
}));
vi.mock("../../privsvc/macos/src/crypto-store", () => ({ loadInstalledIdentity: () => null }));
vi.mock("../../privsvc/macos/src/server-pin", () => ({
  makeCheckServerIdentity: () => undefined,
  readServerKeyPins: () => []
}));

import * as grpc from "@grpc/grpc-js";
import { __test__ } from "../../privsvc/macos/src/grpc-bridge";

const { watchChannelState, clearChannelGrace, state, CHANNEL_GRACE_MS } = __test__;
const S = grpc.connectivityState;

/**
 * A channel whose state we drive by hand.
 *
 * watchConnectivityState is the real contract: it fires the callback when the
 * state moves away from the one the caller passed in. Here `advance()` sets
 * the new state and fires whatever watcher is pending, which is what the real
 * runtime does on a transition.
 */
function fakeChannel(initial: grpc.connectivityState) {
  let current = initial;
  let pending: ((err?: Error) => void) | null = null;
  return {
    current: () => current,
    advance(next: grpc.connectivityState) {
      current = next;
      const cb = pending;
      pending = null;
      cb?.();
    },
    /** The 5-minute re-arm deadline elapsing with no state change. */
    deadlineElapses() {
      const cb = pending;
      pending = null;
      cb?.(new Error("deadline"));
    },
    getConnectivityState: () => current,
    watchConnectivityState: (_from: any, _deadline: any, cb: (err?: Error) => void) => {
      pending = cb;
    }
  };
}

function client(ch: any) {
  return { getChannel: () => ch };
}

function messages() {
  return logged.map((l) => l.msg);
}

beforeEach(() => {
  logged.length = 0;
  vi.useFakeTimers();
  clearChannelGrace();
  state.channelWatchGen = 1;
  // Connected, because that is the situation a degraded channel happens in —
  // and because teardownBridge only logs `grpc_bridge_teardown` when it had a
  // connection to tear down. A test running against a disconnected bridge
  // would pass while asserting nothing.
  state.connected = true;
  state.connecting = false;
});

afterEach(() => {
  clearChannelGrace();
  vi.useRealTimers();
});

describe("watchChannelState — TRANSIENT_FAILURE is not a teardown", () => {
  it("does NOT tear down when the channel first reports TRANSIENT_FAILURE", () => {
    const ch = fakeChannel(S.READY);
    watchChannelState(client(ch), 1);
    ch.advance(S.TRANSIENT_FAILURE);

    expect(messages()).toContain("grpc_bridge_channel_degraded");
    expect(messages()).not.toContain("grpc_bridge_teardown");
    expect(state.channelGraceTimer).toBeTruthy();
  });

  it("cancels the teardown when the channel comes back READY inside the window", () => {
    const ch = fakeChannel(S.READY);
    watchChannelState(client(ch), 1);
    ch.advance(S.TRANSIENT_FAILURE);

    vi.advanceTimersByTime(CHANNEL_GRACE_MS - 1000);
    ch.advance(S.READY);

    expect(messages()).toContain("grpc_bridge_channel_recovered");
    expect(state.channelGraceTimer).toBeNull();

    // And the window really is cancelled, not merely reported as such.
    vi.advanceTimersByTime(CHANNEL_GRACE_MS * 2);
    expect(messages()).not.toContain("grpc_bridge_teardown");
  });

  it("does NOT restart the window on CONNECTING — gRPC retries through that state", () => {
    // The bug in the first draft of this patch. gRPC cycles
    // TRANSIENT_FAILURE → CONNECTING → TRANSIENT_FAILURE while retrying, so
    // treating CONNECTING as recovery makes the timer immortal and the bridge
    // never gives up on a channel that is genuinely gone.
    const ch = fakeChannel(S.READY);
    watchChannelState(client(ch), 1);
    ch.advance(S.TRANSIENT_FAILURE);
    const armedAt = state.channelDegradedSinceMs;

    for (let i = 0; i < 5; i += 1) {
      vi.advanceTimersByTime(10_000);
      ch.advance(S.CONNECTING);
      ch.advance(S.TRANSIENT_FAILURE);
    }

    expect(messages()).not.toContain("grpc_bridge_channel_recovered");
    // Same window, never re-armed.
    expect(state.channelDegradedSinceMs).toBe(armedAt);

    vi.advanceTimersByTime(CHANNEL_GRACE_MS);
    expect(messages()).toContain("grpc_bridge_teardown");
  });

  it("tears down once the window closes with the channel still down", () => {
    const ch = fakeChannel(S.READY);
    watchChannelState(client(ch), 1);
    ch.advance(S.TRANSIENT_FAILURE);

    vi.advanceTimersByTime(CHANNEL_GRACE_MS - 1);
    expect(messages()).not.toContain("grpc_bridge_teardown");

    vi.advanceTimersByTime(2);
    const teardown = logged.find((l) => l.msg === "grpc_bridge_teardown");
    expect(teardown?.details?.reason).toBe("channel_transient_failure");
    expect(teardown?.details?.degradedMs).toBeGreaterThanOrEqual(CHANNEL_GRACE_MS);
  });

  it("tears down IMMEDIATELY on SHUTDOWN — that one is terminal, not transient", () => {
    const ch = fakeChannel(S.READY);
    watchChannelState(client(ch), 1);
    ch.advance(S.SHUTDOWN);

    const teardown = logged.find((l) => l.msg === "grpc_bridge_teardown");
    expect(teardown?.details?.reason).toBe("channel_shutdown");
    expect(state.channelGraceTimer).toBeNull();
  });

  it("a pending window never tears down the connection that REPLACED it", () => {
    // A teardown for some other reason bumps channelWatchGen. The timer from
    // the old generation is still on the event loop; if it fired blindly it
    // would kill a healthy successor stream, and the symptom would look
    // exactly like the bug this patch is fixing.
    const ch = fakeChannel(S.READY);
    watchChannelState(client(ch), 1);
    ch.advance(S.TRANSIENT_FAILURE);

    state.channelWatchGen = 2; // something else tore down and reconnected
    logged.length = 0;
    vi.advanceTimersByTime(CHANNEL_GRACE_MS * 2);

    expect(messages()).not.toContain("grpc_bridge_teardown");
  });

  it("keeps watching across the 5-minute re-arm deadline while degraded", () => {
    // watchConnectivityState fires with an error when its deadline elapses
    // without a state change. That path must not lose the pending window.
    const ch = fakeChannel(S.READY);
    watchChannelState(client(ch), 1);
    ch.advance(S.TRANSIENT_FAILURE);

    ch.deadlineElapses();
    expect(state.channelGraceTimer).toBeTruthy();

    vi.advanceTimersByTime(CHANNEL_GRACE_MS + 1);
    expect(messages()).toContain("grpc_bridge_teardown");
  });

  it("arms the window once per outage, not once per state report", () => {
    const ch = fakeChannel(S.READY);
    watchChannelState(client(ch), 1);
    ch.advance(S.TRANSIENT_FAILURE);
    ch.deadlineElapses();
    ch.deadlineElapses();

    expect(messages().filter((m) => m === "grpc_bridge_channel_degraded")).toHaveLength(1);
  });
});
